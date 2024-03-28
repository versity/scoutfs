#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "util.h"
#include "lk_rbtree_wrapper.h"

#include "debug.h"
#include "extent.h"

/*
 * In-memory extent management in rbtree nodes.
 */

bool extents_overlap(u64 a_start, u64 a_len, u64 b_start, u64 b_len)
{
	u64 a_end = a_start + a_len;
	u64 b_end = b_start + b_len;

	return !((a_end <= b_start) || (b_end <= a_start));
}

static int ext_contains(struct extent_node *ext, u64 start, u64 len)
{
	return ext->start <= start && ext->start + ext->len >= start + len;
}

/*
 * True if the given extent is bisected by the given range; there's
 * leftover containing extents on both the left and right sides of the
 * range in the extent.
 */
static int ext_bisected(struct extent_node *ext, u64 start, u64 len)
{
	return ext->start < start && ext->start + ext->len > start + len;
}

static struct extent_node *ext_from_rbnode(struct rb_node *rbnode)
{
	return rbnode ? container_of(rbnode, struct extent_node, rbnode) : NULL;
}

static struct extent_node *next_ext(struct extent_node *ext)
{
	return ext ? ext_from_rbnode(rb_next(&ext->rbnode)) : NULL;
}

static struct extent_node *prev_ext(struct extent_node *ext)
{
	return ext ? ext_from_rbnode(rb_prev(&ext->rbnode)) : NULL;
}

struct walk_results {
	unsigned bisect_to_leaf:1;
	struct extent_node *found;
	struct extent_node *next;
	struct rb_node *parent;
	struct rb_node **node;
};

static void walk_extents(struct extent_root *root, u64 start, u64 len, struct walk_results *wlk)
{
	struct rb_node **node = &root->rbroot.rb_node;
	struct extent_node *ext;
	u64 end = start + len;
	int cmp;

	wlk->found = NULL;
	wlk->next = NULL;
	wlk->parent = NULL;

	while (*node) {
		wlk->parent = *node;
		ext = ext_from_rbnode(*node);
		cmp = end <= ext->start ? -1 :
		      start >= ext->start + ext->len ? 1 : 0;

		if (cmp < 0) {
			node = &ext->rbnode.rb_left;
			wlk->next = ext;
		} else if (cmp > 0) {
			node = &ext->rbnode.rb_right;
		} else {
			wlk->found = ext;
			if (!(wlk->bisect_to_leaf && ext_bisected(ext, start, len)))
				break;
			/* walk right so we can insert greater right from bisection */
			node = &ext->rbnode.rb_right;
		}
	}

	wlk->node = node;
}

/*
 * Return an extent that overlaps with the given range.
 */
int extent_lookup(struct extent_root *root, u64 start, u64 len, struct extent_node *found)
{
	struct walk_results wlk = { 0, };
	int ret;

	walk_extents(root, start, len, &wlk);
	if (wlk.found) {
		memset(found, 0, sizeof(struct extent_node));
		found->start = wlk.found->start;
		found->len = wlk.found->len;
		ret = 0;
	} else {
		ret = -ENOENT;
	}

	return ret;
}

/*
 * Callers can iterate through direct node references and are entirely
 * responsible for consistency when doing so.
 */
struct extent_node *extent_first(struct extent_root *root)
{
	struct walk_results wlk = { 0, };

	walk_extents(root, 0, 1, &wlk);

	return wlk.found ?: wlk.next;
}

struct extent_node *extent_next(struct extent_node *ext)
{
	return next_ext(ext);
}

struct extent_node *extent_prev(struct extent_node *ext)
{
	return prev_ext(ext);
}

/*
 * Insert a new extent into the tree.  We can extend existing nodes,
 * merge with neighbours, or remove existing extents entirely if we
 * insert a range that fully spans existing nodes.
 */
static int walk_insert(struct extent_root *root, u64 start, u64 len, int found_err)
{
	struct walk_results wlk = { 0, };
	struct extent_node *ext;
	struct extent_node *nei;
	int ret;

	walk_extents(root, start, len, &wlk);

	ext = wlk.found;
	if (ext && found_err) {
		ret = found_err;
		goto out;
	}

	if (!ext) {
		ext = malloc(sizeof(struct extent_node));
		if (!ext) {
			ret = -ENOMEM;
			goto out;
		}

		ext->start = start;
		ext->len = len;

		rb_link_node(&ext->rbnode, wlk.parent, wlk.node);
		rb_insert_color(&ext->rbnode, &root->rbroot);
	}

	/* start by expanding an existing extent if our range is larger */
	if (start < ext->start) {
		ext->len += ext->start - start;
		ext->start = start;
	}
	if (ext->start + ext->len < start + len)
		ext->len += (start + len) - (ext->start + ext->len);

	/* drop any fully spanned neighbors, possibly merging with a final adjacent one */

	while ((nei = prev_ext(ext))) {
		if (nei->start + nei->len < ext->start)
			break;

		if (nei->start < ext->start) {
			ext->len += ext->start - nei->start;
			ext->start = nei->start;
		}

		rb_erase(&nei->rbnode, &root->rbroot);
		free(nei);
	}

	while ((nei = next_ext(ext))) {
		if (ext->start + ext->len < nei->start)
			break;

		if (ext->start + ext->len < nei->start + nei->len)
			ext->len += (nei->start + nei->len) - (ext->start + ext->len);

		rb_erase(&nei->rbnode, &root->rbroot);
		free(nei);
	}

	ret = 0;
out:
	if (ret < 0)
		debug("start %llu len %llu ret %d", start, len, ret);
	return ret;
}

/*
 * Insert a new extent.  The specified extent must not overlap with any
 * existing extents or -EEXIST is returned.
 */
int extent_insert_new(struct extent_root *root, u64 start, u64 len)
{
	return walk_insert(root, start, len, true);
}

/*
 * Insert an extent, extending any existing extents that may overlap.
 */
int extent_insert_extend(struct extent_root *root, u64 start, u64 len)
{
	return walk_insert(root, start, len, false);
}

/*
 * Remove the specified extent from an existing node.  The given extent must be fully
 * contained in a single node or -ENOENT is returned.
 */
int extent_remove(struct extent_root *root, u64 start, u64 len)
{
	struct extent_node *ext;
	struct extent_node *ins;
	struct walk_results wlk = {
		.bisect_to_leaf = 1,
	};
	int ret;

	walk_extents(root, start, len, &wlk);

	if (!(ext = wlk.found) || !ext_contains(ext, start, len)) {
		ret = -ENOENT;
		goto out;
	}

	if (ext_bisected(ext, start, len)) {
		debug("found bisected start %llu len %llu", ext->start, ext->len);
		ins = malloc(sizeof(struct extent_node));
		if (!ins) {
			ret = -ENOMEM;
			goto out;
		}

		ins->start = start + len;
		ins->len = (ext->start + ext->len) - ins->start;

		rb_link_node(&ins->rbnode, wlk.parent, wlk.node);
		rb_insert_color(&ins->rbnode, &root->rbroot);
	}

	if (start > ext->start) {
		ext->len = start - ext->start;
	} else if (len < ext->len) {
		ext->start += len;
		ext->len -= len;
	} else {
		rb_erase(&ext->rbnode, &root->rbroot);
	}

	ret = 0;
out:
	debug("start %llu len %llu ret %d", start, len, ret);

	return ret;
}

void extent_root_init(struct extent_root *root)
{
	root->rbroot = RB_ROOT;
	root->total = 0;
}

void extent_root_free(struct extent_root *root)
{
	struct extent_node *ext;
	struct rb_node *node;
	struct rb_node *tmp;

	for (node = rb_first(&root->rbroot); node && ((tmp = rb_next(node)), 1); node = tmp) {
		ext = rb_entry(node, struct extent_node, rbnode);
		rb_erase(&ext->rbnode, &root->rbroot);
		free(ext);
	}
}

void extent_root_print(struct extent_root *root)
{
	struct extent_node *ext;
	struct rb_node *node;
	struct rb_node *tmp;

	for (node = rb_first(&root->rbroot); node && ((tmp = rb_next(node)), 1); node = tmp) {
		ext = rb_entry(node, struct extent_node, rbnode);
		debug("  start %llu len %llu", ext->start, ext->len);
	}
}
