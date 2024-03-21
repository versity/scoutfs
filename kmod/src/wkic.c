/*
 * Copyright (C) 2023 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/rbtree.h>
#include <linux/debugfs.h>

#include "super.h"
#include "format.h"
#include "client.h"
#include "block.h"
#include "forest.h"
#include "totl.h"
#include "counters.h"
#include "util.h"
#include "scoutfs_trace.h"
#include "wkic.h"

/*
 * This weaker item cache differs from the core item cache in item.c:
 *
 *  - It is not protected by cluster lock consistency.  Reads do not
 *  flush currently dirty items and will not see them.  Writes don't
 *  invalidate reads which can still be cached and returned after a
 *  write.
 *
 *  - It is not used to write items.  The items read here are not also
 *  written through the same cache.  The only insertions into this cache
 *  come from bulk reads of persistent items.
 *
 *  - Items are only evicted based on the passage of time or from memory
 *  pressure.
 *
 * These differences give us significant degrees of freedom to implement
 * a cache that is simpler and creates less read contention than the
 * core item cache which must provide stronger cache coherency.
 *
 * Items are stored in pages which are indexed by an rbtree.  Once pages
 * are visible to readers by being inserted into the rbtree they will
 * not change.  The key ranges of pages in the trees are not allowed to
 * overlap.  Overlapping insertions are resolved by removing the
 * existing overlap, dropping the insertion, or trimming the insertion
 * depending on the age and overlapping range of the pages.
 *
 * Readers are fully concurrent and create no store contention by only
 * acquiring an RCU read lock.
 *
 * Readers are protected from traversing modifications made to the tree
 * by actually having two trees.  Writers grab an exclusive lock, update
 * an idle tree while readers are busy with the other tree, swap the
 * trees, and then replay the changes so that both trees are kept in
 * sync.  The writer uses RCU grace periods to ensure that readers have
 * finished with each tree before they start modifying it.
 *
 * The passage of time is the only read consistency mechanic so we have
 * to drop old pages regularly to have a chance to read the new version
 * of cached items.  The exclusive writer makes it trivial to keep a
 * list of pages by age for both expiring and for shrinking in response
 * to memory pressure.
 */

/*
 * A cached item can be returned for twice this delay after it is
 * written to persistence.  We can use a root for _LIFETIME after the
 * write, and then we can insert a cached page at the end of that for
 * another _LIFETIME.
 */
#define WKIC_CACHE_LIFETIME_MS	(5 * MSEC_PER_SEC)

struct wkic_info {
	/* concurrent reader fast path */
	struct rb_root wpage_roots[2];
	unsigned long bits;

	/* exclusive writer */
	struct mutex update_mutex ____cacheline_aligned_in_smp;
	struct list_head shrink_list;
	atomic64_t shrink_count;

	/* block reading slow path */
	struct mutex roots_mutex;
	struct scoutfs_net_roots roots;
	u64 roots_read_seq;
	ktime_t roots_expire;

	/* misc glue */
	struct super_block *sb;
	KC_DEFINE_SHRINKER(shrinker);
	struct dentry *drop_dentry;
};

/*
 * Determines which root readers use during their rcu read lock.  Tree
 * updates flip this bit during their work to make sure readers don't
 * see tree modifications while they're reading.
 */
#define WINF_BIT_READING		0

/*
 * Pages are read-only once they're inserted.  They're only removed if
 * they expire or are reclaimed by shrinking.
 *
 * There's some false sharing here as the writer modifies page nodes
 * that are near the nodes that the readers are traversing.
 */
struct wkic_page {
	/* concurrent readers */
	struct rb_node nodes[2];
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct rb_root item_root;
	ktime_t expiration;

	/* serialized writers */
	struct list_head head;
	struct rb_node *ins_parent;
	struct rb_node **ins_node;
	u64 read_seq;
};

#define trace_wpage(sb, event, which, wpage)						\
do {											\
	__typeof__(wpage) _wpage = (wpage);						\
											\
	trace_scoutfs_wkic_wpage_##event(sb, _wpage, which,				\
					 !RB_EMPTY_NODE(&_wpage->nodes[0]),		\
					 !RB_EMPTY_NODE(&_wpage->nodes[1]),		\
					 &_wpage->start, &_wpage->end);			\
} while (0)

static struct wkic_page *wpage_container(struct rb_node *node, unsigned int which)
{
	return container_of(node, struct wkic_page, nodes[which]);
}

static struct wkic_page *next_wpage(struct wkic_page *wpage, unsigned int which)
{
	return wpage_container(!wpage ? NULL : rb_next(&wpage->nodes[which]), which);
}

/*
 * Iterate over pages in the tree starting with a current page, allowing the for
 * body to remove the wpage.
 */
#define for_each_wpage_safe(wpage, tmp, which) \
	for (; wpage && ((tmp = next_wpage(wpage, which)), 1); wpage = tmp)

static bool wpage_expired(struct wkic_page *wpage, ktime_t kt)
{
	return ktime_before(wpage->expiration, kt);
}

struct wkic_item {
	struct rb_node node;
	struct scoutfs_key key;
	u64 seq;
	unsigned int val_len;
	u8 flags;
	u8 val[0] __aligned(ARCH_KMALLOC_MINALIGN); /* totls have native structs */
};

static struct wkic_item *witem_container(struct rb_node *node)
{
	return !node ? NULL : container_of(node, struct wkic_item, node);
}

static struct wkic_item *first_witem(struct rb_root *root)
{
	return witem_container(rb_first(root));
}

static struct wkic_item *last_witem(struct rb_root *root)
{
	return witem_container(rb_last(root));
}

static struct wkic_item *next_witem(struct wkic_item *witem)
{
	return witem_container(!witem ? NULL : rb_next(&witem->node));
}

static struct wkic_item *prev_witem(struct wkic_item *witem)
{
	return witem_container(!witem ? NULL : rb_prev(&witem->node));
}

static struct wkic_page *alloc_wpage(struct super_block *sb, struct scoutfs_key *start,
				     struct scoutfs_key *end, u64 read_seq)
{
	struct wkic_page *wpage;

	wpage = (void *)__get_free_page(GFP_NOFS);
	if (wpage) {
		RB_CLEAR_NODE(&wpage->nodes[0]);
		RB_CLEAR_NODE(&wpage->nodes[1]);
		wpage->start = *start;
		wpage->end = *end;
		wpage->item_root = RB_ROOT;
		wpage->expiration = ktime_set(0, 0); /* later set as added to expire list */
		INIT_LIST_HEAD(&wpage->head);
		wpage->read_seq = read_seq;
		wpage->ins_parent = NULL;
		wpage->ins_node = NULL;

		trace_wpage(sb, alloced, -1, wpage);
	}

	return wpage;
}

static void free_wpage(struct super_block *sb, struct wkic_page *wpage)
{
	if (wpage) {
		trace_wpage(sb, freeing, -1, wpage);

		BUG_ON(!RB_EMPTY_NODE(&wpage->nodes[0]));
		BUG_ON(!RB_EMPTY_NODE(&wpage->nodes[1]));
		BUG_ON(!list_empty(&wpage->head));

		free_page((long)wpage);
	}
}

static struct wkic_page *find_wpage(struct super_block *sb, struct rb_root *root,
				    unsigned int which, struct scoutfs_key *start,
				    struct scoutfs_key *end, struct rb_node **parent_ret,
				    struct rb_node ***node_ret)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct wkic_page *wpage = NULL;
	int cmp;

	while (*node) {
		parent = *node;
		wpage = wpage_container(*node, which);

		cmp = scoutfs_key_compare_ranges(start, end, &wpage->start, &wpage->end);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			trace_wpage(sb, found, which, wpage);
			return wpage;
		}
	}

	if (parent_ret) {
		*parent_ret = parent;
		*node_ret = node;
	}

	return NULL;
}

static void trim_wpage(struct super_block *sb, struct wkic_page *wpage,
		       bool from_start, struct scoutfs_key *edge)
{
	struct wkic_item *witem;
	struct wkic_item *tmp;
	int cmp;

	witem = from_start ? first_witem(&wpage->item_root) : last_witem(&wpage->item_root);
	while (witem) {
		cmp = scoutfs_key_compare(&witem->key, edge);

		if ((from_start && cmp >= 0) || (!from_start && cmp <= 0))
			break;

		tmp = from_start ? next_witem(witem) : prev_witem(witem);
		rb_erase(&witem->node, &wpage->item_root);
		witem = tmp;
	}

	trace_wpage(sb, trimmed, -1, wpage);
}

static void erase_wpage(struct super_block *sb, struct rb_root *root, unsigned int which,
			struct wkic_page *wpage)
{
	BUG_ON(RB_EMPTY_NODE(&wpage->nodes[which]));

	rb_erase(&wpage->nodes[which], root);
	RB_CLEAR_NODE(&wpage->nodes[which]);
	trace_wpage(sb, erased, which, wpage);
}

/*
 * Try to insert a page into a tree.  We can't insert pages into the
 * tree that overlap and once pages are inserted they can't be changed.
 * If an existing page intersects with our insertion then we have to
 * look at the two pages to find out which to drop or trim.
 *
 * As this modifies the tree it logs the pages on the caller's log list.
 * If this doesn't insert the page then it returns false so the caller
 * can free it.
 */
static bool try_insert_wpage(struct super_block *sb, struct wkic_info *winf, struct rb_root *root,
			     unsigned int which, ktime_t now, struct wkic_page *ins,
			     struct list_head *log_list)
{
	struct wkic_page *wpar;
	struct wkic_page *olap;
	struct rb_node *parent;
	struct rb_node **node;
	int is_os;
	int ie_oe;

	trace_wpage(sb, inserting, which, ins);

	/* check for overlaps with insertion, there can be many */
	while ((olap = find_wpage(sb, root, which, &ins->start, &ins->end, &parent, &node))) {

		if (wpage_expired(olap, now) || ins->read_seq > olap->read_seq) {
			/* erase overlap if it's expired or older than insertion */
			erase_wpage(sb, root, which, olap);
			list_move_tail(&olap->head, log_list);

		} else  {
			is_os = scoutfs_key_compare(&ins->start, &olap->start);
			ie_oe = scoutfs_key_compare(&ins->end, &olap->end);

			if (is_os >= 0 && ie_oe <= 0) {
				/* drop insertion when entirely within newer overlap */
				ins = NULL;
				break;
			}

			if (ie_oe > 0) {
				/*
				 * trim start to cache exposed insertion
				 * end.  This also catches the case
				 * where the newer overlap is within the
				 * insertion, we want to bias later
				 * keys.
				 */
				ins->start = olap->end;
				scoutfs_key_inc(&ins->start);
				trim_wpage(sb, ins, true, &ins->start);
			} else {
				/* otherwise trim end to cache exposed start */
				ins->end = olap->start;
				scoutfs_key_dec(&ins->end);
				trim_wpage(sb, ins, false, &ins->end);
			}
		}
	}

	if (ins) {
		rb_link_node(&ins->nodes[which], parent, node);
		rb_insert_color(&ins->nodes[which], root);
		list_add_tail(&ins->head, log_list);

		trace_wpage(sb, inserted, which, ins);

		if (parent == NULL) {
			ins->ins_parent = NULL;
			ins->ins_node = &winf->wpage_roots[!which].rb_node;
		} else {
			wpar = wpage_container(parent, which);

			ins->ins_parent = &wpar->nodes[!which];
			if (node == &parent->rb_left)
				ins->ins_node = &ins->ins_parent->rb_left;
			else
				ins->ins_node = &ins->ins_parent->rb_right;
		}
	}

	return ins != NULL;
}

static unsigned which_reading(struct wkic_info *winf)
{
	unsigned int which;

	which = !!test_bit(WINF_BIT_READING, &winf->bits);
	smp_rmb(); /* bit read before any tree access */
	return which;
}

/*
 * Set the reading bit so readers start using it.
 */
static void set_reading(struct wkic_info *winf, unsigned int which)
{
	smp_wmb(); /* tree updates visible before bit changes */
	if (which)
		set_bit(WINF_BIT_READING, &winf->bits);
	else
		clear_bit(WINF_BIT_READING, &winf->bits);
}

/*
 * Verify that the two trees identically index the same set of pages.
 */
__always_unused
static void verify_trees(struct wkic_info *winf)
{
	struct rb_node *zero;
	struct rb_node *one;

	zero = rb_first(&winf->wpage_roots[0]);
	one = rb_first(&winf->wpage_roots[1]);
	for (;;) {
		BUG_ON((zero == NULL && one != NULL) || (zero && one != zero + 1));
		if (!zero)
			break;
		zero = rb_next(zero);
		one = rb_next(one);
	}
}

/*
 * Make an update to the page rbtrees.  As we start the two trees are in
 * sync.  We make our changes to the non-reading tree, flip the reading
 * bit, and then replay the changes in the other tree.
 *
 * Updates are serialized and high latency.  They block on a mutex and
 * then wait for two RCU grace periods to make sure each non-reading
 * tree is idle.  This keeps the writer simple with a constrained update
 * mechanism that doesn't have any async processing.  Writers are
 * already either expensive insertion of multiple pages read from block
 * IO or are responding to pressure from the shrinker.  It's worth
 * slowing them down to make reads fully concurrent with no store
 * contention (almost, there's some false sharing in the pages).
 *
 * shrink_nr controls how we'll shrink.  We'll always try and remove
 * expired pages but we'll also push into un-expired pages when
 * shrink_nr is non-zero and it wasn't satisfied by shrinking the
 * initial set of expired pages.
 *
 * If the drop range is specified then we drop any pages that intersect
 * with the range and which were not read from the current roots.
 *
 * Returns true if we were able to acquire the lock and made changes,
 * which is always the case unless the caller asked us to acquire the
 * update mutex with trylock.
 */
static bool update_trees(struct super_block *sb, struct wkic_info *winf,
			 struct list_head *ins_list, unsigned long shrink_nr,
			 struct scoutfs_key *drop_start, struct scoutfs_key *drop_end,
			 bool trylock)
{
	struct wkic_page *wpage;
	struct wkic_page *tmp;
	struct rb_root *root;
	unsigned int which;
	LIST_HEAD(log_list);
	ktime_t expiration;
	ktime_t now;

	if (trylock) {
		if (!mutex_trylock(&winf->update_mutex))
			return false;
	} else {
		mutex_lock(&winf->update_mutex);
	}

	synchronize_rcu();
	which = !which_reading(winf);
	root = &winf->wpage_roots[which];
	now = ktime_get_raw();
	expiration = ktime_add_ms(now, WKIC_CACHE_LIFETIME_MS);

	/* erase expired pages, possibly satisfying nr by shrinking before expiration */
	list_for_each_entry_safe(wpage, tmp, &winf->shrink_list, head) {
		if (shrink_nr == 0 && !wpage_expired(wpage, now))
			break;

		trace_wpage(sb, shrinking, which, wpage);
		erase_wpage(sb, root, which, wpage);
		list_move_tail(&wpage->head, &log_list);
		atomic64_dec(&winf->shrink_count);

		if (shrink_nr > 0)
			shrink_nr--;
	}

	/* drop pages in the drop range outside the current read_seq */
	if (drop_start)
		wpage = find_wpage(sb, root, which, drop_start, drop_end, NULL, NULL);
	else
		wpage = NULL;
	for_each_wpage_safe(wpage, tmp, which) {
	       if (scoutfs_key_compare_ranges(&wpage->start, &wpage->end, drop_start, drop_end))
		       break;
		trace_wpage(sb, dropping, which, wpage);
		erase_wpage(sb, root, which, wpage);
		list_move_tail(&wpage->head, &log_list);
		atomic64_dec(&winf->shrink_count);
	}

	/* try to insert new pages, rarely freed if expired or overlap with newer */
	list_for_each_entry_safe(wpage, tmp, ins_list, head) {
		list_del_init(&wpage->head);
		BUG_ON(!RB_EMPTY_NODE(&wpage->nodes[0]));
		BUG_ON(!RB_EMPTY_NODE(&wpage->nodes[1]));

		wpage->expiration = expiration;

		if (!try_insert_wpage(sb, winf, root, which, now, wpage, &log_list))
			free_wpage(sb, wpage);
	}

	/* flip reading and wait to drain */
	set_reading(winf, which);
	synchronize_rcu();
	which = !which;
	root = &winf->wpage_roots[which];

	/* bring trees in sync by replaying changes to logged pages */
	list_for_each_entry_safe(wpage, tmp, &log_list, head) {
		trace_wpage(sb, replaying, which, wpage);
		if (RB_EMPTY_NODE(&wpage->nodes[which])) {
			rb_link_node(&wpage->nodes[which], wpage->ins_parent, wpage->ins_node);
			rb_insert_color(&wpage->nodes[which], root);
			wpage->ins_parent = NULL;
			wpage->ins_node = NULL;
			list_move_tail(&wpage->head, &winf->shrink_list);
			atomic64_inc(&winf->shrink_count);
		} else {
			list_del_init(&wpage->head);
			erase_wpage(sb, root, which, wpage);
			free_wpage(sb, wpage);
		}
	}

	/* and finally let readers see stable tree */
	set_reading(winf, which);

	mutex_unlock(&winf->update_mutex);
	return true;
}

static unsigned long wkic_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
{
	struct wkic_info *winf = KC_SHRINKER_CONTAINER_OF(shrink, struct wkic_info);

	return shrinker_min_long(atomic64_read(&winf->shrink_count));
}

static unsigned long wkic_shrink_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	struct wkic_info *winf = KC_SHRINKER_CONTAINER_OF(shrink, struct wkic_info);
	struct super_block *sb = winf->sb;
	unsigned long freed = 0;
	unsigned long before;
	unsigned long after;
	LIST_HEAD(empty_list);

	if (sc->nr_to_scan > 0) {
		before = wkic_shrink_count(shrink, sc);
		update_trees(sb, winf, &empty_list, sc->nr_to_scan, NULL, NULL, true);
		after = wkic_shrink_count(shrink, sc);
		if (before > after)
			freed = before - after;
	}

	return freed;
}

/*
 * Search for and return the item with the given key.  The caller can
 * also ask us to set a pointer to the next item after the search key or
 * to give them the final parent and node pointer for insertion.
 */
static struct wkic_item *find_witem(struct rb_root *root, struct scoutfs_key *key,
				    struct wkic_item **next, struct rb_node **parent_ret,
				    struct rb_node ***node_ret)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct wkic_item *witem;
	int cmp;

	if (next)
		*next = NULL;

	while (*node) {
		parent = *node;
		witem = container_of(*node, struct wkic_item, node);

		cmp = scoutfs_key_compare(key, &witem->key);
		if (cmp < 0) {
			if (next)
				*next = witem;
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			return witem;
		}
	}

	if (parent_ret) {
		*parent_ret = parent;
		*node_ret = node;
	}

	return NULL;
}

/*
 * Add each item from the persistent btree blocks into our private
 * rbtree.  We have to keep deleted items so that they can override
 * older items but they'll be dropped as we copy into the final cached
 * pages.
 *
 * xattr totl items are special because we need visibility into multiple
 * versions of the totals before we resolve them into a consistent
 * total.  We transform their value payload into the totl_merge struct
 * as we read and convert it back into the raw form once we've read all
 * the items and copy it into the cached pages.
 */
static int read_items_cb(struct super_block *sb, struct scoutfs_key *key, u64 seq, u8 flags,
			 void *val, int val_len, int fic, void *arg)
{
	const bool is_totl = key->sk_zone == SCOUTFS_XATTR_TOTL_ZONE;
	struct scoutfs_totl_merging *merg;
	struct rb_root *root = arg;
	struct wkic_item *witem;
	struct wkic_item *found;
	struct rb_node *parent = NULL;
	struct rb_node **node = NULL;
	int ret;

	found = find_witem(root, key, NULL, &parent, &node);
	if (found) {
		if (is_totl) {
			merg = (void *)found->val;
			scoutfs_totl_merge_contribute(merg, seq, flags, val, val_len, fic);
			ret = 0;
			goto out;
		}

		if (found->seq >= seq) {
			ret = 0;
			goto out;
		}

		/* caller's item is newer, will replace and free found below */
	}

	if (is_totl) {
		if (val_len != sizeof(struct scoutfs_xattr_totl_val)) {
			ret = -EIO;
			goto out;
		}
		val_len = sizeof(struct scoutfs_totl_merging);
	}

	witem = kmalloc(offsetof(struct wkic_item, val[val_len]), GFP_NOFS);
	if (!witem) {
		ret = -ENOMEM;
		goto out;
	}

	witem->key = *key;
	witem->seq = seq;
	witem->val_len = val_len;
	witem->flags = flags;
	if (is_totl) {
		merg = (void *)witem->val;
		scoutfs_totl_merge_init(merg);
		scoutfs_totl_merge_contribute(merg, seq, flags, val, val_len, fic);
	} else if (val_len) {
		memcpy(witem->val, val, val_len);
	}

	if (found) {
		rb_replace_node(&found->node, &witem->node, root);
		kfree(found);
	} else {
		rb_link_node(&witem->node, parent, node);
		rb_insert_color(&witem->node, root);
	}

	ret = 0;
out:
	return ret;
}

static void fill_page_items(struct super_block *sb, struct wkic_page *wpage, struct rb_root *root)
{
	struct scoutfs_xattr_totl_val *tval;
	struct scoutfs_totl_merging *merg;
	struct wkic_item *pg_item;
	struct wkic_item *witem;
	struct wkic_item *tmp;
	struct rb_node *parent;
	struct rb_node **node;
	unsigned int bytes;
	u64 total;
	u64 count;

	pg_item = (void*)wpage + ALIGN(sizeof(struct wkic_page), ARCH_KMALLOC_MINALIGN);
	parent = NULL;
	node = &wpage->item_root.rb_node;

	for (witem = first_witem(root); witem && ((tmp = next_witem(witem)), 1); witem = tmp) {

		/* free deleted items */
		if (witem->flags & SCOUTFS_ITEM_FLAG_DELETION) {
			rb_erase(&witem->node, root);
			kfree(witem);
			continue;
		}

		/*
		 * Transform the totl merge back into the raw totals,
		 * freeing it if it comes to zero.
		 */
		if (witem->key.sk_zone == SCOUTFS_XATTR_TOTL_ZONE &&
		    witem->val_len == sizeof(struct scoutfs_totl_merging)) {
			BUILD_BUG_ON(sizeof(struct scoutfs_xattr_totl_val) >
				     sizeof(struct scoutfs_totl_merging));
			merg = (void *)witem->val;
			scoutfs_totl_merge_resolve(merg, &total, &count);
			tval = (void *)witem->val;
			tval->total = cpu_to_le64(total);
			tval->count = cpu_to_le64(count);
			witem->val_len = sizeof(struct scoutfs_xattr_totl_val);

			if (tval->total == 0 && tval->count == 0) {
				rb_erase(&witem->node, root);
				kfree(witem);
				continue;
			}
		}

		bytes = ALIGN(offsetof(struct wkic_item, val[witem->val_len]),
			      ARCH_KMALLOC_MINALIGN);
		if ((long)pg_item - (long)wpage + bytes > PAGE_SIZE) {
			wpage->end = witem->key;
			scoutfs_key_dec(&wpage->end);
			break;
		}

		/* add item to end of page */
		pg_item->key = witem->key;
		pg_item->seq = witem->seq;
		pg_item->val_len = witem->val_len;
		pg_item->flags = witem->flags;
		if (witem->val_len)
			memcpy(pg_item->val, witem->val, witem->val_len);

		/* always inserting greatest item into page */
		rb_link_node(&pg_item->node, parent, node);
		rb_insert_color(&pg_item->node, &wpage->item_root);
		parent = &pg_item->node;
		node = &pg_item->node.rb_right;

		pg_item = (void*)pg_item + bytes;

		rb_erase(&witem->node, root);
		kfree(witem);
	}

	trace_wpage(sb, filled, -1, wpage);
}

static void free_item_tree(struct rb_root *root)
{
	struct wkic_item *witem;
	struct wkic_item *tmp;

	rbtree_postorder_for_each_entry_safe(witem, tmp, root, node)
		kfree(witem);
}

static void free_page_list(struct super_block *sb, struct list_head *list)
{
	struct wkic_page *wpage;
	struct wkic_page *tmp;

	list_for_each_entry_safe(wpage, tmp, list, head) {
		list_del_init(&wpage->head);
		free_wpage(sb, wpage);
	}
}

/*
 * We tie exclusive sampling of the forest btree roots to an increasing
 * read_seq number so that we can compare the age of the items in cached
 * pages.  Only one request to refresh the roots is in progress at a
 * time.  This is the slow path that's only used when the cache isn't
 * populated and the roots aren't cached.  The root request is fast
 * enough, especially compared to the resulting item reading IO, that we
 * don't mind hiding it behind a trivial mutex.
 */
static int get_roots(struct super_block *sb, struct wkic_info *winf,
		     struct scoutfs_net_roots *roots_ret, u64 *read_seq, bool force_new)
{
	struct scoutfs_net_roots roots;
	int ret;

	mutex_lock(&winf->roots_mutex);

	if (force_new || ktime_before(winf->roots_expire, ktime_get_raw())) {
		ret = scoutfs_client_get_roots(sb, &roots);
		if (ret < 0)
			goto out;

		winf->roots = roots;
		winf->roots_read_seq++;
		winf->roots_expire = ktime_add_ms(ktime_get_raw(), WKIC_CACHE_LIFETIME_MS);
	}

	*roots_ret = winf->roots;
	*read_seq = winf->roots_read_seq;
	ret = 0;
out:
	mutex_unlock(&winf->roots_mutex);

	return ret;
}

static void invalidate_cached_roots(struct wkic_info *winf)
{
	mutex_lock(&winf->roots_mutex);
	winf->roots_expire = ktime_sub_ns(ktime_get_raw(), WKIC_CACHE_LIFETIME_MS * NSEC_PER_MSEC);
	mutex_unlock(&winf->roots_mutex);
}

/*
 * Populate the cache when a caller finds that their key isn't cached.
 * This is the expensive slow path that waits for many dependent block
 * IO reads.
 *
 * We read items from the forest of btrees but we control the version of
 * the roots we read from so that we can order pages and insure that
 * cached items strictly advance over time.  We need to carefully handle
 * reading from stale blocks -- we need to force getting new roots and
 * still return a hard error if the block still look bad.
 *
 * As our callback sees items we merge them into a private rbtree.  We
 * copy the eventual set of read items into pages and return once
 * they're inserted into the trees.
 */
static int insert_read_pages(struct super_block *sb, struct wkic_info *winf,
			     struct scoutfs_key *key, struct scoutfs_key *range_start,
			     struct scoutfs_key *range_end)
{
	struct scoutfs_net_roots roots;
	struct rb_root root = RB_ROOT;
	struct scoutfs_key pg_start;
	DECLARE_SAVED_REFS(saved);
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct wkic_page *wpage;
	LIST_HEAD(pages);
	u64 read_seq;
	int ret;

	ret = 0;
retry_stale:
	ret = get_roots(sb, winf, &roots, &read_seq, ret == -ESTALE);
	if (ret < 0)
		goto out;

	start = *range_start;
	end = *range_end;
	ret = scoutfs_forest_read_items_roots(sb, &roots, key, range_start, &start, &end,
					      read_items_cb, &root);
	trace_scoutfs_wkic_read_items(sb, key, &start, &end);
	ret = scoutfs_block_check_stale(sb, ret, &saved, &roots.fs_root.ref, &roots.logs_root.ref);
	if (ret < 0) {
		if (ret == -ESTALE)
			goto retry_stale;
		goto out;
	}

	/* pack all the read items into pages, can make empty range page  */
	pg_start = start;
	do {
		wpage = alloc_wpage(sb, &pg_start, &end, read_seq);
		if (!wpage) {
			ret = -ENOMEM;
			goto out;
		}
		list_add_tail(&wpage->head, &pages);

		fill_page_items(sb, wpage, &root);

		pg_start = wpage->end;
		scoutfs_key_inc(&pg_start);

	} while (!RB_EMPTY_ROOT(&root));

	update_trees(sb, winf, &pages, 0, NULL, NULL, false);
	ret = 0;
out:
	free_item_tree(&root);
	free_page_list(sb, &pages);

	return ret;
}

/*
 * Search for the page that contains the starting key and call the
 * callback on items up to and including the last key.  Iteration will
 * stop if the callback returns anything other than -EAGAIN.  If there
 * isn't a page containing the key then we return -ENODATA, expecting
 * the caller to read pages that contain the key and try again.
 *
 * If the caller wants stable iteration then we use their stable_seq storage
 * to ensure that all the items come from the same root.  We return
 * -ESTALE if items were read from different roots and might be an
 * inconsistent set of items.
 */
static int iterate_page_items(struct super_block *sb, struct wkic_info *winf,
			      struct scoutfs_key *key, struct scoutfs_key *last,
			      ktime_t now, u64 *stable_seq, wkic_iter_cb_t cb, void *cb_arg)
{
	struct wkic_page *wpage;
	struct wkic_item *witem;
	struct wkic_item *next;
	struct rb_root *root;
	unsigned int which;
	int ret;

	rcu_read_lock();
	which = which_reading(winf);
	root = &winf->wpage_roots[which];

	wpage = find_wpage(sb, root, which, key, key, NULL, NULL);
	if (!wpage || wpage_expired(wpage, now)) {
		ret = -ENODATA;
		goto out;
	}

	if (stable_seq) {
		if (*stable_seq == 0) {
			*stable_seq = wpage->read_seq;
		} else if (wpage->read_seq != *stable_seq) {
			ret = -ESTALE;
			goto out;
		}
	}

	witem = find_witem(&wpage->item_root, key, &next, NULL, NULL) ?: next;
	while (witem) {
		if (scoutfs_key_compare(&witem->key, last) > 0)
			break;

		ret = cb(&witem->key, witem->val, witem->val_len, cb_arg);
		if (WARN_ON_ONCE(ret == -ENODATA))
			ret = -EINVAL;
		if (ret != -EAGAIN)
			goto out;

		witem = next_witem(witem);
	}

	if (scoutfs_key_compare(&wpage->end, last) >= 0) {
		/* done if the page covered the end of the range */
		ret = 0;
	} else {
		/* keep iterating into the next page */
		*key = wpage->end;
		scoutfs_key_inc(key);
		ret = -EAGAIN;
	}
out:
	rcu_read_unlock();
	return ret;
}

/*
 * Call the caller's callback on all cached items from and including the
 * starting key until and including the last key.  The callback can stop
 * iterating by returning anything other than -EAGAIN which will be
 * returned to the caller.  This can return hard allocation and IO
 * errors.
 *
 * If the read is stable then we make sure that all the items came from
 * pages with the same read_seq which means that they were read from
 * the same root and are a consistent set of items.
 */
static int iterate_and_read(struct super_block *sb, struct scoutfs_key *key,
			    struct scoutfs_key *last, struct scoutfs_key *range_start,
			    struct scoutfs_key *range_end, u64 *stable_seq,
			    wkic_iter_cb_t cb, void *cb_arg)
{
	struct wkic_info *winf = SCOUTFS_SB(sb)->wkic_info;
	struct scoutfs_key pos = *key;
	ktime_t now = ktime_get_raw();
	int ret;

	do {
		ret = iterate_page_items(sb, winf, &pos, last, now, stable_seq, cb, cb_arg);
		if (ret == -ENODATA) {
			ret = insert_read_pages(sb, winf, &pos, range_start, range_end);
			if (ret == 0) {
				now = ktime_get_raw();
				ret = -EAGAIN;
			}
		}
	} while (ret == -EAGAIN);

	return ret;
}

int scoutfs_wkic_iterate(struct super_block *sb, struct scoutfs_key *key, struct scoutfs_key *last,
			 struct scoutfs_key *range_start, struct scoutfs_key *range_end,
			 wkic_iter_cb_t cb, void *cb_arg)
{
	return iterate_and_read(sb, key, last, range_start, range_end, NULL, cb, cb_arg);
}

/*
 * If we hit a stable inconsistency then we drop the pages in the range
 * that are not from the current read_seq and tell the caller to
 * retry.  We can't retry ourselves because we can't claw back items
 * that we gave to the callback before we found the inconsistency.
 */
int scoutfs_wkic_iterate_stable(struct super_block *sb, struct scoutfs_key *key,
				struct scoutfs_key *last, struct scoutfs_key *range_start,
				struct scoutfs_key *range_end, wkic_iter_cb_t cb, void *cb_arg)
{
	struct wkic_info *winf = SCOUTFS_SB(sb)->wkic_info;
	LIST_HEAD(empty_list);
	u64 stable_seq = 0;
	int ret;

	ret = iterate_and_read(sb, key, last, range_start, range_end, &stable_seq, cb, cb_arg);
	if (ret == -ESTALE)
		update_trees(sb, winf, &empty_list, 0, key, last, false);

	return ret;
}

static ssize_t wkic_drop_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	return 0;
}

/*
 * Drop all pages in the weak item cache.  We don't strictly drain the
 * cache size to zero but make as many attempts as would be needed to
 * fully drain the cache given its size as the call was made.  We drop
 * the cached roots so that the next cache read will get the current
 * version of the persistent structures.  This is only a best effort for
 * testing in reasonably controlled circumstances.
 */
static ssize_t wkic_drop_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	struct wkic_info *winf = file_inode(file)->i_private;
	struct super_block *sb = winf->sb;
	LIST_HEAD(empty_list);
	u64 iter;

	invalidate_cached_roots(winf);

	iter = (atomic64_read(&winf->shrink_count) + 1023) >> 10;
	while (iter--)
		update_trees(sb, winf, &empty_list, 1024, NULL, NULL, false);

	return size;
}

static const struct file_operations wkic_drop_fops = {
	.read =		wkic_drop_read,
	.write =	wkic_drop_write,
};

int scoutfs_wkic_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wkic_info *winf;

	winf = kzalloc(sizeof(struct wkic_info), GFP_KERNEL);
	if (!winf)
		return -ENOMEM;

	winf->wpage_roots[0] = RB_ROOT;
	winf->wpage_roots[1] = RB_ROOT;
	mutex_init(&winf->update_mutex);
	INIT_LIST_HEAD(&winf->shrink_list);
	atomic64_set(&winf->shrink_count, 0);
	mutex_init(&winf->roots_mutex);
	winf->roots_read_seq = 1; /* 0 is unused */

	invalidate_cached_roots(winf);

	winf->drop_dentry = debugfs_create_file("drop_weak_item_cache", S_IFREG|S_IRUSR,
						sbi->debug_root, winf, &wkic_drop_fops);
	if (!winf->drop_dentry) {
		kfree(winf);
		return -ENOMEM;
	}

	winf->sb = sb;
	KC_INIT_SHRINKER_FUNCS(&winf->shrinker, wkic_shrink_count, wkic_shrink_scan);
	KC_REGISTER_SHRINKER(&winf->shrinker);

	sbi->wkic_info = winf;
	return 0;
}

/*
 * Make sure that the two nodes in a page have the same pointers set.
 * It's a weak check, but it's trivial and will catch wild divergence
 * between the trees.
 */
static void bug_on_differing_pointers(struct rb_node *zero, struct rb_node *one)
{
	BUG_ON(!rb_parent(zero) != !rb_parent(one));
	BUG_ON(!zero->rb_left != !one->rb_left);
	BUG_ON(!zero->rb_right != !one->rb_right);
}

void scoutfs_wkic_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct wkic_info *winf = sbi->wkic_info;
	struct wkic_page *wpage;
	struct wkic_page *tmp;
	LIST_HEAD(list);

	if (winf) {
		debugfs_remove(winf->drop_dentry);
		KC_UNREGISTER_SHRINKER(&winf->shrinker);

		/* trees are in sync so tearing down one frees all pages */
		rbtree_postorder_for_each_entry_safe(wpage, tmp, &winf->wpage_roots[0], nodes[0]) {
			bug_on_differing_pointers(&wpage->nodes[0], &wpage->nodes[1]);
			RB_CLEAR_NODE(&wpage->nodes[0]);
			RB_CLEAR_NODE(&wpage->nodes[1]);
			list_del_init(&wpage->head);
			free_wpage(sb, wpage);
		}

		BUG_ON(!list_empty(&winf->shrink_list));

		kfree(winf);
		sbi->wkic_info = NULL;
	}
}
