/*
 * Copyright (C) 2020 Versity Software, Inc.  All rights reserved.
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
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/list_sort.h>
#include <linux/cpu.h>
#include <linux/mm.h>

#include "super.h"
#include "item.h"
#include "forest.h"
#include "block.h"
#include "msg.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "util.h"

/*
 * The item cache maintains a consistent view of items that are read
 * from and written to the forest of btrees under the protection of
 * cluster locks.
 *
 * The cache is built around pages of items.  A page has the range of
 * keys that it caches and the items that are present in that range.
 * Pages are non-overlapping, there is only one page that can contain a
 * given key at a time.  The pages are tracked by an rbtree, and each
 * page has an rbtree of items.
 *
 * The cache is populated by reading items from the forest of btrees
 * into a private set of pages.  The regions of those pages which
 * weren't already cached are then inserted into the cache.
 *
 * CPUs can concurrently modify items that are in different pages.  The
 * page rbtree can be read locked to find a page, and then the page is
 * locked to work with its items.  We then add per-cpu references to
 * recently used pages so that the global page rbtree can be skipped in
 * the typical case of repeated calls to localized portions of the key
 * space.
 *
 * Dirty items are kept in a per-page dirty list, and pages with dirty
 * items are kept in a global dirty list.  This reduces contention on
 * the global list by accessing it at page granularity instead of every
 * time an item is dirtied.  The dirty items are not sorted until it
 * comes time to commit them to the btrees.  This reduces the cost of
 * tracking dirty items during the transaction, particularly moving them
 * between pages as pages are split to make room for new items.
 *
 * The size of the cache is only limited by memory reclaim.  Pages are
 * kept in a very coarse lru.  Dirtying doesn't remove pages from the
 * lru, and is operating against lock ordering with trylocks, so
 * shrinking can rarely have to skip pages in the LRU.
 *
 * The locking is built around the fast path of everyone checking the
 * the page rbtree, then locking pages, and then adding or removing
 * pages from the lru or dirty lists.  Writing and the shrinker work
 * work in reverse, starting with the dirty or lru lists and have to use
 * trylock to lock the pages.  When we split we have to lock multiple
 * pages and we use trylock which is guaranteed to succeed because the
 * pages are private.
 */

struct item_cache_info {
	/* almost always read, barely written */
	struct super_block *sb;
	struct item_percpu_pages __percpu *pcpu_pages;
	KC_DEFINE_SHRINKER(shrinker);
#ifdef KC_CPU_NOTIFIER
	struct notifier_block notifier;
#endif

	/* often walked, but per-cpu refs are fast path */
	rwlock_t rwlock;
	struct rb_root pg_root;

	/* page-granular modification by writers, then exclusive to commit */
	spinlock_t dirty_lock;
	struct list_head dirty_list;
	atomic_t dirty_pages;

	/* page-granular modification by readers */
	spinlock_t lru_lock;
	struct list_head lru_list;
	unsigned long lru_pages;

	/* written by page readers, read by shrink */
	spinlock_t active_lock;
	struct list_head active_list;
};

#define DECLARE_ITEM_CACHE_INFO(sb, name) \
	struct item_cache_info *name = SCOUTFS_SB(sb)->item_cache_info

#define PG_PER_CPU 32
struct item_percpu_pages {
	struct rb_root root;
	struct list_head list;
	struct pcpu_page_ref {
		struct scoutfs_key start;
		struct scoutfs_key end;
		struct cached_page *pg;
		struct rb_node node;
		struct list_head head;
	} refs[PG_PER_CPU];
};

struct cached_page {
	/* often read by concurrent rbtree walks */
	struct rb_node node;
	struct scoutfs_key start;
	struct scoutfs_key end;

	/* often modified by page rwlock holder */
	rwlock_t rwlock;
	struct rb_root item_root;
	struct list_head lru_head;
	unsigned long lru_time;
	struct list_head dirty_list;
	struct list_head dirty_head;
	u64 max_seq;
	struct page *page;
	unsigned int page_off;
	unsigned int erased_bytes;
	atomic_t refcount;
};

struct cached_item {
	struct rb_node node;
	struct list_head dirty_head;
	unsigned int dirty:1,		/* needs to be written */
		     persistent:1,	/* in btrees, needs deletion item */
		     deletion:1,	/* negative del item for writing */
		     delta:1;		/* item vales are combined, freed after write */
	unsigned int val_len;
	struct scoutfs_key key;
	u64 seq;
	char val[0];
};

#define CACHED_ITEM_ALIGN 8

static int item_val_bytes(int val_len)
{
	return round_up(offsetof(struct cached_item, val[val_len]),
			CACHED_ITEM_ALIGN);
}

/*
 * Return if the page has room to allocate an item with the given value
 * length at its free page offset.  This must be called with the page
 * writelock held because it can modify the page to reclaim free space
 * to mkae room for the allocation.  Today all it does is recognize that
 * the page is empty and reset the page_off.
 */
static bool page_has_room(struct cached_page *pg, int val_len)
{
	if (RB_EMPTY_ROOT(&pg->item_root))
		pg->page_off = 0;

	return pg->page_off + item_val_bytes(val_len) <= PAGE_SIZE;
}

static struct cached_page *first_page(struct rb_root *root)
{
	struct rb_node *node;

	if (!root || !(node = rb_first(root)))
		return NULL;

	return rb_entry(node, struct cached_page, node);
}

static struct cached_item *first_item(struct rb_root *root)
{
	struct rb_node *node;

	if (!root || !(node = rb_first(root)))
		return NULL;

	return rb_entry(node, struct cached_item, node);
}

static struct cached_item *last_item(struct rb_root *root)
{
	struct rb_node *node;

	if (!root || !(node = rb_last(root)))
		return NULL;

	return rb_entry(node, struct cached_item, node);
}

static struct cached_item *next_item(struct cached_item *item)
{
	struct rb_node *node;

	if (!item || !(node = rb_next(&item->node)))
		return NULL;

	return rb_entry(node, struct cached_item, node);
}

static struct cached_item *prev_item(struct cached_item *item)
{
	struct rb_node *node;

	if (!item || !(node = rb_prev(&item->node)))
		return NULL;

	return rb_entry(node, struct cached_item, node);
}

static void rbtree_insert(struct rb_node *node, struct rb_node *par,
			  struct rb_node **pnode, struct rb_root *root)
{
	rb_link_node(node, par, pnode);
	rb_insert_color(node, root);
}

static void rbtree_erase(struct rb_node *node, struct rb_root *root)
{
	rb_erase(node, root);
	RB_CLEAR_NODE(node);
}

static void rbtree_replace_node(struct rb_node *victim, struct rb_node *new,
				struct rb_root *root)
{
	rb_replace_node(victim, new, root);
	RB_CLEAR_NODE(victim);
}

/*
 * This is far too expensive to use regularly, but it's very helpful for
 * discovering corruption after modifications to cached pages.
 */
static __attribute__((unused)) void verify_page_rbtree(struct rb_root *root)
{
	struct cached_item *item;
	struct cached_page *par;
	struct cached_page *pg;
	struct cached_page *n;
	char *reason = NULL;
	struct rb_node *p;
	int cmp;

	rbtree_postorder_for_each_entry_safe(pg, n, root, node) {

		item = NULL;
		par = NULL;

		if (scoutfs_key_compare(&pg->start, &pg->end) > 0) {
			reason = "start > end";
			break;
		}

		item = first_item(&pg->item_root);
		if (item && scoutfs_key_compare(&item->key, &pg->start) < 0) {
			reason = "first item < start";
			break;
		}

		item = last_item(&pg->item_root);
		if (item && scoutfs_key_compare(&item->key, &pg->end) > 0) {
			reason = "last item > end";
			break;
		}

		p = rb_parent(&pg->node);
		if (!p)
			continue;
		par = rb_entry(p, struct cached_page, node);

		cmp = scoutfs_key_compare_ranges(&pg->start, &pg->end,
						 &par->start, &par->end);
		if (cmp == 0) {
			reason = "parent and child overlap";
			break;
		}

		if (par->node.rb_right == &pg->node && cmp < 0) {
			reason = "right child < parent";
			break;
		}

		if (par->node.rb_left == &pg->node && cmp > 0) {
			reason = "left child > parent";
			break;
		}
	}

	if (!reason)
		return;

	printk("bad item page rbtree: %s\n", reason);
	printk("pg %p start "SK_FMT" end "SK_FMT"\n",
		pg, SK_ARG(&pg->start), SK_ARG(&pg->end));
	if (par)
		printk("par %p start "SK_FMT" end "SK_FMT"\n",
			par, SK_ARG(&par->start), SK_ARG(&par->end));
	if (item)
		printk("item %p key "SK_FMT"\n", item, SK_ARG(&item->key));

	rbtree_postorder_for_each_entry_safe(pg, n, root, node) {
		printk("  pg %p left %p right %p start "SK_FMT" end "SK_FMT"\n",
		       pg,
		       pg->node.rb_left ? rb_entry(pg->node.rb_left,
						   struct cached_page, node) :
					  NULL,
		       pg->node.rb_right ? rb_entry(pg->node.rb_right,
						   struct cached_page, node) :
					   NULL,
		       SK_ARG(&pg->start),
		       SK_ARG(&pg->end));
	}

	BUG();
}


/*
 * This lets us lock newly allocated pages without having to add nesting
 * annotation.  The non-acquired path is never executed.
 */
static void write_trylock_will_succeed(rwlock_t *rwlock)
__acquires(rwlock)
{
	while (!write_trylock(rwlock))
		BUG();
}

static struct cached_page *alloc_pg(struct super_block *sb, gfp_t gfp)
{
	struct cached_page *pg;
	struct page *page;

	pg = kzalloc(sizeof(struct cached_page), GFP_NOFS | gfp);
	page = alloc_page(GFP_NOFS | gfp);
	if (!page || !pg) {
		kfree(pg);
		if (page)
			__free_page(page);
		return NULL;
	}

	scoutfs_inc_counter(sb, item_page_alloc);

	RB_CLEAR_NODE(&pg->node);
	rwlock_init(&pg->rwlock);
	pg->item_root = RB_ROOT;
	INIT_LIST_HEAD(&pg->lru_head);
	INIT_LIST_HEAD(&pg->dirty_list);
	INIT_LIST_HEAD(&pg->dirty_head);
	pg->page = page;
	atomic_set(&pg->refcount, 1);

	return pg;
}

static void get_pg(struct cached_page *pg)
{
	atomic_inc(&pg->refcount);
}

static void put_pg(struct super_block *sb, struct cached_page *pg)
{
	if (pg && atomic_dec_and_test(&pg->refcount)) {
		scoutfs_inc_counter(sb, item_page_free);

		BUG_ON(!RB_EMPTY_NODE(&pg->node));
		BUG_ON(!list_empty(&pg->lru_head));
		BUG_ON(!list_empty(&pg->dirty_list));
		BUG_ON(!list_empty(&pg->dirty_head));

		__free_page(pg->page);
		kfree(pg);
	}
}

static void update_pg_max_seq(struct cached_page *pg, struct cached_item *item)
{
	if (item->seq > pg->max_seq)
		pg->max_seq = item->seq;
}

/*
 * Allocate space for a new item from the free offset at the end of a
 * cached page.  This isn't a blocking allocation, and it's likely that
 * the caller has ensured it will succeed by allocating from a new empty
 * page or checking the free space first.
 */
static struct cached_item *alloc_item(struct cached_page *pg,
				      struct scoutfs_key *key, u64 seq, bool deletion,
				      void *val, int val_len)
{
	struct cached_item *item;

	if (!page_has_room(pg, val_len))
		return NULL;

	item = page_address(pg->page) + pg->page_off;
	pg->page_off += item_val_bytes(val_len);

	RB_CLEAR_NODE(&item->node);
	INIT_LIST_HEAD(&item->dirty_head);
	item->dirty = 0;
	item->persistent = 0;
	item->deletion = !!deletion;
	item->delta = 0;
	item->val_len = val_len;
	item->key = *key;
	item->seq = seq;

	if (val_len)
		memcpy(item->val, val, val_len);

	update_pg_max_seq(pg, item);

	return item;
}

static void erase_item(struct cached_page *pg, struct cached_item *item)
{
	rbtree_erase(&item->node, &pg->item_root);
	pg->erased_bytes += item_val_bytes(item->val_len);
}

static void lru_add(struct super_block *sb, struct item_cache_info *cinf,
		      struct cached_page *pg)
{
	spin_lock(&cinf->lru_lock);
	if (list_empty(&pg->lru_head)) {
		scoutfs_inc_counter(sb, item_page_lru_add);
		list_add_tail(&pg->lru_head, &cinf->lru_list);
		cinf->lru_pages++;
	}
	spin_unlock(&cinf->lru_lock);
}

static void __lru_remove(struct super_block *sb, struct item_cache_info *cinf,
			 struct cached_page *pg)
{
	if (!list_empty(&pg->lru_head)) {
		scoutfs_inc_counter(sb, item_page_lru_remove);
		list_del_init(&pg->lru_head);
		cinf->lru_pages--;
	}
}

static void lru_remove(struct super_block *sb, struct item_cache_info *cinf,
		       struct cached_page *pg)
{
	spin_lock(&cinf->lru_lock);
	__lru_remove(sb, cinf, pg);
	spin_unlock(&cinf->lru_lock);
}

/*
 * Make sure that the page the caller just accessed is reasonably close
 * to the tail of the lru so it will be less likely to be reclaimed by
 * the shrinker.
 *
 * We want to quickly determine that the page is close enough to the
 * tail by only looking at the page.  We use a coarse clock tick to
 * determine if we've already moved the head to the tail sufficiently
 * recently.  We can't differentiate shrinking priority amongst the
 * number of pages that the cpu can access within given chunk of time.
 *
 * We don't care that the lru_time accessed aren't locked and could see
 * rare corruption.  It's just a shrink priority heuristic.
 */
static void lru_accessed(struct super_block *sb, struct item_cache_info *cinf,
			 struct cached_page *pg)
{
	unsigned long time = jiffies_to_msecs(jiffies);

	scoutfs_inc_counter(sb, item_page_accessed);

	if (pg->lru_time != time) {
		lru_remove(sb, cinf, pg);
		pg->lru_time = time;
		lru_add(sb, cinf, pg);
	}
}

/*
 * Return the pg that contains the key and set the parent nodes for insertion.
 * When we find the pg we go right so that the caller can insert a new
 * page to the right of the found page if it had to split the page.
 */
static struct cached_page *page_rbtree_walk(struct super_block *sb,
					    struct rb_root *root,
					    struct scoutfs_key *start,
					    struct scoutfs_key *end,
					    struct cached_page **prev,
					    struct cached_page **next,
					    struct rb_node **par,
					    struct rb_node ***pnode)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct cached_page *ret = NULL;
	struct cached_page *pg;
	int cmp;

	scoutfs_inc_counter(sb, item_page_rbtree_walk);

	if (next)
		*next = NULL;
	if (prev)
		*prev = NULL;

	while (*node) {
		parent = *node;
		pg = container_of(*node, struct cached_page, node);

		cmp = scoutfs_key_compare_ranges(start, end, &pg->start,
						 &pg->end);
		if (cmp < 0) {
			if (next)
				*next = pg;
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			if (prev)
				*prev = pg;
			node = &(*node)->rb_right;
		} else {
			ret = pg;
			node = &(*node)->rb_right;
		}
	}

	if (par)
		*par = parent;
	if (pnode)
		*pnode = node;

	return ret;
}

#define for_each_page_safe(root, pg, tmp)				  \
	for (tmp = rb_first(root);					  \
	     tmp && (pg = container_of(tmp, struct cached_page, node)) && \
		((tmp = rb_next(tmp)), 1); )

static struct cached_item *item_rbtree_walk(struct rb_root *root,
					    struct scoutfs_key *key,
					    struct cached_item **next,
					    struct rb_node **par,
					    struct rb_node ***pnode)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct cached_item *ret = NULL;
	struct cached_item *item;
	int cmp;

	if (next)
		*next = NULL;

	while (*node) {
		parent = *node;
		item = container_of(*node, struct cached_item, node);

		cmp = scoutfs_key_compare(key, &item->key);
		if (cmp < 0) {
			if (next)
				*next = item;
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			ret = item;
			node = &(*node)->rb_left;
		}
	}

	if (par)
		*par = parent;
	if (pnode)
		*pnode = node;

	return ret;
}

#define for_each_item_from_safe(root, item, tmp, key)			  \
	for (item = item_rbtree_walk(root, key, &tmp, NULL, NULL) ?: tmp; \
	     item && ((tmp = next_item(item)), 1);			  \
	     item = tmp)

#define for_each_item_safe(root, item, tmp)				    \
	for (tmp = rb_first(root);					    \
	     tmp && (item = container_of(tmp, struct cached_item, node)) && \
		((tmp = rb_next(tmp)), 1); )

/*
 * As we mark the first and clear the last items in a page, we add or
 * delete the page from the dirty list.  The caller can give us a page
 * to add the newly dirtied page after, rather than at the tail of the
 * list.
 */
static void mark_item_dirty(struct super_block *sb,
			    struct item_cache_info *cinf,
			    struct cached_page *pg,
			    struct cached_page *after,
			    struct cached_item *item)
{
	if (!item->dirty) {
		if (list_empty(&pg->dirty_list)) {
			scoutfs_inc_counter(sb, item_page_mark_dirty);
			spin_lock(&cinf->dirty_lock);
			if (after)
				list_add(&pg->dirty_head, &after->dirty_head);
			else
				list_add_tail(&pg->dirty_head,
					      &cinf->dirty_list);
			atomic_inc(&cinf->dirty_pages);
			spin_unlock(&cinf->dirty_lock);
		}

		scoutfs_inc_counter(sb, item_mark_dirty);
		list_add_tail(&item->dirty_head, &pg->dirty_list);
		item->dirty = 1;
	}

	update_pg_max_seq(pg, item);
}

static void clear_item_dirty(struct super_block *sb,
			     struct item_cache_info *cinf,
			     struct cached_page *pg,
			     struct cached_item *item)
{
	if (item->dirty) {
		scoutfs_inc_counter(sb, item_clear_dirty);
		item->dirty = 0;
		list_del_init(&item->dirty_head);

		if (list_empty(&pg->dirty_list)) {
			scoutfs_inc_counter(sb, item_page_clear_dirty);
			spin_lock(&cinf->dirty_lock);
			list_del_init(&pg->dirty_head);
			atomic_dec(&cinf->dirty_pages);
			spin_unlock(&cinf->dirty_lock);
		}
	}
}

static void erase_page_items(struct cached_page *pg,
			     struct scoutfs_key *start,
			     struct scoutfs_key *end)
{
	struct cached_item *item;
	struct cached_item *tmp;

	for_each_item_from_safe(&pg->item_root, item, tmp, start) {

		/* only called in unused read regions or read_pages pages */
		BUG_ON(item->dirty);

		if (scoutfs_key_compare(&item->key, end) > 0)
			break;

		erase_item(pg, item);
	}
}

/*
 * Move all the items starting from the key and stopping before moving
 * the stop key.  The right destination page must be empty.  Items are
 * copied in tree order which lets us easily insert after each previous
 * item.
 *
 * This preserves dirty page and item ordering by adding the right page
 * to the dirty list after the left page, and by adding items to the
 * tail of right's dirty list in key sort order.
 *
 * The max_seq of the source page might be larger than all the items
 * while protecting an erased item from being reclaimed while an older
 * read is in flight.  We don't know where it might be in the source
 * page so we have to assume that it's in the key range being moved and
 * update the destination page's max_seq accordingly.
 *
 * The caller is responsible for page locking and managing the lru.
 */
static void move_page_items(struct super_block *sb,
			    struct item_cache_info *cinf,
			    struct cached_page *left,
			    struct cached_page *right,
			    struct scoutfs_key *key,
			    struct scoutfs_key *stop)
{
	struct cached_item *from;
	struct cached_item *to;
	struct cached_item *tmp;
	struct rb_node **pnode;
	struct rb_node *par;

	/* really empty right destination? */
	BUG_ON(!RB_EMPTY_ROOT(&right->item_root));
	par = NULL;
	pnode = &right->item_root.rb_node;

	for_each_item_from_safe(&left->item_root, from, tmp, key) {

		if (stop && scoutfs_key_compare(&from->key, stop) >= 0)
			break;

		to = alloc_item(right, &from->key, from->seq, from->deletion, from->val,
				from->val_len);
		rbtree_insert(&to->node, par, pnode, &right->item_root);
		par = &to->node;
		pnode = &to->node.rb_right;

		if (from->dirty) {
			mark_item_dirty(sb, cinf, right, left, to);
			clear_item_dirty(sb, cinf, left, from);
		}

		to->persistent = from->persistent;
		to->delta = from->delta;

		erase_item(left, from);
	}

	if (left->max_seq > right->max_seq)
		right->max_seq = left->max_seq;
}

enum page_intersection_type {
	PGI_DISJOINT,
	PGI_INSIDE,
	PGI_START_OLAP,
	PGI_END_OLAP,
	PGI_BISECT_NEEDED,
	PGI_BISECT,
};

/*
 * Remove items from the page with intersect with the range.  We return
 * a code to indicate which kind of intersection occurred.  The caller
 * provides the right page to move items to if the page is bisected by
 * the range.
 *
 * This modifies the page keys so it needs to be held with a write page
 * rbtree lock if the page is in the page rbtree.
 */
static int trim_page_intersection(struct super_block *sb,
				  struct item_cache_info *cinf,
				  struct cached_page *pg,
				  struct cached_page *right,
				  struct scoutfs_key *start,
				  struct scoutfs_key *end)
{
	int ps_e = scoutfs_key_compare(&pg->start, end);
	int pe_s = scoutfs_key_compare(&pg->end, start);
	int ps_s;
	int pe_e;

	/*
	 * page and range don't intersect
	 *
	 *                     ps |----------|  pe
	 *  s |----------|  e
	 * (or)
	 * ps |----------|  pe
	 *                      s |----------|  e
	 */
	if (ps_e > 0 || pe_s < 0)
		return PGI_DISJOINT;

	ps_s = scoutfs_key_compare(&pg->start, start);
	pe_e = scoutfs_key_compare(&pg->end, end);

	/*
	 * page entirely inside range
	 *
	 * ps |----------|  pe
	 *  s |----------|  e
	 */
	if (ps_s >= 0 && pe_e <= 0)
		return PGI_INSIDE;

	/*
	 * page surrounds range, and is bisected by it
	 *
	 * ps |----------|  pe
	 *    s |------|  e
	 */
	if (ps_s < 0 && pe_e > 0) {
		if (!right)
			return PGI_BISECT_NEEDED;

		right->start = *end;
		scoutfs_key_inc(&right->start);
		right->end = pg->end;
		pg->end = *start;
		scoutfs_key_dec(&pg->end);
		erase_page_items(pg, start, end);
		move_page_items(sb, cinf, pg, right, &right->start, NULL);
		return PGI_BISECT;
	}

	/*
	 * start of page overlaps with range
	 *
	 *   ps |----------|  pe
	 *  s |----------|  e
	 */
	if (pe_e > 0) {
		/* start of page overlaps range */
		pg->start = *end;
		scoutfs_key_inc(&pg->start);
		erase_page_items(pg, start, end);
		return PGI_START_OLAP;
	}

	/*
	 * end of page overlaps with range
	 *
	 * ps |----------|  pe
	 *    s |----------|  e
	 */
	pg->end = *start;
	scoutfs_key_dec(&pg->end);
	erase_page_items(pg, start, end);
	return PGI_END_OLAP;
}

/*
 * The caller wants to allocate an item in the page but there isn't room
 * at the page_off.  If erasing items has left sufficient internal free
 * space we can pack the existing items to the start of the page to make
 * room for the insertion.
 *
 * The caller's empty pg is only used for its page struct, which we swap
 * with our old empty page.  We don't touch its pg struct.
 *
 * This is a coarse bulk way of dealing with free space, as opposed to
 * specifically tracking internal free regions and using them to satisfy
 * item allocations.
 */
static void compact_page_items(struct super_block *sb,
			       struct cached_page *pg,
			       struct cached_page *empty)
{
	struct cached_item *from;
	struct cached_item *to;
	struct rb_root item_root = RB_ROOT;
	struct rb_node *par = NULL;
	struct rb_node **pnode = &item_root.rb_node;
	unsigned int page_off = 0;
	LIST_HEAD(dirty_list);

	if (pg->erased_bytes < item_val_bytes(SCOUTFS_MAX_VAL_SIZE))
		return;

	if (WARN_ON_ONCE(empty->page_off != 0) ||
	    WARN_ON_ONCE(!RB_EMPTY_ROOT(&empty->item_root)) ||
	    WARN_ON_ONCE(!list_empty(&empty->dirty_list)))
		return;

	scoutfs_inc_counter(sb, item_page_compact);

	for (from = first_item(&pg->item_root); from; from = next_item(from)) {
		to = page_address(empty->page) + page_off;
		page_off += item_val_bytes(from->val_len);

		/* copy the entire item, struct members and all */
		memcpy(to, from, item_val_bytes(from->val_len));

		rbtree_insert(&to->node, par, pnode, &item_root);
		par = &to->node;
		pnode = &to->node.rb_right;

		if (to->dirty)
			list_add_tail(&to->dirty_head, &dirty_list);
	}

	pg->item_root = item_root;
	list_replace(&dirty_list, &pg->dirty_list);
	swap(pg->page, empty->page);
	pg->page_off = page_off;
	pg->erased_bytes = 0;
}

/*
 * This behaves a little differently than the other walks because we
 * want to minimize compares and there are only simple searching and
 * inserting callers.
 */
static struct pcpu_page_ref *pcpu_page_rbtree_walk(struct rb_root *root,
						   struct scoutfs_key *key,
						   struct pcpu_page_ref *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct pcpu_page_ref *ret = NULL;
	struct pcpu_page_ref *ref;
	int cmp;

	while (*node) {
		parent = *node;
		ref = container_of(*node, struct pcpu_page_ref, node);

		cmp = scoutfs_key_compare_ranges(key, key,
						 &ref->start, &ref->end);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			ret = ref;
			if (!ins)
				return ret;
			node = &(*node)->rb_right;
		}
	}

	if (ins)
		rbtree_insert(&ins->node, parent, node, root);

	return ret;
}

/*
 * Search the per-cpu page references for a page that contains the key
 * the caller needs.  These lookups are very frequent and key
 * comparisons are relatively expensive, so we use an rbtree to decrease
 * the comparison costs, particularly of misses.
 *
 * All the references in all the cpus go stale as page key boundaries
 * are modified by reading, insertion, and invalidation.  If we find a
 * stale ref we will drop it, but otherwise we let stale refs age out as
 * new refs are inserted.
 */
static struct cached_page *get_pcpu_page(struct super_block *sb,
					 struct item_cache_info *cinf,
					 struct scoutfs_key *key,
					 bool write)
{
	struct item_percpu_pages *pages = get_cpu_ptr(cinf->pcpu_pages);
	struct cached_page *pg = NULL;
	struct pcpu_page_ref *ref;

	ref = pcpu_page_rbtree_walk(&pages->root, key, NULL);
	if (ref) {
		pg = ref->pg;
		if (write)
			write_lock(&pg->rwlock);
		else
			read_lock(&pg->rwlock);

		if (scoutfs_key_compare_ranges(key, key,
					       &pg->start, &pg->end)) {
			if (write)
				write_unlock(&pg->rwlock);
			else
				read_unlock(&pg->rwlock);

			scoutfs_inc_counter(sb, item_pcpu_page_miss_keys);
			rbtree_erase(&ref->node, &pages->root);
			list_move_tail(&ref->head, &pages->list);
			put_pg(sb, pg);
			ref->pg = NULL;
			pg = NULL;
		} else {
			if (pages->list.next != &ref->head)
				list_move(&ref->head, &pages->list);
			__release(pg_rwlock);
		}
	}

	put_cpu_ptr(cinf->pcpu_pages);

	if (pg)
		scoutfs_inc_counter(sb, item_pcpu_page_hit);
	else
		scoutfs_inc_counter(sb, item_pcpu_page_miss);

	return pg;
}

/*
 * The caller has a locked page that it knows is authoritative for its
 * range of keys.  Add it to this cpu's cache and remove any other page
 * in the pool which intersects with its range.
 */
static void add_pcpu_page(struct super_block *sb, struct item_cache_info *cinf,
			  struct cached_page *pg)
{
	struct item_percpu_pages *pages = get_cpu_ptr(cinf->pcpu_pages);
	struct pcpu_page_ref *old;
	struct pcpu_page_ref *ref;

	ref = list_last_entry(&pages->list, struct pcpu_page_ref, head);
	if (ref->pg) {
		rbtree_erase(&ref->node, &pages->root);
		put_pg(sb, ref->pg);
	}
	ref->start = pg->start;
	ref->end = pg->end;
	ref->pg = pg;
	get_pg(pg);

	list_move(&ref->head, &pages->list);

	old = pcpu_page_rbtree_walk(&pages->root, &ref->end, ref);
	if (old) {
		scoutfs_inc_counter(sb, item_pcpu_add_replaced);
		rbtree_erase(&old->node, &pages->root);
		list_move_tail(&old->head, &pages->list);
		put_pg(sb, old->pg);
		old->pg = NULL;
	}

	put_cpu_ptr(cinf->pcpu_pages);
}

/*
 * If a page is removed from the page rbtree we clear its keys so that percpu
 * references won't use the page and will drop their reference.  Must be
 * called with a write page rwlock.
 */
static void invalidate_pcpu_page(struct cached_page *pg)
{
	scoutfs_key_set_zeros(&pg->start);
	scoutfs_key_set_zeros(&pg->end);
}

static void init_pcpu_pages(struct item_cache_info *cinf, int cpu)
{
	struct item_percpu_pages *pages = per_cpu_ptr(cinf->pcpu_pages, cpu);
	struct pcpu_page_ref *ref;
	int i;

	pages->root = RB_ROOT;
	INIT_LIST_HEAD(&pages->list);

	for (i = 0; i < ARRAY_SIZE(pages->refs); i++) {
		ref = &pages->refs[i];

		ref->pg = NULL;
		list_add_tail(&ref->head, &pages->list);
	}
}

static void drop_pcpu_pages(struct super_block *sb,
			    struct item_cache_info *cinf, int cpu)
{
	struct item_percpu_pages *pages = per_cpu_ptr(cinf->pcpu_pages, cpu);
	struct pcpu_page_ref *ref;
	int i;

	for (i = 0; i < ARRAY_SIZE(pages->refs); i++) {
		ref = &pages->refs[i];

		if (ref->pg)
			put_pg(sb, ref->pg);
		ref->pg = NULL;
	}

	pages->root = RB_ROOT;
}

/*
 * Set the keys of the destination pages of a split.  We try to find the
 * key which balances the space consumed by items in the resulting split
 * pages.  We move the split key to the right, setting the left end by
 * decrementing that key.  We bias towards advancing the left item first
 * so that we don't use it and possibly decrementing the starting page
 * key.  We can't have a page that covers a single key.  Callers of
 * split should have tried compacting which ensures that if we split we
 * must have multiple items, even if they all have the max value length.
 */
static void set_split_keys(struct cached_page *pg, struct cached_page *left,
			   struct cached_page *right)
{
	struct cached_item *left_item = first_item(&pg->item_root);
	struct cached_item *right_item = last_item(&pg->item_root);
	struct cached_item *mid;
	int left_tot = 0;
	int right_tot = 0;

	BUILD_BUG_ON((PAGE_SIZE / SCOUTFS_MAX_VAL_SIZE) < 4);
	BUG_ON(scoutfs_key_compare(&pg->start, &pg->end) > 0);
	BUG_ON(left_item == NULL);
	BUG_ON(right_item == NULL);
	BUG_ON(left_item == right_item);

	while (left_item && right_item && left_item != right_item) {
		if (left_tot <= right_tot) {
			left_tot += item_val_bytes(left_item->val_len);
			left_item = next_item(left_item);
		} else {
			right_tot += item_val_bytes(right_item->val_len);
			right_item = prev_item(right_item);
		}
	}

	mid = left_item ?: right_item;

	left->start = pg->start;
	left->end = mid->key;
	scoutfs_key_dec(&left->end);
	right->start = mid->key;
	right->end = pg->end;
}

/*
 * The caller found a page that didn't have room for the item they
 * wanted to allocate.  We allocate pages for the split and see if the
 * page still needs splitting once we've locked it.
 *
 * To modify page keys we need a write lock on the page rbtree, which
 * globally prevents reads from finding pages.  We want to minimize this
 * so we add empty pages with the split ranges to the rbtree and then
 * perform the item motion only with the page locks held.  This will
 * exclude any users of the items in the affected range.
 */
static int try_split_page(struct super_block *sb, struct item_cache_info *cinf,
			  struct scoutfs_key *key, int val_len)
{
	struct cached_page *right;
	struct cached_page *left;
	struct cached_page *pg;
	struct cached_item *item;
	struct rb_node **pnode;
	struct rb_node *par;
	int ret;

	left = alloc_pg(sb, 0);
	right = alloc_pg(sb, 0);
	if (!left || !right) {
		ret = -ENOMEM;
		goto out;
	}

	write_lock(&cinf->rwlock);

	pg = page_rbtree_walk(sb, &cinf->pg_root, key, key, NULL, NULL,
			      &par, &pnode);
	if (pg == NULL) {
		write_unlock(&cinf->rwlock);
		ret = 0;
		goto out;
	}

	write_lock(&pg->rwlock);

	if (!page_has_room(pg, val_len))
		compact_page_items(sb, pg, left);

	if (page_has_room(pg, val_len)) {
		write_unlock(&cinf->rwlock);
		write_unlock(&pg->rwlock);
		ret = 0;
		goto out;
	}

	/* special case adding an empty page when key is after the last item */
	item = last_item(&pg->item_root);
	if (scoutfs_key_compare(key, &item->key) > 0) {
		right->start = *key;
		right->end = pg->end;
		pg->end = *key;
		scoutfs_key_dec(&pg->end);

		write_trylock_will_succeed(&right->rwlock);
		rbtree_insert(&right->node, par, pnode, &cinf->pg_root);
		lru_accessed(sb, cinf, right);

		/* adding right first removes pg */
		add_pcpu_page(sb, cinf, right);
		add_pcpu_page(sb, cinf, pg);

		write_unlock(&cinf->rwlock);
		write_unlock(&pg->rwlock);
		write_unlock(&right->rwlock);
		right = NULL;
		ret = 0;
		goto out;
	}

	scoutfs_inc_counter(sb, item_page_split);

	/* pages are still private, tylock will succeed */
	write_trylock_will_succeed(&left->rwlock);
	write_trylock_will_succeed(&right->rwlock);

	set_split_keys(pg, left, right);

	rbtree_insert(&right->node, par, pnode, &cinf->pg_root);
	rbtree_replace_node(&pg->node, &left->node, &cinf->pg_root);
	lru_remove(sb, cinf, pg);

	write_unlock(&cinf->rwlock);

	/* move items while only holding page locks, visible once unlocked */
	move_page_items(sb, cinf, pg, left, &left->start, &right->start);
	lru_accessed(sb, cinf, left);
	add_pcpu_page(sb, cinf, left);
	write_unlock(&left->rwlock);
	left = NULL;

	move_page_items(sb, cinf, pg, right, &right->start, NULL);
	lru_accessed(sb, cinf, right);
	add_pcpu_page(sb, cinf, right);
	write_unlock(&right->rwlock);
	right = NULL;

	/* and drop the source page, it was replaced above */
	invalidate_pcpu_page(pg);
	write_unlock(&pg->rwlock);
	put_pg(sb, pg);

	ret = 0;
out:
	put_pg(sb, left);
	put_pg(sb, right);
	return ret;
}

/*
 * The caller has a write-only cluster lock and wants to populate the
 * cache so that it can insert an item without reading.  They found a
 * hole but unlocked so we check again under the lock after allocating.
 * We insert an empty page that covers the key and extends to either the
 * neighbours or the caller's (lock's) range.
 */
static int cache_empty_page(struct super_block *sb,
			    struct item_cache_info *cinf,
			    struct scoutfs_key *key, struct scoutfs_key *start,
			    struct scoutfs_key *end)
{
	struct cached_page *prev;
	struct cached_page *next;
	struct cached_page *pg;
	struct rb_node **pnode;
	struct rb_node *par;

	pg = alloc_pg(sb, 0);
	if (!pg)
		return -ENOMEM;

	write_lock(&cinf->rwlock);

	if (!page_rbtree_walk(sb, &cinf->pg_root, key, key, &prev, &next,
			      &par, &pnode)) {
		pg->start = *start;
		if (prev && scoutfs_key_compare(&prev->end, start) > 0) {
			pg->start = prev->end;
			scoutfs_key_inc(&pg->start);
		}

		pg->end = *end;
		if (next && scoutfs_key_compare(&next->start, end) < 0) {
			pg->end = next->start;
			scoutfs_key_dec(&pg->end);
		}

		rbtree_insert(&pg->node, par, pnode, &cinf->pg_root);
		lru_accessed(sb, cinf, pg);
		pg = NULL;
	}

	write_unlock(&cinf->rwlock);

	put_pg(sb, pg);

	return 0;
}

/*
 * Readers operate independently from dirty items and transactions.
 * They read a set of persistent items and insert them into the cache
 * when there aren't already pages whose key range contains the items.
 * This naturally prefers cached dirty items over stale read items.
 *
 * We have to deal with the case where dirty items are written and
 * invalidated while a read is in flight.   The reader won't have seen
 * the items that were dirty in their persistent roots as they started
 * reading.  By the time they insert their read pages the previously
 * dirty items have been reclaimed and are not in the cache.  The old
 * stale items will be inserted in their place, effectively corrupting
 * by having the dirty items disappear.
 *
 * We fix this by tracking the max seq of items in pages.  As readers
 * start they record the current transaction seq.  Invalidation skips
 * pages with a max seq greater than the first reader seq because the
 * items in the page have to stick around to prevent the readers stale
 * items from being inserted.
 *
 * This naturally only affects a small set of pages with items that were
 * written relatively recently.  If we're in memory pressure then we
 * probably have a lot of pages and they'll naturally have items that
 * were visible to any raders.  We don't bother with the complicated and
 * expensive further refinement of tracking the ranges that are being
 * read and comparing those with pages to invalidate.
 */
struct active_reader {
	struct list_head head;
	u64 seq;
};

#define INIT_ACTIVE_READER(rdr) \
	struct active_reader rdr = { .head = LIST_HEAD_INIT(rdr.head) }

static void add_active_reader(struct super_block *sb, struct active_reader *active)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);

	BUG_ON(!list_empty(&active->head));

	active->seq = scoutfs_trans_sample_seq(sb);

	spin_lock(&cinf->active_lock);
	list_add_tail(&active->head, &cinf->active_list);
	spin_unlock(&cinf->active_lock);
}

static u64 first_active_reader_seq(struct item_cache_info *cinf)
{
	struct active_reader *active;
	u64 first;

	/* only the calling task adds or deletes this active */
	spin_lock(&cinf->active_lock);
	active = list_first_entry_or_null(&cinf->active_list, struct active_reader, head);
	first = active ? active->seq : U64_MAX;
	spin_unlock(&cinf->active_lock);

	return first;
}

static void del_active_reader(struct item_cache_info *cinf, struct active_reader *active)
{
	/* only the calling task adds or deletes this active */
	if (!list_empty(&active->head)) {
		spin_lock(&cinf->active_lock);
		list_del_init(&active->head);
		spin_unlock(&cinf->active_lock);
	}
}

/*
 * Add a newly read item to the pages that we're assembling for
 * insertion into the cache.   These pages are private, they only exist
 * on our root and aren't in dirty or lru lists.
 *
 * We need to store deletion items here as we read items from all the
 * btrees so that they can override older items.  The deletion items
 * will be deleted before we insert the pages into the cache.  We don't
 * insert old versions of items into the tree here so that the trees
 * don't have to compare seqs.
 */
static int read_page_item(struct super_block *sb, struct scoutfs_key *key, u64 seq, u8 flags,
			  void *val, int val_len, int fic, void *arg)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const bool deletion = !!(flags & SCOUTFS_ITEM_FLAG_DELETION);
	struct rb_root *root = arg;
	struct cached_page *right = NULL;
	struct cached_page *left = NULL;
	struct cached_page *pg;
	struct cached_item *found;
	struct cached_item *item;
	struct rb_node *p_par;
	struct rb_node *par;
	struct rb_node **p_pnode;
	struct rb_node **pnode;

	pg = page_rbtree_walk(sb, root, key, key, NULL, NULL, &p_par, &p_pnode);
	found = item_rbtree_walk(&pg->item_root, key, NULL, &par, &pnode);
	if (found && (found->seq >= seq))
		return 0;

	if (!page_has_room(pg, val_len)) {
		left = alloc_pg(sb, 0);
		/* split needs multiple items, sparse may not have enough */
		if (!left)
			return -ENOMEM;

		compact_page_items(sb, pg, left);
		found = item_rbtree_walk(&pg->item_root, key, NULL, &par,
					 &pnode);
	}

	item = alloc_item(pg, key, seq, deletion, val, val_len);
	if (!item) {
		/* simpler split of private pages, no locking/dirty/lru */
		if (!left)
			left = alloc_pg(sb, 0);
		right = alloc_pg(sb, 0);
		if (!left || !right) {
			put_pg(sb, left);
			put_pg(sb, right);
			return -ENOMEM;
		}

		scoutfs_inc_counter(sb, item_read_pages_split);

		set_split_keys(pg, left, right);
		rbtree_insert(&right->node, p_par, p_pnode, root);
		rbtree_replace_node(&pg->node, &left->node, root);
		move_page_items(sb, cinf, pg, left,
				&left->start, &right->start);
		move_page_items(sb, cinf, pg, right, &right->start, NULL);
		put_pg(sb, pg);

		pg = scoutfs_key_compare(key, &left->end) <= 0 ? left : right;
		item = alloc_item(pg, key, seq, deletion, val, val_len);
		found = item_rbtree_walk(&pg->item_root, key, NULL, &par,
					 &pnode);

		left = NULL;
		right = NULL;
	}

	/* if deleted a deletion item will be required */
	item->persistent = 1;

	rbtree_insert(&item->node, par, pnode, &pg->item_root);
	if (found)
		erase_item(pg, found);

	put_pg(sb, left);
	put_pg(sb, right);
	return 0;
}

/*
 * The caller couldn't find a page that contains the key we're looking
 * for.  We combine a block's worth of items around the key in all the
 * forest btrees and store them in pages.  After filtering out deletions
 * and duplicates, we insert any resulting pages which don't overlap
 * with existing cached pages.
 *
 * We only insert uncached regions because this is called with cluster
 * locks held, but without locking the cache.  The regions we read can
 * be stale with respect to the current cache, which can be read and
 * dirtied by other cluster lock holders on our node, but the cluster
 * locks protect the stable items we read.  Invalidation is careful not
 * to drop pages that have items that we couldn't see because they were
 * dirty when we started reading.
 *
 * The forest item reader is reading stable trees that could be
 * overwritten.  It can return -ESTALE which we return to the caller who
 * will retry the operation and work with a new set of more recent
 * btrees.
 */
static int read_pages(struct super_block *sb, struct item_cache_info *cinf,
		      struct scoutfs_key *key, struct scoutfs_lock *lock)
{
	struct rb_root root = RB_ROOT;
	INIT_ACTIVE_READER(active);
	struct cached_page *right = NULL;
	struct cached_page *pg;
	struct cached_page *rd;
	struct cached_item *item;
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct scoutfs_key inf;
	struct scoutfs_key edge;
	struct rb_node **pnode;
	struct rb_node *par;
	struct rb_node *pg_tmp;
	struct rb_node *item_tmp;
	int pgi;
	int ret;

	/* start with an empty page that covers the whole lock */
	pg = alloc_pg(sb, 0);
	if (!pg) {
		ret = -ENOMEM;
		goto out;
	}
	pg->start = lock->start;
	pg->end = lock->end;
	rbtree_insert(&pg->node, NULL, &root.rb_node, &root);

	/* set active reader seq before reading persistent roots */
	add_active_reader(sb, &active);

	start = lock->start;
	end = lock->end;
	ret = scoutfs_forest_read_items(sb, key, &lock->start, &start, &end, read_page_item, &root);
	if (ret < 0)
		goto out;

	/* clean up our read items and pages before locking */
	for_each_page_safe(&root, pg, pg_tmp) {

		/* trim any items we read outside the read range */
		scoutfs_key_set_zeros(&inf);
		edge = start;
		scoutfs_key_dec(&edge);
		pgi = trim_page_intersection(sb, cinf, pg, NULL, &inf, &edge);
		if (pgi != PGI_INSIDE) {
			scoutfs_key_set_ones(&inf);
			edge = end;
			scoutfs_key_inc(&edge);
			pgi = trim_page_intersection(sb, cinf, pg, NULL, &edge,
						     &inf);
		}
		if (pgi == PGI_INSIDE) {
			rbtree_erase(&pg->node, &root);
			put_pg(sb, pg);
			continue;
		}

		/* drop deletion items, we don't need them in the cache */
		for_each_item_safe(&pg->item_root, item, item_tmp) {
			if (item->deletion)
				erase_item(pg, item);
		}
	}

retry:
	write_lock(&cinf->rwlock);

	while ((rd = first_page(&root))) {

		pg = page_rbtree_walk(sb, &cinf->pg_root, &rd->start, &rd->end,
				      NULL, NULL, &par, &pnode);
		if (!pg) {
			/* insert read pages that don't intersect */
			rbtree_erase(&rd->node, &root);
			rbtree_insert(&rd->node, par, pnode, &cinf->pg_root);
			lru_accessed(sb, cinf, rd);
			trace_scoutfs_item_read_page(sb, key, &rd->start,
						     &rd->end);
			continue;
		}

		pgi = trim_page_intersection(sb, cinf, rd, right, &pg->start,
					     &pg->end);
		if (pgi == PGI_INSIDE) {
			rbtree_erase(&rd->node, &root);
			put_pg(sb, rd);

		} else if (pgi == PGI_BISECT_NEEDED) {
			write_unlock(&cinf->rwlock);
			right = alloc_pg(sb, 0);
			if (!right) {
				ret = -ENOMEM;
				goto out;
			}
			goto retry;

		} else if (pgi == PGI_BISECT) {
			page_rbtree_walk(sb, &root, &right->start, &right->end,
					 NULL, NULL, &par, &pnode);
			rbtree_insert(&right->node, par, pnode, &root);
			right = NULL;
		}
	}

	write_unlock(&cinf->rwlock);

	ret = 0;
out:
	del_active_reader(cinf, &active);

	/* free any pages we left dangling on error */
	for_each_page_safe(&root, rd, pg_tmp) {
		rbtree_erase(&rd->node, &root);
		put_pg(sb, rd);
	}

	put_pg(sb, right);

	return ret;
}

/*
 * Get a locked cached page for the caller to work with.  This populates
 * the cache on misses and can ensure that the locked page has enough
 * room for an item allocation for the caller.  Unfortunately, sparse
 * doesn't seem to deal very well with the pattern of conditional lock
 * acquisition.  Callers manually add __acquire.
 */
static int get_cached_page(struct super_block *sb,
			   struct item_cache_info *cinf,
			   struct scoutfs_lock *lock, struct scoutfs_key *key,
			   bool write, bool alloc, int val_len,
			   struct cached_page **pg_ret)
{
	struct cached_page *pg = NULL;
	struct rb_node **pnode;
	struct rb_node *par;
	int ret;

	if (WARN_ON_ONCE(alloc && !write))
		return -EINVAL;

	pg = get_pcpu_page(sb, cinf, key, write);
	if (pg) {
		__acquire(pg->rwlock);
		if (!alloc || page_has_room(pg, val_len))
			goto found;

		if (write)
			write_unlock(&pg->rwlock);
		else
			read_unlock(&pg->rwlock);
		pg = NULL;
	}

retry:
	read_lock(&cinf->rwlock);

	pg = page_rbtree_walk(sb, &cinf->pg_root, key, key, NULL, NULL,
			      &par, &pnode);
	if (pg == NULL) {
		read_unlock(&cinf->rwlock);
		if (lock->mode == SCOUTFS_LOCK_WRITE_ONLY)
			ret = cache_empty_page(sb, cinf, key, &lock->start,
					       &lock->end);
		else
			ret = read_pages(sb, cinf, key, lock);
		if (ret < 0 && ret != -ESTALE)
			goto out;
		goto retry;
	}

	if (write)
		write_lock(&pg->rwlock);
	else
		read_lock(&pg->rwlock);

	if (alloc && !page_has_room(pg, val_len)) {
		read_unlock(&cinf->rwlock);
		if (write)
			write_unlock(&pg->rwlock);
		else
			read_unlock(&pg->rwlock);

		ret = try_split_page(sb, cinf, key, val_len);
		if (ret < 0)
			goto out;
		goto retry;
	}

	read_unlock(&cinf->rwlock);

	add_pcpu_page(sb, cinf, pg);
found:
	__release(pg_rwlock);
	lru_accessed(sb, cinf, pg);
	ret = 0;
out:
	if (ret < 0)
		*pg_ret = NULL;
	else
		*pg_ret = pg;
	return ret;
}

static int lock_safe(struct super_block *sb, struct scoutfs_lock *lock, struct scoutfs_key *key,
		     int mode)
{
	bool prot = scoutfs_lock_protected(lock, key, mode);

	if (!prot) {
		static bool once = false;
		if (!once) {
			scoutfs_err(sb, "lock (start "SK_FMT" end "SK_FMT" mode 0x%x) does not protect operation (key "SK_FMT" mode 0x%x)",
				    SK_ARG(&lock->start), SK_ARG(&lock->end), lock->mode,
				    SK_ARG(key), mode);
			dump_stack();
			once = true;
		}
		return -EINVAL;
	}

	return 0;
}

static int optional_lock_mode_match(struct scoutfs_lock *lock, int mode)
{
	if (WARN_ON_ONCE(lock && lock->mode != mode))
		return -EINVAL;
	else
		return 0;
}

/*
 * Copy the cached item's value into the caller's value.  The number of
 * bytes copied is returned.  A null val returns 0.
 */
static int copy_val(void *dst, int dst_len, void *src, int src_len)
{
	int ret;

	BUG_ON(dst_len < 0 || src_len < 0);

	ret = min(dst_len, src_len);
	if (ret)
		memcpy(dst, src, ret);
	return ret;
}

/*
 * Find an item with the given key and copy its value to the caller.
 * The amount of bytes copied is returned which can be 0 or truncated if
 * the caller's buffer isn't big enough.
 */
static int item_lookup(struct super_block *sb, struct scoutfs_key *key,
		       void *val, int val_len, int len_limit, struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct cached_item *item;
	struct cached_page *pg;
	int ret;

	scoutfs_inc_counter(sb, item_lookup);

	if ((ret = lock_safe(sb, lock, key, SCOUTFS_LOCK_READ)))
		goto out;

	ret = get_cached_page(sb, cinf, lock, key, false, false, 0, &pg);
	if (ret < 0)
		goto out;
	__acquire(&pg->rwlock);

	item = item_rbtree_walk(&pg->item_root, key, NULL, NULL, NULL);
	if (!item || item->deletion)
		ret = -ENOENT;
	else if (len_limit > 0 && item->val_len > len_limit)
		ret = -EIO;
	else
		ret = copy_val(val, val_len, item->val, item->val_len);

	read_unlock(&pg->rwlock);
out:
	return ret;
}

int scoutfs_item_lookup(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock)
{
	return item_lookup(sb, key, val, val_len, 0, lock);
}

/*
 * Copy an item's value into the caller's buffer.  If the item's value
 * is larger than the caller's buffer then -EIO is returned.  If the
 * item is smaller then the bytes from the end of the copied value to
 * the end of the buffer are zeroed.  The number of value bytes copied
 * is returned, and 0 can be returned for an item with no value.
 */
int scoutfs_item_lookup_smaller_zero(struct super_block *sb, struct scoutfs_key *key,
				     void *val, int val_len, struct scoutfs_lock *lock)
{
	int ret;

	ret = item_lookup(sb, key, val, val_len, val_len, lock);
	if (ret >= 0 && ret < val_len)
		memset(val + ret, 0, val_len - ret);

	return ret;
}

int scoutfs_item_lookup_exact(struct super_block *sb, struct scoutfs_key *key,
			      void *val, int val_len,
			      struct scoutfs_lock *lock)
{
	int ret;

	ret = item_lookup(sb, key, val, val_len, 0, lock);
	if (ret == val_len)
		ret = 0;
	else if (ret >= 0)
		ret = -EIO;

	return ret;
}

/*
 * Return the next item starting with the given key and returning the
 * last key at most.
 *
 * The range covered by the lock also limits the last item that can be
 * returned.  -ENOENT can be returned when there are no next items
 * covered by the lock but there are still items before the last key
 * outside of the lock.  The caller needs to know to reacquire the next
 * lock to continue iteration.
 *
 * -ENOENT is returned if there are no items between the given and last
 * keys inside the range covered by the lock.
 *
 * The next item's key is copied to the caller's key.
 *
 * The next item's value is copied into the callers value.  The number
 * of value bytes copied is returned.  The copied value can be truncated
 * by the caller's value buffer length.
 */
int scoutfs_item_next(struct super_block *sb, struct scoutfs_key *key,
		      struct scoutfs_key *last, void *val, int val_len,
		      struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct cached_item *item;
	struct cached_item *next;
	struct cached_page *pg = NULL;
	struct scoutfs_key pos;
	int ret;

	scoutfs_inc_counter(sb, item_next);

	/* use the end key as the last key if it's closer */
	if (scoutfs_key_compare(&lock->end, last) < 0)
		last = &lock->end;

	if (scoutfs_key_compare(key, last) > 0) {
		ret = -ENOENT;
		goto out;
	}

	if ((ret = lock_safe(sb, lock, key, SCOUTFS_LOCK_READ)))
		goto out;

	pos = *key;

	for (;;) {
		ret = get_cached_page(sb, cinf, lock, &pos, false, false, 0,
				      &pg);
		if (ret < 0)
			goto out;
		__acquire(&pg->rwlock);

		item = item_rbtree_walk(&pg->item_root, &pos, &next,
					NULL, NULL) ?: next;
		while (item && scoutfs_key_compare(&item->key, last) <= 0) {
			if (!item->deletion) {
				*key = item->key;
				ret = copy_val(val, val_len, item->val,
					       item->val_len);
				goto unlock;
			}

			item = next_item(item);
		}

		if (scoutfs_key_compare(&pg->end, last) >= 0) {
			ret = -ENOENT;
			goto unlock;
		}

		pos = pg->end;
		read_unlock(&pg->rwlock);

		scoutfs_key_inc(&pos);
	}

unlock:
	read_unlock(&pg->rwlock);
out:

	return ret;
}

/*
 * An item's seq is greater of the client transaction's seq and the
 * lock's write_seq.  This ensures that multiple commits in one lock
 * grant will have increasing seqs, and new locks in open commits will
 * also increase the seqs.  It lets us limit the inputs of item merging
 * to the last stable seq and ensure that all the items in open
 * transactions and granted locks will have greater seqs.
 *
 * This is a little awkward for WRITE_ONLY locks which can have much
 * older versions than the version of locked primary data that they're
 * operating on behalf of.  Callers can optionally provide that primary
 * lock to get the version from.   This ensures that items created under
 * WRITE_ONLY locks can not have versions less than their primary data.
 */
static u64 item_seq(struct super_block *sb, struct scoutfs_lock *lock,
		    struct scoutfs_lock *primary)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	return max3(sbi->trans_seq, lock->write_seq, primary ? primary->write_seq : 0);
}

/*
 * Mark the item dirty.  Dirtying while holding a transaction pins the
 * page holding the item and guarantees that the item can be deleted or
 * updated (without increasing the value length) during the transaction
 * without errors.
 */
int scoutfs_item_dirty(struct super_block *sb, struct scoutfs_key *key,
		       struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct cached_item *item;
	struct cached_page *pg;
	int ret;

	scoutfs_inc_counter(sb, item_dirty);

	if ((ret = lock_safe(sb, lock, key, SCOUTFS_LOCK_WRITE)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	ret = get_cached_page(sb, cinf, lock, key, true, false, 0, &pg);
	if (ret < 0)
		goto out;
	__acquire(pg->rwlock);

	item = item_rbtree_walk(&pg->item_root, key, NULL, NULL, NULL);
	if (!item || item->deletion) {
		ret = -ENOENT;
	} else {
		item->seq = item_seq(sb, lock, NULL);
		mark_item_dirty(sb, cinf, pg, NULL, item);
		ret = 0;
	}

	write_unlock(&pg->rwlock);
out:
	return ret;
}

/*
 * Create a new cached item with the given value.  -EEXIST is returned
 * if the item already exists.  Forcing creates the item without knowldge
 * of any existing items.. it doesn't read and can't return -EEXIST.
 */
static int item_create(struct super_block *sb, struct scoutfs_key *key,
		       void *val, int val_len, struct scoutfs_lock *lock,
		       struct scoutfs_lock *primary, int mode, bool force)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const u64 seq = item_seq(sb, lock, primary);
	struct cached_item *found;
	struct cached_item *item;
	struct cached_page *pg;
	struct rb_node **pnode;
	struct rb_node *par;
	int ret;

	scoutfs_inc_counter(sb, item_create);

	if ((ret = lock_safe(sb, lock, key, mode)) ||
	    (ret = optional_lock_mode_match(primary, SCOUTFS_LOCK_WRITE)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	ret = get_cached_page(sb, cinf, lock, key, true, true, val_len, &pg);
	if (ret < 0)
		goto out;
	__acquire(pg->rwlock);

	found = item_rbtree_walk(&pg->item_root, key, NULL, &par, &pnode);
	if (!force && found && !found->deletion) {
		ret = -EEXIST;
		goto unlock;
	}

	item = alloc_item(pg, key, seq, false, val, val_len);
	rbtree_insert(&item->node, par, pnode, &pg->item_root);
	mark_item_dirty(sb, cinf, pg, NULL, item);

	if (found) {
		item->persistent = found->persistent;
		clear_item_dirty(sb, cinf, pg, found);
		erase_item(pg, found);
	}

	if (force)
		item->persistent = 1;

	ret = 0;
unlock:
	write_unlock(&pg->rwlock);
out:
	return ret;
}

int scoutfs_item_create(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock)
{
	return item_create(sb, key, val, val_len, lock, NULL,
			   SCOUTFS_LOCK_WRITE, false);
}

int scoutfs_item_create_force(struct super_block *sb, struct scoutfs_key *key,
			      void *val, int val_len,
			      struct scoutfs_lock *lock, struct scoutfs_lock *primary)
{
	return item_create(sb, key, val, val_len, lock, primary,
			   SCOUTFS_LOCK_WRITE_ONLY, true);
}

/*
 * Update an item with a new value.  If the new value is smaller and the
 * item is dirty then this is guaranteed to succeed.  It can fail if the
 * item doesn't exist or it gets errors reading or allocating new pages
 * for a larger value.
 */
int scoutfs_item_update(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const u64 seq = item_seq(sb, lock, NULL);
	struct cached_item *item;
	struct cached_item *found;
	struct cached_page *pg;
	struct rb_node **pnode;
	struct rb_node *par;
	int ret;

	scoutfs_inc_counter(sb, item_update);

	if ((ret = lock_safe(sb, lock, key, SCOUTFS_LOCK_WRITE)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	ret = get_cached_page(sb, cinf, lock, key, true, true, val_len, &pg);
	if (ret < 0)
		goto out;
	__acquire(pg->rwlock);

	found = item_rbtree_walk(&pg->item_root, key, NULL, &par, &pnode);
	if (!found || found->deletion) {
		ret = -ENOENT;
		goto unlock;
	}

	if (val_len <= found->val_len) {
		if (val_len)
			memcpy(found->val, val, val_len);
		if (val_len < found->val_len)
			pg->erased_bytes += item_val_bytes(found->val_len) -
					    item_val_bytes(val_len);
		found->val_len = val_len;
		found->seq = seq;
		mark_item_dirty(sb, cinf, pg, NULL, found);
	} else {
		item = alloc_item(pg, key, seq, false, val, val_len);
		item->persistent = found->persistent;
		rbtree_insert(&item->node, par, pnode, &pg->item_root);
		mark_item_dirty(sb, cinf, pg, NULL, item);

		clear_item_dirty(sb, cinf, pg, found);
		erase_item(pg, found);
	}

	ret = 0;
unlock:
	write_unlock(&pg->rwlock);
out:
	return ret;
}

/*
 * Add a delta item.  Delta items are an incremental change relative to
 * the current persistent delta items.  We never have to read the
 * current items so the caller always writes with write only locks.  If
 * combining the current delta item and the caller's item results in a
 * null we can just drop it, we don't have to emit a deletion item.
 *
 * Delta items don't have to worry about creating items with old
 * versions under write_only locks.  The versions don't impact how we
 * merge two items.
 */
int scoutfs_item_delta(struct super_block *sb, struct scoutfs_key *key,
		       void *val, int val_len, struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const u64 seq = item_seq(sb, lock, NULL);
	struct cached_item *item;
	struct cached_page *pg;
	struct rb_node **pnode;
	struct rb_node *par;
	int ret;

	scoutfs_inc_counter(sb, item_delta);

	if ((ret = lock_safe(sb, lock, key, SCOUTFS_LOCK_WRITE_ONLY)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	ret = get_cached_page(sb, cinf, lock, key, true, true, val_len, &pg);
	if (ret < 0)
		goto out;
	__acquire(pg->rwlock);

	item = item_rbtree_walk(&pg->item_root, key, NULL, &par, &pnode);
	if (item) {
		if (!item->delta) {
			ret = -EIO;
			goto unlock;
		}

		ret = scoutfs_forest_combine_deltas(key, item->val, item->val_len, val, val_len);
		if (ret <= 0) {
			if (ret == 0)
				ret = -EIO;
			goto unlock;
		}

		if (ret == SCOUTFS_DELTA_COMBINED) {
			item->seq = seq;
			mark_item_dirty(sb, cinf, pg, NULL, item);
		} else if (ret == SCOUTFS_DELTA_COMBINED_NULL) {
			clear_item_dirty(sb, cinf, pg, item);
			erase_item(pg, item);
		} else {
			ret = -EIO;
			goto unlock;
		}
		ret = 0;
	} else {
		item = alloc_item(pg, key, seq, false, val, val_len);
		rbtree_insert(&item->node, par, pnode, &pg->item_root);
		mark_item_dirty(sb, cinf, pg, NULL, item);
		item->delta = 1;
		ret = 0;
	}

unlock:
	write_unlock(&pg->rwlock);
out:
	return ret;
}

/*
 * Delete an item from the cache.  We can leave behind a dirty deletion
 * item if there is a persistent item that needs to be overwritten.
 * This can't fail if the caller knows that the item exists and it has
 * been dirtied during the transaction it holds.  If we're forcing then
 * we're not reading the old state of the item and have to create a
 * deletion item if there isn't one already cached.
 */
static int item_delete(struct super_block *sb, struct scoutfs_key *key,
		       struct scoutfs_lock *lock, struct scoutfs_lock *primary,
		       int mode, bool force)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const u64 seq = item_seq(sb, lock, primary);
	struct cached_item *item;
	struct cached_page *pg;
	struct rb_node **pnode;
	struct rb_node *par;
	int ret;

	scoutfs_inc_counter(sb, item_delete);

	if ((ret = lock_safe(sb, lock, key, mode)) ||
	    (ret = optional_lock_mode_match(primary, SCOUTFS_LOCK_WRITE)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	ret = get_cached_page(sb, cinf, lock, key, true, force, 0, &pg);
	if (ret < 0)
		goto out;
	__acquire(pg->rwlock);

	item = item_rbtree_walk(&pg->item_root, key, NULL, &par, &pnode);
	if (!force && (!item || item->deletion)) {
		ret = -ENOENT;
		goto unlock;
	}

	if (!item) {
		item = alloc_item(pg, key, seq, false, NULL, 0);
		rbtree_insert(&item->node, par, pnode, &pg->item_root);
	}

	if (force)
		item->persistent = 1;

	if (!item->persistent) {
		/* can just forget items that aren't yet persistent */
		clear_item_dirty(sb, cinf, pg, item);
		erase_item(pg, item);
	} else {
		/* must emit deletion to clobber old persistent item */
		item->seq = seq;
		item->deletion = 1;
		pg->erased_bytes += item_val_bytes(item->val_len) -
				    item_val_bytes(0);
		item->val_len = 0;
		mark_item_dirty(sb, cinf, pg, NULL, item);
	}

	ret = 0;
unlock:
	write_unlock(&pg->rwlock);
out:
	return ret;
}

int scoutfs_item_delete(struct super_block *sb, struct scoutfs_key *key,
			struct scoutfs_lock *lock)
{
	return item_delete(sb, key, lock, NULL, SCOUTFS_LOCK_WRITE, false);
}

int scoutfs_item_delete_force(struct super_block *sb, struct scoutfs_key *key,
			      struct scoutfs_lock *lock, struct scoutfs_lock *primary)
{
	return item_delete(sb, key, lock, primary, SCOUTFS_LOCK_WRITE_ONLY, true);
}

u64 scoutfs_item_dirty_pages(struct super_block *sb)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);

	return (u64)atomic_read(&cinf->dirty_pages);
}

static int cmp_pg_start(void *priv, KC_LIST_CMP_CONST struct list_head *A, KC_LIST_CMP_CONST struct list_head *B)
{
	KC_LIST_CMP_CONST struct cached_page *a = list_entry(A, KC_LIST_CMP_CONST struct cached_page, dirty_head);
	KC_LIST_CMP_CONST struct cached_page *b = list_entry(B, KC_LIST_CMP_CONST struct cached_page, dirty_head);

	return scoutfs_key_compare(&a->start, &b->start);
}

static int cmp_item_key(void *priv, KC_LIST_CMP_CONST struct list_head *A, KC_LIST_CMP_CONST struct list_head *B)
{
	KC_LIST_CMP_CONST struct cached_item *a = list_entry(A, KC_LIST_CMP_CONST struct cached_item, dirty_head);
	KC_LIST_CMP_CONST struct cached_item *b = list_entry(B, KC_LIST_CMP_CONST struct cached_item, dirty_head);

	return scoutfs_key_compare(&a->key, &b->key);
}

/*
 * Write all the dirty items into dirty blocks in the forest of btrees.
 * If this succeeds then the dirty blocks can be submitted to commit
 * their transaction.  If this returns an error then the dirty blocks
 * could have a partial set of the dirty items and result in an
 * inconsistent state.  The blocks should only be committed once all the
 * dirty items have been written.
 *
 * This is called during transaction commit which prevents item writers
 * from entering a transaction and dirtying items.  The set of dirty
 * items will be constant.
 *
 * But the pages that contain the dirty items can be changing.  A
 * neighbouring read lock can be invalidated and require bisecting a
 * page, moving dirty items to a new page.  That new page will be put
 * after the original page on the dirty list.  This will be done under
 * the page rwlock and the global dirty_lock.
 *
 * We first sort the pages by their keys, then lock each page and copy
 * its items into a private allocated singly-linked list of the items to
 * dirty.  Once we have that we can hand it off to the forest of btrees
 * to write into items without causing any contention with other page
 * users.
 */
int scoutfs_item_write_dirty(struct super_block *sb)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct scoutfs_btree_item_list *first;
	struct scoutfs_btree_item_list **prev;
	struct scoutfs_btree_item_list *lst;
	struct cached_item *item;
	struct cached_page *pg;
	struct page *second = NULL;
	struct page *page;
	LIST_HEAD(pages);
	LIST_HEAD(pos);
	u64 max_seq = 0;
	int bytes;
	int off;
	int ret;

	if (atomic_read(&cinf->dirty_pages) == 0)
		return 0;

	scoutfs_inc_counter(sb, item_write_dirty);

	/* sort page dirty list by keys */
	read_lock(&cinf->rwlock);
	spin_lock(&cinf->dirty_lock);

	/* sort cached pages by key, add our pos head */
	list_sort(NULL, &cinf->dirty_list, cmp_pg_start);
	list_add(&pos, &cinf->dirty_list);

	read_unlock(&cinf->rwlock);
	spin_unlock(&cinf->dirty_lock);

	page = alloc_page(GFP_NOFS);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	list_add(&page->lru, &pages);

	first = NULL;
	prev = &first;
	off = 0;

	while (!list_empty_careful(&pos)) {
		if (!second) {
			second = alloc_page(GFP_NOFS);
			if (!second) {
				ret = -ENOMEM;
				goto out;
			}
			list_add(&second->lru, &pages);
		}

		/* read lock next sorted page, we're only dirty_list user */

		spin_lock(&cinf->dirty_lock);
		pg = list_entry(pos.next, struct cached_page, dirty_head);
		if (!read_trylock(&pg->rwlock)) {
			spin_unlock(&cinf->dirty_lock);
			cpu_relax();
			continue;
		}
		spin_unlock(&cinf->dirty_lock);

		list_sort(NULL, &pg->dirty_list, cmp_item_key);

		list_for_each_entry(item, &pg->dirty_list, dirty_head) {
			bytes = offsetof(struct scoutfs_btree_item_list,
					 val[item->val_len]);
			max_seq = max(max_seq, item->seq);

			if (off + bytes > PAGE_SIZE) {
				page = second;
				second = NULL;
				off = 0;
			}

			lst = (void *)page_address(page) + off;
			off += round_up(bytes, CACHED_ITEM_ALIGN);

			lst->next = NULL;
			*prev = lst;
			prev = &lst->next;

			lst->key = item->key;
			lst->seq = item->seq;
			lst->flags = item->deletion ? SCOUTFS_ITEM_FLAG_DELETION : 0;
			lst->val_len = item->val_len;
			memcpy(lst->val, item->val, item->val_len);
		}

		spin_lock(&cinf->dirty_lock);
		if (pg->dirty_head.next == &cinf->dirty_list)
			list_del_init(&pos);
		else
			list_move(&pos, &pg->dirty_head);
		spin_unlock(&cinf->dirty_lock);

		read_unlock(&pg->rwlock);
	}

	/* store max item seq in forest's log_trees */
	scoutfs_forest_set_max_seq(sb, max_seq);

	/* write all the dirty items into log btree blocks */
	ret = scoutfs_forest_insert_list(sb, first);
out:
	list_for_each_entry_safe(page, second, &pages, lru) {
		list_del_init(&page->lru);
		__free_page(page);
	}

	return ret;
}

/*
 * The caller has successfully committed all the dirty btree blocks that
 * contained the currently dirty items.  Clear all the dirty items and
 * pages.
 */
int scoutfs_item_write_done(struct super_block *sb)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct cached_item *item;
	struct cached_item *tmp;
	struct cached_page *pg;

retry:
	spin_lock(&cinf->dirty_lock);

	while ((pg = list_first_entry_or_null(&cinf->dirty_list,
					      struct cached_page,
					      dirty_head))) {

		if (!write_trylock(&pg->rwlock)) {
			spin_unlock(&cinf->dirty_lock);
			cpu_relax();
			goto retry;
		}

		spin_unlock(&cinf->dirty_lock);

		list_for_each_entry_safe(item, tmp, &pg->dirty_list,
					 dirty_head) {
			clear_item_dirty(sb, cinf, pg, item);

			if (item->delta)
				scoutfs_inc_counter(sb, item_delta_written);

			/* free deletion items */
			if (item->deletion || item->delta)
				erase_item(pg, item);
			else
				item->persistent = 1;
		}

		write_unlock(&pg->rwlock);

		spin_lock(&cinf->dirty_lock);
	}

	spin_unlock(&cinf->dirty_lock);

	return 0;
}

/*
 * Return true if the item cache covers the given range and set *dirty
 * to true if any items in the cached range are dirty.
 *
 * This is relatively rarely called as locks are granted to make sure
 * that we *don't* have existing cache covered by the lock which then
 * must be inconsistent.  Finding pages is the critical error case,
 * under correct operation this will be a read locked walk of the page
 * rbtree that doesn't find anything.
 */
bool scoutfs_item_range_cached(struct super_block *sb,
			       struct scoutfs_key *start,
			       struct scoutfs_key *end, bool *dirty)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct cached_item *item;
	struct cached_page *pg;
	struct scoutfs_key pos;
	bool cached;

	cached = false;
	*dirty = false;
	pos = *start;

	read_lock(&cinf->rwlock);

	while (!(*dirty) && scoutfs_key_compare(&pos, end) <= 0 &&
	       (pg = page_rbtree_walk(sb, &cinf->pg_root, &pos, end, NULL, NULL,
				      NULL, NULL))) {
		cached = true;

		read_lock(&pg->rwlock);
		read_unlock(&cinf->rwlock);

		/* the dirty list isn't sorted :/ */
		list_for_each_entry(item, &pg->dirty_list, dirty_head) {
			if (!scoutfs_key_compare_ranges(&item->key, &item->key,
							start, end)) {
				*dirty = true;
				break;
			}
		}

		pos = pg->end;
		scoutfs_key_inc(&pos);

		read_unlock(&pg->rwlock);
		read_lock(&cinf->rwlock);
	}

	read_unlock(&cinf->rwlock);

	return cached;
}

/*
 * Remove the cached items in the given range.  We drop pages that are
 * fully inside the range and trim any pages that intersect it.  This is
 * being by locking for a lock that can't be used so there can't be item
 * calls within the range.  It can race with all our other page uses.
 */
void scoutfs_item_invalidate(struct super_block *sb, struct scoutfs_key *start,
			     struct scoutfs_key *end)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct cached_page *right = NULL;
	struct cached_page *pg;
	struct rb_node **pnode;
	struct rb_node *par;
	int pgi;

	scoutfs_inc_counter(sb, item_invalidate);

retry:
	write_lock(&cinf->rwlock);

	while ((pg = page_rbtree_walk(sb, &cinf->pg_root, start, end, NULL,
				      NULL, &par, &pnode))) {

		scoutfs_inc_counter(sb, item_invalidate_page);

		write_lock(&pg->rwlock);

		pgi = trim_page_intersection(sb, cinf, pg, right, start, end);
		trace_scoutfs_item_invalidate_page(sb, start, end,
						   &pg->start, &pg->end, pgi);
		BUG_ON(pgi == PGI_DISJOINT); /* walk wouldn't ret disjoint */

		if (pgi == PGI_INSIDE) {
			/* free entirely invalidated page */
			lru_remove(sb, cinf, pg);
			rbtree_erase(&pg->node, &cinf->pg_root);
			invalidate_pcpu_page(pg);
			write_unlock(&pg->rwlock);
			put_pg(sb, pg);
			continue;

		} else if (pgi == PGI_BISECT_NEEDED) {
			/* allocate so we can bisect a larger page */
			write_unlock(&cinf->rwlock);
			write_unlock(&pg->rwlock);
			right = alloc_pg(sb, __GFP_NOFAIL);
			goto retry;

		} else if (pgi == PGI_BISECT) {
			/* inv was entirely inside page, done after bisect */
			write_trylock_will_succeed(&right->rwlock);
			rbtree_insert(&right->node, par, pnode, &cinf->pg_root);
			lru_accessed(sb, cinf, right);
			write_unlock(&right->rwlock);
			write_unlock(&pg->rwlock);
			right = NULL;
			break;
		}

		/* OLAP trimmed edge, keep searching */
		write_unlock(&pg->rwlock);
	}

	write_unlock(&cinf->rwlock);

	put_pg(sb, right);
}

static unsigned long item_cache_count_objects(struct shrinker *shrink,
					      struct shrink_control *sc)
{
	struct item_cache_info *cinf = KC_SHRINKER_CONTAINER_OF(shrink, struct item_cache_info);
	struct super_block *sb = cinf->sb;

	scoutfs_inc_counter(sb, item_cache_count_objects);

	return shrinker_min_long(cinf->lru_pages);
}

/*
 * Shrink the size the item cache.  We're operating against the fast
 * path lock ordering and we skip pages if we can't acquire locks.  We
 * can run into dirty pages or pages with items that weren't visible to
 * the earliest active reader which must be skipped.
 */
static unsigned long item_cache_scan_objects(struct shrinker *shrink,
					     struct shrink_control *sc)
{
	struct item_cache_info *cinf = KC_SHRINKER_CONTAINER_OF(shrink, struct item_cache_info);
	struct super_block *sb = cinf->sb;
	struct cached_page *tmp;
	struct cached_page *pg;
	unsigned long freed = 0;
	u64 first_reader_seq;
	int nr = sc->nr_to_scan;

	scoutfs_inc_counter(sb, item_cache_scan_objects);

	/* can't invalidate pages with items that weren't visible to first reader */
	first_reader_seq = first_active_reader_seq(cinf);

	write_lock(&cinf->rwlock);
	spin_lock(&cinf->lru_lock);

	list_for_each_entry_safe(pg, tmp, &cinf->lru_list, lru_head) {

		if (first_reader_seq <= pg->max_seq) {
			scoutfs_inc_counter(sb, item_shrink_page_reader);
			continue;
		}

		if (!write_trylock(&pg->rwlock)) {
			scoutfs_inc_counter(sb, item_shrink_page_trylock);
			continue;
		}

		if (!list_empty(&pg->dirty_list)) {
			scoutfs_inc_counter(sb, item_shrink_page_dirty);
			write_unlock(&pg->rwlock);
			continue;
		}

		scoutfs_inc_counter(sb, item_shrink_page);

		__lru_remove(sb, cinf, pg);
		rbtree_erase(&pg->node, &cinf->pg_root);
		invalidate_pcpu_page(pg);
		write_unlock(&pg->rwlock);
		freed++;

		put_pg(sb, pg);

		if (--nr == 0)
			break;
	}

	write_unlock(&cinf->rwlock);
	spin_unlock(&cinf->lru_lock);

	return freed;
}

#ifdef KC_CPU_NOTIFIER
static int item_cpu_callback(struct notifier_block *nfb,
			     unsigned long action, void *hcpu)
{
	struct item_cache_info *cinf = container_of(nfb,
						    struct item_cache_info,
						    notifier);
	struct super_block *sb = cinf->sb;
	unsigned long cpu = (unsigned long)hcpu;

        if (action == CPU_DEAD)
		drop_pcpu_pages(sb, cinf, cpu);

	return NOTIFY_OK;
}
#endif

int scoutfs_item_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache_info *cinf;
	int cpu;

	cinf = kzalloc(sizeof(struct item_cache_info), GFP_KERNEL);
	if (!cinf)
		return -ENOMEM;

	cinf->sb = sb;
	rwlock_init(&cinf->rwlock);
	cinf->pg_root = RB_ROOT;
	spin_lock_init(&cinf->dirty_lock);
	INIT_LIST_HEAD(&cinf->dirty_list);
	atomic_set(&cinf->dirty_pages, 0);
	spin_lock_init(&cinf->lru_lock);
	INIT_LIST_HEAD(&cinf->lru_list);
	spin_lock_init(&cinf->active_lock);
	INIT_LIST_HEAD(&cinf->active_list);

	cinf->pcpu_pages = alloc_percpu(struct item_percpu_pages);
	if (!cinf->pcpu_pages)
		return -ENOMEM;

	for_each_possible_cpu(cpu)
		init_pcpu_pages(cinf, cpu);

	KC_INIT_SHRINKER_FUNCS(&cinf->shrinker, item_cache_count_objects,
			       item_cache_scan_objects);
	KC_REGISTER_SHRINKER(&cinf->shrinker);
#ifdef KC_CPU_NOTIFIER
        cinf->notifier.notifier_call = item_cpu_callback;
        register_hotcpu_notifier(&cinf->notifier);
#endif

	sbi->item_cache_info = cinf;
	return 0;
}

/*
 * There must be no more item callers at this point.
 */
void scoutfs_item_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct item_cache_info *cinf = sbi->item_cache_info;
	struct cached_page *tmp;
	struct cached_page *pg;
	int cpu;

	if (cinf) {
		BUG_ON(!list_empty(&cinf->active_list));

#ifdef KC_CPU_NOTIFIER
		unregister_hotcpu_notifier(&cinf->notifier);
#endif
		KC_UNREGISTER_SHRINKER(&cinf->shrinker);

		for_each_possible_cpu(cpu)
			drop_pcpu_pages(sb, cinf, cpu);
		free_percpu(cinf->pcpu_pages);

		rbtree_postorder_for_each_entry_safe(pg, tmp, &cinf->pg_root,
						     node) {
			RB_CLEAR_NODE(&pg->node);
			INIT_LIST_HEAD(&pg->lru_head);
			INIT_LIST_HEAD(&pg->dirty_list);
			INIT_LIST_HEAD(&pg->dirty_head);
			put_pg(sb, pg);
		}

		kfree(cinf);
		sbi->item_cache_info = NULL;
	}
}
