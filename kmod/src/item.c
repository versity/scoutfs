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
#include <linux/list_sort.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/mm.h>

#include "super.h"
#include "cwskip.h"
#include "item.h"
#include "forest.h"
#include "block.h"
#include "trans.h"
#include "cwskip.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * The item cache maintains a consistent view of items that are read
 * from and written to the forest of btrees under the protection of
 * cluster locks.
 *
 * The cache is built around a concurrent skip list of items.   Readers
 * are protected by per-item seqlocks and retry if their items are
 * modified while they're being referenced.  Writers use trylock to
 * acquire locks on adjacent pairs of items and retry if they encounter
 * contention.
 *
 * The item cache has to support negative caches of ranges of keys that
 * contain no items.   This is done by marking a node as having a "hole"
 * in the cache following its key.   Searches that hit keys in these
 * hole regions read items from btree blocks and insert the resulting
 * key range into the cache.   Searches that end after items without the
 * following hole marker know that the item doesn't exist and can act
 * accordingly, say by returning enoent.  Working with this space
 * between items is why the skip list interface is built around
 * returning the pair of items that surround a key.
 *
 * The cache is populated by reading items from the forest of btrees
 * into a private list.  The range of keys in the list that didn't exist
 * in the cache are inserted into the list, maintaining the negative
 * cached range around the read items.
 *
 * Dirty items are kept in per-cpu lists to reduce global contention,
 * loads where all cpus are only creating dirty items are common.  The
 * dirty items are only combined and sorted when it comes to to commit
 * them.
 *
 * The size of the cache is only limited by memory reclaim.  We try to
 * group items into coarse ages by how recently they were accessed.  We
 * don't precisely order items by access time to avoid contention.
 * Shrinking randomly walks all items looking for items that weren't
 * accessed recently.
 */

struct pcpu_age_counters {
	atomic64_t age_marked;
	atomic64_t total;
};

struct pcpu_dirty_list {
	struct list_head list;
	spinlock_t lock;
};

struct item_cache_info {
	/* almost always read, barely written */
	struct super_block *sb;
	struct pcpu_age_counters __percpu *pcpu_age;
	struct pcpu_dirty_list __percpu *pcpu_dirty;
	struct shrinker shrinker;
	struct notifier_block notifier;

	/* read for every op, rarely written by tall or early nodes */
	____cacheline_aligned_in_smp struct scoutfs_cwskip_root item_root;

	/* often read, rarely written as ages advance */
	atomic64_t current_age;
	atomic64_t age_marked;
	atomic64_t age_total;

	/* written by every dirty item change */
	____cacheline_aligned_in_smp atomic64_t dirty_bytes;

	/* written by readers, read by shrink */
	____cacheline_aligned_in_smp spinlock_t active_lock;
	struct list_head active_list;
};

#define DECLARE_ITEM_CACHE_INFO(sb, name) \
	struct item_cache_info *name = SCOUTFS_SB(sb)->item_cache_info

struct cached_item {
	struct scoutfs_cwskip_node *node;
	struct list_head dirty_head;
	struct rcu_head rcu_head;
	atomic64_t age;
	unsigned int dirty:1,		/* needs to be written */
		     persistent:1,	/* in btrees, needs deletion item */
		     deletion:1,	/* negative del item for writing */
		     delta:1,		/* item vales are combined, freed after write */
		     negative:1,	/* no item, marks hole_after boundary */ 
		     hole_after:1;	/* no cache until next item */
	unsigned int alloc_bytes;
	unsigned int val_len;
	int dirty_cpu;
	struct scoutfs_key key;
	u64 seq;
	char *val;
};

static int key_item_cmp(void *K, void *C)
{
	struct scoutfs_key *key = K;
	struct cached_item *item = C;

	return scoutfs_key_compare(key, &item->key);
}

static int item_alloc_bytes(int height, int val_len)
{
	return sizeof(struct cached_item) +
	       offsetof(struct scoutfs_cwskip_node, links[height]) +
	       val_len;
}

/*
 * Allocate and initialize a new item.  These can be freed directly
 * until they're inserted into the item list.  The moment they're
 * visible via the list they have to be freed with call_free_item within
 * an RCU read lock.
 */
static struct cached_item *alloc_item(struct super_block *sb,
				      struct scoutfs_key *key, u64 seq, bool deletion,
				      void *val, int val_len)
{
	struct cached_item *item;
	int height;
	int bytes;

	height = scoutfs_cwskip_rand_height();
	bytes = item_alloc_bytes(height, val_len);
	item = kmalloc(bytes, GFP_NOFS);
	if (!item)
		return NULL;

	item->node = (void *)item + sizeof(struct cached_item);
	item->val = (void *)&item->node->links[height];

	INIT_LIST_HEAD(&item->dirty_head);
	atomic64_set(&item->age, 0);

	item->dirty = 0;
	item->persistent = 0;
	item->deletion = !!deletion;
	item->delta = 0;
	item->negative = 0;
	item->hole_after = 0;
	item->alloc_bytes = bytes;
	item->val_len = val_len;
	item->dirty_cpu = -1;
	item->key = *key;
	item->seq = seq;

	item->node->height = height;
	item->node->write_seq = 0;
	/* insert initializes all node links */

	if (val_len)
		memcpy(item->val, val, val_len);

	scoutfs_add_counter(sb, item_alloc_bytes, bytes);

	return item;
}

static void call_free_item(struct super_block *sb, struct cached_item *item)
{
	if (item) {
		scoutfs_add_counter(sb, item_free_bytes, item->alloc_bytes);
		kfree_rcu(item, rcu_head);
	}
}

#define ITEM_AGE_NR_SHIFT	3
#define ITEM_AGE_NR		(1 << ITEM_AGE_NR_SHIFT)
#define ITEM_AGE_HALF		(ITEM_AGE_NR / 2)
#define ITEM_AGE_MARK_BATCH	(256 * 1024)
#define ITEM_AGE_MARK_SHIFT	62
#define ITEM_AGE_MARK_MASK	((1ULL << ITEM_AGE_MARK_SHIFT) - 1)


/*
 * Add the caller's per-cpu marked count for their age to the global
 * marked count for the current age.   If the current age advances we
 * drop the caller's marked count.
 */
static u64 add_global_age_marked(struct item_cache_info *cinf, u64 age_marked)
{
	u64 old;
	u64 new;

	do {
		old = atomic64_read(&cinf->age_marked);
		if ((old & ~ITEM_AGE_MARK_MASK) !=
		    (age_marked & ~ITEM_AGE_MARK_MASK))
			return 0;

		new = old + (age_marked & ITEM_AGE_MARK_MASK);
	} while (atomic64_cmpxchg(&cinf->age_marked, old, new) != old);

	return new & ITEM_AGE_MARK_MASK;
}

/*
 * Make sure that a recently accessed item is marked with the current
 * age to protect it from shrink.  We record the total bytes we've
 * marked in per-cpu counters.   If the per-cpu marked count crosses a
 * threshold we combine it with a global count.  If the global count
 * exceeds an age's fraction of the total then we increment the current
 * age to mark and clear the marking counts.
 *
 * The result is that recent ages will have roughly a (1/ages) fraction
 * of the total bytes of the cache.  That gets less and less true over
 * time as the old ages have items removed.
 *
 * This is very far from perfect, but we don't need perfect.  We need to
 * avoid creating read storms by shrinking active items while also not
 * creating global contention by tracking items.
 *
 * This has to be a little fiddly to avoid a marked batch count on a cpu
 * for age N being added to the global total for age N+1.  We mark the
 * high bits of the marked totals with the low two bits of the current
 * age.   cmpxchg then stops the total for an old age being added to a
 * different age, within a short distance.
 */
static void mark_item_age(struct item_cache_info *cinf, struct cached_item *item)
{
	struct pcpu_age_counters *pac;
	u64 old_age;
	u64 marked;
	u64 limit;
	u64 age;
	u64 old;
	u64 new;
	u64 was;
	int cpu;

	old_age = atomic64_read(&item->age);
	age = atomic64_read(&cinf->current_age);
	if (old_age == age ||
	    atomic64_cmpxchg(&item->age, old_age, age) != old_age)
		return;

	pac = get_cpu_ptr(cinf->pcpu_age);

	old = atomic64_read(&pac->age_marked);
	marked = (old & ITEM_AGE_MARK_MASK) + item->alloc_bytes;
	new = (age << ITEM_AGE_MARK_SHIFT) + marked;

	/* bail on the only failure case when the age advances */
	was = atomic64_cmpxchg(&pac->age_marked, old, new);
	put_cpu_ptr(cinf->pcpu_age);
	if (was != old)
		return;

	if (marked < ITEM_AGE_MARK_BATCH)
		return;

	/* adding to the global retries unless the age changes */
	marked = add_global_age_marked(cinf, atomic64_read(&pac->age_marked));
	limit = atomic64_read(&cinf->age_total) >> ITEM_AGE_NR_SHIFT;
	if (marked < limit)
		return;

	age = atomic64_inc_return(&cinf->current_age);
	atomic64_set(&cinf->age_marked, age << ITEM_AGE_MARK_SHIFT);

	for_each_online_cpu(cpu) {
		atomic64_set(&pac->age_marked, age << ITEM_AGE_MARK_SHIFT);
		atomic64_add(atomic64_xchg(&pac->total, 0), &cinf->age_total);
	}
}

static void update_age_total(struct item_cache_info *cinf, int upd)
{
	struct pcpu_age_counters *pac = get_cpu_ptr(cinf->pcpu_age);

	atomic64_add((s64)upd, &pac->total);
	put_cpu_ptr(cinf->pcpu_age);
}

/*
 * Dirty items have a particular usage pattern.   Many cpus can be
 * creating them at full speed, they're almost never removed, their
 * total number is limited by the size of a commit, and they're
 * committed while protected from modification.   We track the dirty
 * items in per-cpu lists to avoid contention.  They're later spliced
 * and sorted when it's time to write.
 *
 * We're still using a global atomic for the ease and precision.  If it
 * becomes a problem we can degrade it to fuzzier use of percpu
 * counters.
 */
static void mark_item_dirty(struct super_block *sb,
			    struct item_cache_info *cinf,
			    struct cached_item *item)
{
	struct pcpu_dirty_list *pdlist;
	int cpu;

	if (!item->dirty) {
		cpu = get_cpu();
		pdlist = per_cpu_ptr(cinf->pcpu_dirty, cpu);
		spin_lock(&pdlist->lock);
		list_add_tail(&item->dirty_head, &pdlist->list);
		item->dirty_cpu = cpu;
		spin_unlock(&pdlist->lock);
		put_cpu();

		scoutfs_inc_counter(sb, item_mark_dirty);
		atomic64_add(item->alloc_bytes, &cinf->dirty_bytes);
		item->dirty = 1;
	}
}

static void clear_item_dirty(struct super_block *sb,
			     struct item_cache_info *cinf,
			     struct cached_item *item)
{
	struct pcpu_dirty_list *pdlist;

	if (item->dirty) {
		pdlist = get_cpu_ptr(cinf->pcpu_dirty);
		spin_lock(&pdlist->lock);
		list_del_init(&item->dirty_head);
		item->dirty_cpu = -1;
		spin_unlock(&pdlist->lock);
		put_cpu_ptr(cinf->pcpu_dirty);

		scoutfs_inc_counter(sb, item_clear_dirty);
		atomic64_sub(item->alloc_bytes, &cinf->dirty_bytes);
		item->dirty = 0;
	}
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
 * Returns true if a direct item search ends in a cached region.   We're
 * only searching for one key so if we find it then its cached and can
 * ignore the previous item.
 */
static bool item_lookup_is_cached(int cmp, struct cached_item *prev)
{
	return cmp == 0 || (prev && !prev->hole_after);
}

/*
 * Returns true if an item search within a range only traversed cached
 * regions.   Once we're searching a range we can be advancing search
 * keys and we need to know if the search we just performed was inside
 * the range, or not.   If we hit an item at the key inside the range
 * but prev indicates a hole then we skipped over unknown uncached keys
 * and we can't use the next item.
 */
static bool item_next_is_cached(bool first, int cmp, struct cached_item *prev)
{
	return (first && cmp == 0) || (prev && !prev->hole_after);
}

/* The item is positive and is visible in the cache */
static bool item_is_positive(struct cached_item *item)
{
	return item && !item->deletion && !item->negative;
}

/*
 * Track read items in a private list.   Newer versions of items replace
 * older.   We keep deletion items here so that they replace older
 * non-deletion items.   Deletion items and items that are outside of
 * the eventual range of keys read from all trees are dropped before
 * being inserted.
 */
static int item_reader(struct super_block *sb, struct scoutfs_key *key, u64 seq, u8 flags,
		       void *val, int val_len, int fic, void *arg)
{
	const bool deletion = !!(flags & SCOUTFS_ITEM_FLAG_DELETION);
	struct scoutfs_cwskip_root *root = arg;
	struct scoutfs_cwskip_writer wr;
	struct cached_item *found;
	struct cached_item *item;
	int cmp;

	item = alloc_item(sb, key, seq, deletion, val, val_len);
	if (!item)
		return -ENOMEM;

	scoutfs_cwskip_write_begin(root, key, item->node->height,
				   NULL, (void **)&found, &cmp, &wr);

	if (cmp == 0 && (found->seq < seq)) {
		/* remove existing if it's older */
		scoutfs_cwskip_write_remove(&wr, found->node);
		call_free_item(sb, found);
	}

	if (cmp != 0 || (found->seq < seq)) {
		/* insert read if first or newer */
		item->persistent = 1;
		scoutfs_cwskip_write_insert(&wr, item->node);
		item = NULL;
	}

	scoutfs_cwskip_write_end(&wr);

	kfree(item);
	return 0;
}

static int insert_missing_negative(struct super_block *sb, struct scoutfs_cwskip_root *root,
				   struct scoutfs_key *key)
{
	struct scoutfs_cwskip_writer wr;
	struct cached_item *item;
	int cmp;

	item = alloc_item(sb, key, 0, false, NULL, 0);
	if (!item)
		return -ENOMEM;

	scoutfs_cwskip_write_begin(root, key, item->node->height, NULL, NULL, &cmp, &wr);
	if (cmp != 0) {
		item->negative = 1;
		scoutfs_cwskip_write_insert(&wr, item->node);
		item = NULL;
	}
	scoutfs_cwskip_write_end(&wr);

	kfree(item);
	return 0;
}

/*
 * Read items from persistent btrees and populate the cache around the
 * key.
 *
 * The caller holds cluster locks which ensure that the persistent items
 * aren't changing.   The currently cached items might be dirty and more
 * recent than the persistent items.   We only insert read items into
 * holes in the cache.
 *
 * We read a single full block of items around the key from each btree.
 * The intersection of these read key ranges is the range of consistent
 * items that can be cached.  Any items read outside of this range might
 * be stale because their keys weren't read from all the btrees.  We
 * drop all the read items outside of the consistent range.
 *
 * The consistent key range can extend outside of the set of items read
 * inside the range.  We add negative cached items to mark the
 * boundaries of the consistent range if we didn't read items right at
 * the edges.
 *
 * Once we have a set of read items that covers the entire range we try
 * to insert them into the cache.   For each read item we iterate
 * through cached items until we find the two cached items around it.
 * If the read item falls in a hole in the cache then we insert it.   We
 * iterate over all cached items in the range, rather than just
 * searching for the position of each read item, because we may need to
 * clear hole_after between cached items.
 *
 * This is racing with all operations on the cache: item api calls,
 * other readers, memory pressure, and lock invalidation.  We are very
 * careful to only atomically modify the cache one locked item pair at a
 * time to ensure that cache is always consistent.
 */
static int read_items(struct super_block *sb, struct item_cache_info *cinf,
		      struct scoutfs_key *key, struct scoutfs_lock *lock)
{
	struct scoutfs_cwskip_root root;
	INIT_ACTIVE_READER(active);
	struct scoutfs_cwskip_writer cached_wr;
	struct scoutfs_cwskip_writer wr;
	struct cached_item *cached_prev;
	struct cached_item *cached_item;
	struct cached_item *item;
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct scoutfs_key pos;
	bool drop_before;
	bool drop_after;
	bool first;
	int cmp;
	int ret;

	/* read into an empty private root */
	scoutfs_cwskip_init_root(&root, key_item_cmp, sizeof(struct cached_item));

	/* set active reader seq before reading persistent roots */
	add_active_reader(sb, &active);

	start = lock->start;
	end = lock->end;
	ret = scoutfs_forest_read_items(sb, key, &lock->start, &start, &end, item_reader, &root);
	if (ret < 0)
		goto out;

	/* drop deleted items and items outside of the final consistent read range */
	drop_before = true;
	drop_after = false;
	scoutfs_cwskip_write_begin(&root, &lock->start, SCOUTFS_CWSKIP_MAX_HEIGHT,
				   NULL, (void **)&item, NULL, &wr);
	do {
		if (drop_before && scoutfs_key_compare(&item->key, &start) >= 0)
			drop_before = false;
		if (!drop_before && !drop_after && scoutfs_key_compare(&item->key, &end) > 0)
			drop_after = true;

		if (drop_before || item->deletion || drop_after) {
			scoutfs_cwskip_write_remove(&wr, item->node);
			call_free_item(sb, item);
		}

	} while (scoutfs_cwskip_write_next(&wr, 1, NULL, (void **)&item));
	scoutfs_cwskip_write_end(&wr);

	/* add negative items at the ends of the range if needed */
	ret = insert_missing_negative(sb, &root, &start) ?:
	      insert_missing_negative(sb, &root, &end);
	if (ret < 0)
		goto out;

	/* lock max height on our private list so _next always succeeds */
	pos = start;
	first = true;
	scoutfs_cwskip_write_begin(&root, &start, SCOUTFS_CWSKIP_MAX_HEIGHT,
				   NULL, (void **)&item, NULL, &wr);
	do {
		scoutfs_cwskip_write_begin(&cinf->item_root, &pos, item->node->height,
					   (void **)&cached_prev, (void **)&cached_item,
					   NULL, &cached_wr);
		do {
			if (cached_item)
				cmp = scoutfs_key_compare(&item->key, &cached_item->key);
			else
				cmp = -1;

			if (cmp <= 0) {
				/* check read item once its between cached items */
				scoutfs_cwskip_write_remove(&wr, item->node);

				/* insert into holes or drop and free */
				if (cmp < 0 && (!cached_prev || cached_prev->hole_after)) {
					item->hole_after = 1;
					scoutfs_cwskip_write_insert(&cached_wr, item->node);
					update_age_total(cinf, item->alloc_bytes);
					mark_item_age(cinf, item);
				} else {
					call_free_item(sb, item);
				}

				/* always succeeds for our private list */
				scoutfs_cwskip_write_next(&wr, 1, NULL, (void **)&item);
			}

			/* gaps after all cached prevs except the first are in the read range */
			if (!first && cached_prev && cached_prev->hole_after)
				cached_prev->hole_after = 0;
			first = false;

			pos = cached_item->key;
			scoutfs_key_inc(&pos);

		} while (item && scoutfs_cwskip_write_next(&cached_wr, item->node->height,
							   (void **)&cached_prev,
							   (void **)&cached_item));
		scoutfs_cwskip_write_end(&cached_wr);

	} while (item);
	scoutfs_cwskip_write_end(&wr);

	ret = 0;
out:
	del_active_reader(cinf, &active);
	return ret;
}

static int lock_safe(struct scoutfs_lock *lock, struct scoutfs_key *key,
		     int mode)
{
	if (WARN_ON_ONCE(!scoutfs_lock_protected(lock, key, mode)))
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
int scoutfs_item_lookup(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct scoutfs_cwskip_reader rd;
	struct cached_item *prev;
	struct cached_item *item;
	bool valid;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, item_lookup);

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_READ)))
		goto out;

	do {
		scoutfs_cwskip_read_begin(&cinf->item_root, key,
					  (void **)&prev, (void **)&item, &cmp, &rd);

		if (!item_lookup_is_cached(cmp, prev))
			ret = -ERANGE;
		else if (cmp != 0 || !item_is_positive(item))
			ret = -ENOENT;
		else
			ret = copy_val(val, val_len, item->val, item->val_len);

		valid = scoutfs_cwskip_read_valid(&rd);
		if (valid && item)
			mark_item_age(cinf, item);

		scoutfs_cwskip_read_end(&rd);
	} while (!valid || (ret == -ERANGE || (ret = read_items(sb, cinf, key, lock)) == 0));

out:
	return ret;
}

int scoutfs_item_lookup_exact(struct super_block *sb, struct scoutfs_key *key,
			      void *val, int val_len,
			      struct scoutfs_lock *lock)
{
	int ret;

	ret = scoutfs_item_lookup(sb, key, val, val_len, lock);
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
	struct scoutfs_cwskip_reader rd;
	struct cached_item *item;
	struct cached_item *prev;
	struct scoutfs_key pos;
	struct scoutfs_key tmp;
	bool first;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, item_next);

	/* use the end key as the last key if it's closer */
	if (scoutfs_key_compare(&lock->end, last) < 0)
		last = &lock->end;

	if (scoutfs_key_compare(key, last) > 0)
		return -ENOENT;

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_READ)))
		return ret;

	first = true;
	pos = *key;
	do {
		scoutfs_cwskip_read_begin(&cinf->item_root, &pos,
					  (void **)&prev, (void **)&item, &cmp, &rd);
		do {
			if (!item_next_is_cached(first, cmp, prev)) {
				ret = -ERANGE;

			} else if (!item || scoutfs_key_compare(&item->key, last) > 0) {
				ret = -ENOENT;

			} else if (item_is_positive(item)) {
				ret = copy_val(val, val_len, item->val, item->val_len);
				tmp = item->key;

			} else {
				tmp = item->key;
				scoutfs_key_inc(&tmp);
				ret = -ESRCH;
			}

			if (scoutfs_cwskip_read_valid(&rd)) {
				pos = tmp;
				first = false;
				if (ret != -ESRCH && item)
					mark_item_age(cinf, item);
			} else {
				ret = -ESRCH;
			}
		} while (ret == -ESRCH &&
			 scoutfs_cwskip_read_next(&rd, (void **)&prev, (void **)&item));
		scoutfs_cwskip_read_end(&rd);

		if (ret == -ERANGE) {
			ret = read_items(sb, cinf, &pos, lock);
			if (ret ==  0)
				ret = -ESRCH;
		}

	} while(ret == -ESRCH);

	if (ret >= 0)
		*key = pos;

	return ret;
}

/*
 * An item's seq is greater of the client transaction's seq and the
 * lock's write_seq.  This ensures that multiple commits in one lock
 * grant will have increasing seqs, and new locks in open commits will
 * also increase the seqs.  It lets us limit the inputs of item merging
 * to the last stable seq and ensure that all the items in open
 * transactions and granted locks will have greater seqs.
 */
static u64 item_seq(struct super_block *sb, struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	return max(sbi->trans_seq, lock->write_seq);
}

/*
 * Mark the item dirty.  Dirtying while holding a transaction pins the
 * item and guarantees that the item can be deleted or updated (without
 * increasing the value length) during the transaction without errors.
 */
int scoutfs_item_dirty(struct super_block *sb, struct scoutfs_key *key,
		       struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct scoutfs_cwskip_writer wr;
	struct cached_item *item;
	struct cached_item *prev;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, item_dirty);

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	do {
		scoutfs_cwskip_write_begin(&cinf->item_root, key, 0,
					   (void **)&prev, (void **)&item, &cmp, &wr);
		if (!item_lookup_is_cached(cmp, prev)) {
			ret = -ERANGE;
		} else if (cmp != 0 || !item_is_positive(item)) {
			ret = -ENOENT;
		} else {
			item->seq = item_seq(sb, lock);
			mark_item_dirty(sb, cinf, item);
			mark_item_age(cinf, item);
			ret = 0;
		}
		scoutfs_cwskip_write_end(&wr);
	} while (ret == -ERANGE && ((ret = read_items(sb, cinf, key, lock)) == 0));

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
		       int mode, bool force)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const u64 seq = item_seq(sb, lock);
	struct scoutfs_cwskip_writer wr;
	struct cached_item *found;
	struct cached_item *item;
	struct cached_item *prev;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, item_create);

	if ((ret = lock_safe(lock, key, mode)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	item = alloc_item(sb, key, seq, false, val, val_len);
	if (!item) {
		ret = -ENOMEM;
		goto out;
	}

	do {
		scoutfs_cwskip_write_begin(&cinf->item_root, key, item->node->height,
					   (void **)&prev, (void **)&found, &cmp, &wr);
		if (!force && !item_lookup_is_cached(cmp, prev)) {
			ret = -ERANGE;
		} else if (!force && cmp == 0 && item_is_positive(found)) {
			ret = -EEXIST;
		} else {
			if (found) {
				item->persistent = found->persistent;
				clear_item_dirty(sb, cinf, found);
				scoutfs_cwskip_write_remove(&wr, found->node);
				update_age_total(cinf, -found->alloc_bytes);
				call_free_item(sb, found);
			}

			if (force)
				item->persistent = 1;
			scoutfs_cwskip_write_insert(&wr, item->node);
			update_age_total(cinf, item->alloc_bytes);
			mark_item_dirty(sb, cinf, item);
			mark_item_age(cinf, item);
			item = NULL;

			ret = 0;
		}
		scoutfs_cwskip_write_end(&wr);

	} while (ret == -ERANGE && ((ret = read_items(sb, cinf, key, lock)) == 0));

	kfree(item);
out:
	return ret;
}

int scoutfs_item_create(struct super_block *sb, struct scoutfs_key *key,
			void *val, int val_len, struct scoutfs_lock *lock)
{
	return item_create(sb, key, val, val_len, lock, SCOUTFS_LOCK_READ, false);
}

int scoutfs_item_create_force(struct super_block *sb, struct scoutfs_key *key,
			      void *val, int val_len,
			      struct scoutfs_lock *lock)
{
	return item_create(sb, key, val, val_len, lock, SCOUTFS_LOCK_WRITE_ONLY, true);
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
	const u64 seq = item_seq(sb, lock);
	struct scoutfs_cwskip_writer wr;
	struct cached_item *item = NULL;
	struct cached_item *found;
	struct cached_item *prev;
	bool need_alloc = false;
	int lock_height;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, item_update);

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	ret = 0;
	do {
		if (need_alloc && !item) {
			item = alloc_item(sb, key, seq, false, val, val_len);
			if (!item) {
				ret = -ENOMEM;
				break;
			}
			lock_height = item->node->height;
		} else {
			lock_height = 0;
		}

		scoutfs_cwskip_write_begin(&cinf->item_root, key, lock_height,
					   (void **)&prev, (void **)&found, &cmp, &wr);
		if (!item_lookup_is_cached(cmp, prev)) {
			ret = -ERANGE;
		} else if (cmp != 0 || !item_is_positive(found)) {
			ret = -ENOENT;
		} else {
			if (val_len <= found->val_len) {
				if (val_len)
					memcpy(found->val, val, val_len);
				found->val_len = val_len;
				found->seq = seq;
				mark_item_dirty(sb, cinf, found);
				mark_item_age(cinf, item);
			} else if (!item) {
				need_alloc = true;
			} else {
				item->persistent = found->persistent;

				clear_item_dirty(sb, cinf, found);
				scoutfs_cwskip_write_remove(&wr, found->node);
				update_age_total(cinf, -found->alloc_bytes);
				call_free_item(sb, found);

				mark_item_dirty(sb, cinf, item);
				mark_item_age(cinf, item);
				scoutfs_cwskip_write_insert(&wr, item->node);
				update_age_total(cinf, item->alloc_bytes);
				item = NULL;
			}
			ret = 0;
		}
		scoutfs_cwskip_write_end(&wr);

	} while (need_alloc || (ret == -ERANGE && ((ret = read_items(sb, cinf, key, lock)) == 0)));

	kfree(item);
out:
	return ret;
}

/*
 * Add a delta item.  Delta items are an incremental change relative to
 * the current persistent delta items.  We never have to read the
 * current items so the caller always writes with write only locks.  If
 * combining the current delta item and the caller's item results in a
 * null we can just drop it, we don't have to emit a deletion item.
 */
int scoutfs_item_delta(struct super_block *sb, struct scoutfs_key *key,
		       void *val, int val_len, struct scoutfs_lock *lock)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const u64 seq = item_seq(sb, lock);
	struct scoutfs_cwskip_writer wr;
	struct cached_item *alloc = NULL;
	struct cached_item *item;
	struct cached_item *prev;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, item_delta);

	if ((ret = lock_safe(lock, key, SCOUTFS_LOCK_WRITE_ONLY)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	alloc = alloc_item(sb, key, seq, false, val, val_len);
	if (!alloc) {
		ret = -ENOMEM;
		goto out;
	}

	scoutfs_cwskip_write_begin(&cinf->item_root, key, alloc->node->height,
				   (void **)&prev, (void **)&item, &cmp, &wr);
	if (cmp == 0) {
		if (!item->delta) {
			ret = -EIO;
			goto end;
		}

		ret = scoutfs_forest_combine_deltas(key, item->val, item->val_len, val, val_len);
		if (ret <= 0) {
			if (ret == 0)
				ret = -EIO;
			goto end;
		}

		if (ret == SCOUTFS_DELTA_COMBINED) {
			item->seq = seq;
			mark_item_dirty(sb, cinf, item);
			mark_item_age(cinf, item);
		} else if (ret == SCOUTFS_DELTA_COMBINED_NULL) {
			clear_item_dirty(sb, cinf, item);
			scoutfs_cwskip_write_remove(&wr, item->node);
			update_age_total(cinf, -item->alloc_bytes);
			call_free_item(sb, item);
		} else {
			ret = -EIO;
			goto end;
		}
		ret = 0;
	} else {
		item = alloc;
		alloc = NULL;

		scoutfs_cwskip_write_insert(&wr, item->node);
		update_age_total(cinf, item->alloc_bytes);
		mark_item_dirty(sb, cinf, item);
		mark_item_age(cinf, item);
		item->delta = 1;
		ret = 0;
	}
end:
	scoutfs_cwskip_write_end(&wr);
out:
	kfree(alloc);
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
		       struct scoutfs_lock *lock, int mode, bool force)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	const u64 seq = item_seq(sb, lock);
	struct scoutfs_cwskip_writer wr;
	struct cached_item *alloc = NULL;
	struct cached_item *item;
	struct cached_item *prev;
	bool need_alloc = false;
	int lock_height;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, item_delete);

	if ((ret = lock_safe(lock, key, mode)))
		goto out;

	ret = scoutfs_forest_set_bloom_bits(sb, lock);
	if (ret < 0)
		goto out;

	ret = 0;
	do {
		if (need_alloc) {
			need_alloc = false;
			alloc = alloc_item(sb, key, seq, true, NULL, 0);
			if (!item) {
				ret = -ENOMEM;
				goto out;
			}
			lock_height = alloc->node->height;
		} else {
			lock_height = 1;
		}

		scoutfs_cwskip_write_begin(&cinf->item_root, key, lock_height,
					   (void **)&prev, (void **)&item, &cmp, &wr);
		if (!force && !item_lookup_is_cached(cmp, prev)) {
			ret = -ERANGE;
			goto end;
		}
		if (!force && !item_is_positive(item)) {
			ret = -ENOENT;
			goto end;
		}

		if (!item) {
			if (!alloc) {
				need_alloc = true;
				goto end;
			}
			item = alloc;
			alloc = NULL;
			scoutfs_cwskip_write_insert(&wr, item->node);
			update_age_total(cinf, item->alloc_bytes);
		}

		if (force)
			item->persistent = 1;

		if (!item->persistent) {
			/* can just forget items that aren't yet persistent */
			clear_item_dirty(sb, cinf, item);
			scoutfs_cwskip_write_remove(&wr, item->node);
			update_age_total(cinf, -item->alloc_bytes);
			call_free_item(sb, item);
		} else {
			/* must emit deletion to clobber old persistent item */
			item->seq = seq;
			item->deletion = 1;
			item->val_len = 0;
			mark_item_dirty(sb, cinf, item);
			mark_item_age(cinf, item);
		}
end:
		scoutfs_cwskip_write_end(&wr);
	} while (need_alloc || (ret == -ERANGE && ((ret = read_items(sb, cinf, key, lock)) == 0)));

out:
	kfree(alloc);
	return ret;
}

int scoutfs_item_delete(struct super_block *sb, struct scoutfs_key *key,
			struct scoutfs_lock *lock)
{
	return item_delete(sb, key, lock, SCOUTFS_LOCK_WRITE, false);
}

int scoutfs_item_delete_force(struct super_block *sb, struct scoutfs_key *key,
			      struct scoutfs_lock *lock)
{
	return item_delete(sb, key, lock, SCOUTFS_LOCK_WRITE_ONLY, true);
}

u64 scoutfs_item_dirty_bytes(struct super_block *sb)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);

	return (u64)atomic64_read(&cinf->dirty_bytes);
}

static int cmp_dirty_item_key(void *priv, struct list_head *A, struct list_head *B)
{
	struct cached_item *a = list_entry(A, struct cached_item, dirty_head);
	struct cached_item *b = list_entry(B, struct cached_item, dirty_head);

	return scoutfs_key_compare(&a->key, &b->key);
}

/*
 * btree block insertion is iterating through the items in write_dirty's
 * private list.  The dirty items won't change.  Each time we're called
 * we return if we filled the descriptor with the current position and
 * advance.
 */
static void *item_btree_iter_cb(struct super_block *sb, struct scoutfs_btree_item_desc *desc,
				void *pos, void *arg)
{
	struct list_head *private_list = arg;
	struct cached_item *item = pos;

	if (item == NULL) {
		memset(desc, 0, sizeof(struct scoutfs_btree_item_desc));
		return NULL;
	}

	desc->key = &item->key;
	desc->seq = item->seq;
	desc->flags = item->deletion ? SCOUTFS_ITEM_FLAG_DELETION : 0;
	desc->val = item->val;
	desc->val_len = item->val_len;

	if (item->dirty_head.next == private_list)
		item = NULL;
	else
		item = list_next_entry(item, dirty_head);

	return item;
}

static void splice_all_pcpu_dirty_lists(struct item_cache_info *cinf, struct list_head *list)
{
	struct pcpu_dirty_list *pdlist;
	int cpu;

	for_each_online_cpu(cpu) {
		pdlist = per_cpu_ptr(cinf->pcpu_dirty, cpu);
		list_splice_init(&pdlist->list, list);
	}
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
 * from entering a transaction and modifying dirtying items.  The dirty
 * items will not be modified and no new dirty items will be added.
 * We're the only user of the dirty lists.
 */
int scoutfs_item_write_dirty(struct super_block *sb)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct pcpu_dirty_list *pdlist;
	struct cached_item *item;
	LIST_HEAD(list);
	u64 max_seq;
	int cpu;
	int ret;

	scoutfs_inc_counter(sb, item_write_dirty);

	/* gather all dirty items and sort by their key */
	splice_all_pcpu_dirty_lists(cinf, &list);
	list_sort(NULL, &list, cmp_dirty_item_key);

	/* scan for the max seq, really seems like we could track this :/ */
	max_seq = 0;
	list_for_each_entry(item, &list, dirty_head)
		max_seq = max(max_seq, item->seq);

	/* store max item seq in forest's log_trees */
	scoutfs_forest_set_max_seq(sb, max_seq);

	/* write all the dirty items into log btree blocks */
	item = list_first_entry_or_null(&list, struct cached_item, dirty_head);
	ret = scoutfs_forest_insert_list(sb, item_btree_iter_cb, item, &list);

	/* return items to a pcpu list, we know ours exists :) */
	cpu = get_cpu();
	pdlist = per_cpu_ptr(cinf->pcpu_dirty, cpu);
	list_splice_init(&list, &pdlist->list);
	list_for_each_entry(item, &pdlist->list, dirty_head) {
		item->dirty_cpu = cpu;
	}
	put_cpu();

	return ret;
}

/*
 * The caller has successfully committed all the dirty btree blocks that
 * contained the currently dirty items.  Clear all the dirty items.
 *
 * Deletion and delta items only existed to emit items into the btree
 * logs.   They aren't read from the item cache so once they're written
 * we can remove them.
 *
 * The items in the private dirty list are still protected by being
 * dirty and won't be removed from the main item list.  For each item in
 * the private list we search for it in the item list and remove it.
 * We're likely to encounter runs of dirty items so we try iterating
 * from our search position and clear as many dirty items as we can
 * find.
 */
int scoutfs_item_write_done(struct super_block *sb)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct scoutfs_cwskip_writer wr;
	struct cached_item *found;
	struct cached_item *item;
	LIST_HEAD(list);
	int cleared = 0;
	int cmp;

	splice_all_pcpu_dirty_lists(cinf, &list);

	while ((item = list_first_entry_or_null(&list, struct cached_item, dirty_head))) {

		scoutfs_cwskip_write_begin(&cinf->item_root, &item->key, item->node->height,
					   NULL, (void **)&found, &cmp, &wr);
		BUG_ON(cmp != 0 || found != item);
		do {
			if (!item->dirty)
				break;

			/* all dirty items are only on our private list */
			list_del_init(&item->dirty_head);
			item->dirty = 0;
			item->dirty_cpu = -1;
			cleared++;

			if (item->delta)
				scoutfs_inc_counter(sb, item_delta_written);

			if (item->deletion || item->delta) {
				scoutfs_cwskip_write_remove(&wr, item->node);
				update_age_total(cinf, -item->alloc_bytes);
				call_free_item(sb, item);
			} else {
				item->persistent = 1;
			}

		} while (scoutfs_cwskip_write_next(&wr, 1, NULL, (void **)&item));

		scoutfs_cwskip_write_end(&wr);
	}

	scoutfs_add_counter(sb, item_clear_dirty, cleared);
	atomic64_set(&cinf->dirty_bytes, 0);

	return 0;
}

/*
 * Return true if the item cache covers the given range and set *dirty
 * to true if any items in the cached range are dirty.
 *
 * This is called as locks are granted to make sure that we *don't* have
 * existing cache covered by the lock which then must be inconsistent.
 * Finding items is the critical error case.  Under correct operation
 * this will be a read search that doesn't find anything.
 *
 * The best way to think about searching for cached items is to see
 * that the only way for there *not* to be cached items in the range is
 * if there is a) no previous item before the start key or the previous
 * item has hole_after set and b) there are no items in the range.  If
 * we see a prev with hole after, or any items within the end key, then
 * the range is cached.
 */
bool scoutfs_item_range_cached(struct super_block *sb,
			       struct scoutfs_key *start,
			       struct scoutfs_key *end, bool *dirty)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct scoutfs_cwskip_reader rd;
	struct scoutfs_key pos = *start;
	struct scoutfs_key rd_pos;
	struct cached_item *item;
	struct cached_item *prev;
	bool cached = false;
	bool done = false;
	bool rd_cached;
	bool rd_dirty;
	bool rd_done;

	*dirty = false;
	do {
		scoutfs_cwskip_read_begin(&cinf->item_root, &pos,
					  (void **)&prev, (void **)&item, NULL, &rd);
		do {
			/* catches region starting with cache between items */
			rd_cached = prev && !prev->hole_after;

			rd_dirty = false;
			rd_done = false;
			if (!item || scoutfs_key_compare(&item->key, end) > 0) {
				rd_done = true;
			} else {
				rd_pos = item->key;
				scoutfs_key_inc(&rd_pos);

				rd_cached = true;
				if (item->dirty) {
					rd_dirty = true;
					rd_done = true;
				}
			}

			if (scoutfs_cwskip_read_valid(&rd)) {
				pos = rd_pos;
				cached |= rd_cached;
				*dirty |= rd_dirty;
				done |= rd_done;
			}
		} while (!done && scoutfs_cwskip_read_next(&rd, (void **)&prev, (void **)&item));
		scoutfs_cwskip_read_end(&rd);

	} while (!done);

	return cached;
}

/*
 * Remove the cached items in the given range.  This is called by lock
 * invalidation which is preventing use of the lock while its
 * invalidating.   There can be no read or write item calls for the
 * specific key range.  There can be item calls working with the
 * neighbouring items that we might reference while invalidating the
 * edges of the range.  This can be racing with memory pressure
 * shrinking the cache.
 *
 * We have to remove the negative cached space covered by the range as
 * well as the cached items themselves.  This is done by setting
 * hole_after in the item before items we remove.   We can have to
 * remove only a negative cached region so we have to do this when there
 * isn't a referenced node after the key.
 */
void scoutfs_item_invalidate(struct super_block *sb, struct scoutfs_key *start,
			     struct scoutfs_key *end)
{
	DECLARE_ITEM_CACHE_INFO(sb, cinf);
	struct scoutfs_cwskip_writer wr;
	struct scoutfs_key key = *start;
	struct cached_item *prev;
	struct cached_item *item;
	bool first = true;
	int cmp;

	scoutfs_inc_counter(sb, item_invalidate);

	do {
		scoutfs_cwskip_write_begin(&cinf->item_root, &key, 1,
					   (void **)&prev, (void **)&item, &cmp, &wr);
		do {
			if (!(first && cmp == 0) && prev && !prev->hole_after)
				prev->hole_after = 1;
			first = false;

			if (item) {
				key = item->key;
				scoutfs_key_inc(&key);
			} else {
				scoutfs_key_set_ones(&key);
			}

			if (!item || scoutfs_key_compare(&item->key, end) > 0)
				break;

			/* cluster locking must sync before invalidating */
			WARN_ON_ONCE(item->dirty);

			scoutfs_inc_counter(sb, item_invalidate_item);

			scoutfs_cwskip_write_remove(&wr, item->node);
			update_age_total(cinf, -item->alloc_bytes);
			call_free_item(sb, item);

		} while (scoutfs_cwskip_write_next(&wr, 1, (void **)&prev, (void **)&item));
		scoutfs_cwskip_write_end(&wr);

	} while (scoutfs_key_compare(&key, end) <= 0);
}

static bool can_shrink_item(struct cached_item *item, u64 shrink_age, u64 first_reader_seq)
{
	return item &&
	       atomic64_read(&item->age) <= shrink_age &&
	       item->seq < first_reader_seq &&
	       !item->dirty;
}

/*
 * Shrink the size the item cache.
 *
 * As items were accessed we tried to mark them with coarse age values
 * that divide them into fractions of the total cached items.  We have
 * no specific indexing of items by age, instead we randomly search the
 * list looking for items that are old enough to shrink.
 *
 * We cast a very wide net when searching for items that are old enough.
 * If we searched for a precise small age window then the random
 * searching has to do more work before it finds the ages it's looking
 * for.  Instead we only search for two broad age categories: either
 * items that are older than the most recently accessed half of the
 * items, or all items.  This ensures that the random search will find
 * items to shrink reasonably often.
 *
 * While we initially search to a random position in the list, we try to
 * shrink contiguous runs of items.  We choose a small size that is
 * still larger than can be read and inserted in a single operation.
 * The worst case would be to randomly free individual items leading to
 * later reads that discard most of their items while inserting into a
 * single item hole.
 *
 * All of this can go wrong.   Access patterns can lead to weird age
 * groupings, the cache can be entirely dirty, invalidation can remove
 * the entire cache out from under us if the entire system is in one
 * lock (a handful of enormous files in one inode group).   This is all
 * a best effort that stops when it has too many attempts that don't
 * make progress.
 *
 * Finally, while we work with items the caller really cares about
 * allocated pages.   We track the bytes allocated to items and
 * translate that to units of pages for the caller.   We have no idea if
 * our frees make up freed contiguous pages, and we're not really
 * freeing items before returning, we're asking RCU to free later for
 * us.   So while we can return and tell the caller we freed our objects
 * it's mostly a lie that we hope works out in the end.
 */
static int item_shrink(struct shrinker *shrink, struct shrink_control *sc)
{
#define ITEM_SHRINK_SCAN_LIMIT		(2 * SCOUTFS_BLOCK_LG_SIZE)
#define ITEM_SHRINK_ATTEMPT_LIMIT	64
	struct item_cache_info *cinf = container_of(shrink, struct item_cache_info, shrinker);
	struct super_block *sb = cinf->sb;
	struct scoutfs_cwskip_reader rd;
	struct scoutfs_cwskip_writer wr;
	struct cached_item *item;
	struct cached_item *prev;
	struct scoutfs_key key;
	u64 first_reader_seq;
	s64 shrink_bytes;
	u64 shrink_age;
	u64 cur_age;
	int attempts;
	int scanned;
	bool found;

	if (sc->nr_to_scan == 0)
		goto out;

	scoutfs_inc_counter(sb, item_shrink);

	/* can't invalidate pages with items that weren't visible to first reader */
	first_reader_seq = first_active_reader_seq(cinf);

	shrink_bytes = (u64)sc->nr_to_scan << PAGE_SHIFT;

	/* can shrink oldest half if shrinking less than half, otherwise everything */
	cur_age = atomic64_read(&cinf->current_age);
	if ((shrink_bytes < (atomic64_read(&cinf->age_total) >> 1)) && (cur_age > ITEM_AGE_NR)) {
		shrink_age = cur_age - ITEM_AGE_HALF;
	} else {
		scoutfs_inc_counter(sb, item_shrink_all);
		shrink_age = U64_MAX;
	}

	attempts = 0;

	do {
		attempts++;

		/* find the key of a shrink candidate */
		scoutfs_inc_counter(sb, item_shrink_read_search);
		scanned = 0;
		found = false;
		scoutfs_cwskip_read_begin(&cinf->item_root, NULL,
					  (void **)&prev, (void **)&item, NULL, &rd);
		do {
			if (!item) {
				if (!prev)
					shrink_bytes = 0;
				break;
			}

			/* keys don't change */
			key = item->key;

			if (can_shrink_item(item, shrink_age, first_reader_seq)) {
				found = true;
				break;
			}

			scoutfs_key_inc(&key);
			scoutfs_inc_counter(sb, item_shrink_searched);
			scanned += item->alloc_bytes;

		} while (scanned < ITEM_SHRINK_SCAN_LIMIT &&
			 scoutfs_cwskip_read_next(&rd, (void **)&prev, (void **)&item));
		scoutfs_cwskip_read_end(&rd);

		if (!found)
			continue;

		/* try to shrink items in a region after the key */
		scoutfs_inc_counter(sb, item_shrink_write_search);
		scanned = 0;
		scoutfs_cwskip_write_begin(&cinf->item_root, &key, 1,
					   (void **)&prev, (void **)&item, NULL, &wr);
		do {
			if (!item)
				break;

			key = item->key;
			scoutfs_key_inc(&key);
			scanned += item->alloc_bytes;

			if (can_shrink_item(item, shrink_age, first_reader_seq)) {
				scoutfs_inc_counter(sb, item_shrink_removed);
				if (prev && !prev->hole_after)
					prev->hole_after = 1;
				scoutfs_cwskip_write_remove(&wr, item->node);
				update_age_total(cinf, -item->alloc_bytes);
				call_free_item(sb, item);
				shrink_bytes -= item->alloc_bytes;
				attempts = 0;
			} else {
				scoutfs_inc_counter(sb, item_shrink_skipped);
			}
		} while (shrink_bytes > 0 && scanned < ITEM_SHRINK_SCAN_LIMIT &&
			 scoutfs_cwskip_write_next(&wr, 1, NULL, (void **)&item));
		scoutfs_cwskip_write_end(&wr);

	} while (shrink_bytes > 0 && attempts < ITEM_SHRINK_ATTEMPT_LIMIT);

	if (attempts >= ITEM_SHRINK_ATTEMPT_LIMIT)
		scoutfs_inc_counter(sb, item_shrink_exhausted);

out:
	return min_t(u64, atomic64_read(&cinf->age_total) >> PAGE_SHIFT, INT_MAX);
}

/*
 * Free all the items in batches so as not to overwhelm rcu.   Only used
 * during teardown when there must be no more item use.
 */
static void free_all_items(struct super_block *sb, struct item_cache_info *cinf)
{
	struct scoutfs_cwskip_writer wr;
	struct cached_item *item;
	struct scoutfs_key key;
	int i;

	/* free items in batches of rcu critical sections */
	scoutfs_key_set_zeros(&key);
	do {
		scoutfs_cwskip_write_begin(&cinf->item_root, &key,
					   SCOUTFS_CWSKIP_MAX_HEIGHT,
					   NULL, (void **)&item, NULL, &wr);
		if (!item)
			break;
		i = 0;
		do {
			clear_item_dirty(sb, cinf, item);
			scoutfs_cwskip_write_remove(&wr, item->node);
			call_free_item(sb, item);
		} while (++i < 1024 && scoutfs_cwskip_write_next(&wr, 1, NULL, (void **)&item));
		scoutfs_cwskip_write_end(&wr);

		synchronize_rcu();
	} while (item);

	WARN_ON_ONCE(!scoutfs_cwskip_empty(&cinf->item_root));
}

static int item_cpu_callback(struct notifier_block *nfb,
			     unsigned long action, void *hcpu)
{
	struct item_cache_info *cinf = container_of(nfb, struct item_cache_info, notifier);
	unsigned long dead_cpu = (unsigned long)hcpu;
	struct pcpu_age_counters *pac;
	struct pcpu_dirty_list *pdlist;
	struct cached_item *item;
	LIST_HEAD(list);
	int our_cpu;

        if (action == CPU_DEAD) {
		our_cpu = get_cpu();

		/* age tracking */
		pac = per_cpu_ptr(cinf->pcpu_age, dead_cpu);
		add_global_age_marked(cinf, atomic64_read(&pac->age_marked));
		atomic64_set(&pac->age_marked, 0);
		atomic64_add(atomic64_xchg(&pac->total, 0), &cinf->age_total);

		/* dirty item lists */
		pdlist = per_cpu_ptr(cinf->pcpu_dirty, dead_cpu);
		list_splice_init(&pdlist->list, &list);

		our_cpu = get_cpu();
		list_for_each_entry(item, &list, dirty_head)
			item->dirty_cpu = our_cpu;
		pdlist = per_cpu_ptr(cinf->pcpu_dirty, our_cpu);
		spin_lock(&pdlist->lock);
		list_splice_init(&list, &pdlist->list);
		spin_unlock(&pdlist->lock);

		put_cpu();
	}

	return NOTIFY_OK;
}

int scoutfs_item_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct pcpu_dirty_list *pdlist;
	struct pcpu_age_counters *pac;
	struct item_cache_info *cinf;
	int cpu;

	cinf = kzalloc(sizeof(struct item_cache_info), GFP_KERNEL);
	if (!cinf)
		return -ENOMEM;

	cinf->sb = sb;
	scoutfs_cwskip_init_root(&cinf->item_root, key_item_cmp, sizeof(struct cached_item));
	atomic64_set(&cinf->current_age, 1);
	atomic64_set(&cinf->age_marked, 1ULL << ITEM_AGE_MARK_SHIFT);
	atomic64_set(&cinf->age_total, 0);
	atomic64_set(&cinf->dirty_bytes, 0);
	spin_lock_init(&cinf->active_lock);
	INIT_LIST_HEAD(&cinf->active_list);

	cinf->pcpu_dirty = alloc_percpu(struct pcpu_dirty_list);
	if (!cinf->pcpu_dirty) {
		kfree(cinf);
		return -ENOMEM;
	}

	cinf->pcpu_age = alloc_percpu(struct pcpu_age_counters);
	if (!cinf->pcpu_age) {
		kfree(cinf);
		free_percpu(cinf->pcpu_dirty);
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu) {
		pac = per_cpu_ptr(cinf->pcpu_age, cpu);
		pac->age_marked = cinf->age_marked;
		atomic64_set(&pac->total, 0);

		pdlist = per_cpu_ptr(cinf->pcpu_dirty, cpu);
		spin_lock_init(&pdlist->lock);
		INIT_LIST_HEAD(&pdlist->list);
	}

	cinf->shrinker.shrink = item_shrink;
	cinf->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&cinf->shrinker);
        cinf->notifier.notifier_call = item_cpu_callback;
        register_hotcpu_notifier(&cinf->notifier);

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

	if (cinf) {
		BUG_ON(!list_empty(&cinf->active_list));

		unregister_hotcpu_notifier(&cinf->notifier);
		unregister_shrinker(&cinf->shrinker);

		free_all_items(sb, cinf);

		free_percpu(cinf->pcpu_dirty);
		free_percpu(cinf->pcpu_age);

		kfree(cinf);
		sbi->item_cache_info = NULL;
	}
}
