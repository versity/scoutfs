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
#include <linux/sort.h>
#include <linux/random.h>

#include "super.h"
#include "block.h"
#include "btree.h"
#include "trans.h"
#include "alloc.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * The core allocator uses extent items in btrees rooted in the super.
 * Each free extent is stored in two items.  The first item is indexed
 * by block location and is used to merge adjacent extents when freeing.
 * The second item is indexed by the order of the length and is used to
 * find large extents to allocate from.
 *
 * Free extent always consumes the front of the largest extent.  This
 * attempts to discourage fragmentation by given smaller freed extents
 * time for an adjacent free to merge before we attempt to re-use them.
 *
 * The metadata btrees that store extents are updated with cow.  This
 * requires allocation during extent item modification on behalf of
 * allocation.  Avoiding this recursion introduces the second structure,
 * persistent singly linked lists of individual blknos.
 *
 * The alloc lists are used for metadata allocation during a
 * transaction.  Before each transaction lists of blknos are prepared
 * for use during the transaction.  This ensures a small predictable
 * number of cows needed to fully dirty the metadata allocator
 * structures during the transaction.  As the transaction proceeds
 * allocations are made from a list of available meta blknos, and frees
 * are performed by adding blknos to another list of freed blknos.
 * After transactions these lists are merged back in to extents.
 *
 * Data allocations are performed directly on a btree of extent items,
 * with a bit of caching to stream small file data allocations from
 * memory instead of performing multiple btree calls per block
 * allocation.
 *
 * Every transaction has exclusive access to its metadata list blocks
 * and data extent trees which are prepared by the server.  For client
 * metadata and srch transactions the server moved extents and blocks
 * into persistent items that are communicated with the server.  For
 * server transactions metadata the server has to prepare structures for
 * itself.  To avoid modifying the same structure both explicitly
 * (refilling an allocator) and implicitly (using the current allocator
 * for cow allocations), it double buffers list blocks.  It uses current
 * blocks to modify the next blocks, and swaps them at each transaction.
 */

/*
 * Return the order of the length of a free extent, which we define as
 * floor(log_8_(len)): 0..7 = 0, 8..63 = 1, etc.
 */
static u64 free_extent_order(u64 len)
{
	return (fls64(len | 1) - 1) / 3;
}

/*
 * The smallest (non-zero) length that will be mapped to the same order
 * as the given length.
 */
static u64 smallest_order_length(u64 len)
{
	return 1ULL << (free_extent_order(len) * 3);
}

/*
 * Free extents don't have flags and are stored in two indexes sorted by
 * block location and by length order, largest first.  The location key
 * field is set to the final block in the extent so that we can find
 * intersections by calling _next() with the start of the range we're
 * searching for.
 *
 * We never store 0 length extents but we do build keys for searching
 * the order index from 0,0 without having to map it to a real extent.
 */
static void init_ext_key(struct scoutfs_key *key, int zone, u64 start, u64 len)
{
	*key = (struct scoutfs_key) {
		.sk_zone = zone,
	};

	if (len == 0) {
		/* we only use 0 len extents for magic 0,0 order lookups */
		WARN_ON_ONCE(zone != SCOUTFS_FREE_EXTENT_ORDER_ZONE || start != 0);
		return;
	}

	if (zone == SCOUTFS_FREE_EXTENT_BLKNO_ZONE) {
		key->skfb_end = cpu_to_le64(start + len - 1);
		key->skfb_len = cpu_to_le64(len);
	} else if (zone == SCOUTFS_FREE_EXTENT_ORDER_ZONE) {
		key->skfo_revord = cpu_to_le64(U64_MAX - free_extent_order(len));
		key->skfo_end = cpu_to_le64(start + len - 1);
		key->skfo_len = cpu_to_le64(len);
	} else {
		BUG();
	}
}

static void ext_from_key(struct scoutfs_extent *ext, struct scoutfs_key *key)
{
	if (key->sk_zone == SCOUTFS_FREE_EXTENT_BLKNO_ZONE) {
		ext->start = le64_to_cpu(key->skfb_end) -
			     le64_to_cpu(key->skfb_len) + 1;
		ext->len = le64_to_cpu(key->skfb_len);
	} else {
		ext->start = le64_to_cpu(key->skfo_end) -
			     le64_to_cpu(key->skfo_len) + 1;
		ext->len = le64_to_cpu(key->skfo_len);
	}
	ext->map = 0;
	ext->flags = 0;

	/* we never store 0 length extents */
	WARN_ON_ONCE(ext->len == 0);
}

struct alloc_ext_args {
	struct scoutfs_alloc *alloc;
	struct scoutfs_block_writer *wri;
	struct scoutfs_alloc_root *root;
	int zone;
};

static int alloc_ext_next(struct super_block *sb, void *arg,
			  u64 start, u64 len, struct scoutfs_extent *ext)
{
	struct alloc_ext_args *args = arg;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	init_ext_key(&key, args->zone, start, len);

	ret = scoutfs_btree_next(sb, &args->root->root, &key, &iref);
	if (ret == 0) {
		if (iref.val_len != 0)
			ret = -EIO;
		else if (iref.key->sk_zone != args->zone)
			ret = -ENOENT;
		else
			ext_from_key(ext, iref.key);
		scoutfs_btree_put_iref(&iref);
	}

	if (ret < 0)
		memset(ext, 0, sizeof(struct scoutfs_extent));

	return ret;
}

static int other_zone(int zone)
{
	if (zone == SCOUTFS_FREE_EXTENT_BLKNO_ZONE)
		return SCOUTFS_FREE_EXTENT_ORDER_ZONE;
	else if (zone == SCOUTFS_FREE_EXTENT_ORDER_ZONE)
		return SCOUTFS_FREE_EXTENT_BLKNO_ZONE;
	else
		BUG();
}

/*
 * Insert an extent along with its matching item which is indexed by
 * opposite of its order or blkno.  If we succeed we update the root's
 * record of the total length of all the stored extents.
 */
static int alloc_ext_insert(struct super_block *sb, void *arg,
			    u64 start, u64 len, u64 map, u8 flags)
{
	struct alloc_ext_args *args = arg;
	struct scoutfs_key other;
	struct scoutfs_key key;
	int ret;
	int err;

	/* allocator extents don't have mappings or flags */
	if (WARN_ON_ONCE(map || flags))
		return -EINVAL;

	init_ext_key(&key, args->zone, start, len);
	init_ext_key(&other, other_zone(args->zone), start, len);

	ret = scoutfs_btree_insert(sb, args->alloc, args->wri,
				   &args->root->root, &key, NULL, 0);
	if (ret == 0) {
		ret = scoutfs_btree_insert(sb, args->alloc, args->wri,
					   &args->root->root, &other, NULL, 0);
		if (ret < 0) {
			err = scoutfs_btree_delete(sb, args->alloc, args->wri,
						   &args->root->root, &key);
			BUG_ON(err);
		} else {
			le64_add_cpu(&args->root->total_len, len);
		}
	}

	return ret;
}

static int alloc_ext_remove(struct super_block *sb, void *arg,
			    u64 start, u64 len, u64 map, u8 flags)
{
	struct alloc_ext_args *args = arg;
	struct scoutfs_key other;
	struct scoutfs_key key;
	int ret;
	int err;

	init_ext_key(&key, args->zone, start, len);
	init_ext_key(&other, other_zone(args->zone), start, len);

	ret = scoutfs_btree_delete(sb, args->alloc, args->wri,
				   &args->root->root, &key);
	if (ret == 0) {
		ret = scoutfs_btree_delete(sb, args->alloc, args->wri,
					   &args->root->root, &other);
		if (ret < 0) {
			err = scoutfs_btree_insert(sb, args->alloc, args->wri,
						   &args->root->root, &key,
						   NULL, 0);
			BUG_ON(err);
		} else {
			le64_add_cpu(&args->root->total_len, -len);
		}
	}

	return ret;
}

static struct scoutfs_ext_ops alloc_ext_ops = {
	.next = alloc_ext_next,
	.insert = alloc_ext_insert,
	.remove = alloc_ext_remove,
};

static bool invalid_extent(u64 start, u64 end, u64 first, u64 last)
{
	return start > end || start < first || end > last;
}

static bool invalid_meta_blkno(struct super_block *sb, u64 blkno)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u64 last_meta = (i_size_read(sbi->meta_bdev->bd_inode) >> SCOUTFS_BLOCK_LG_SHIFT) - 1;

	return invalid_extent(blkno, blkno, SCOUTFS_META_DEV_START_BLKNO, last_meta);
}

static bool invalid_data_extent(struct super_block *sb, u64 start, u64 len)
{
	u64 last_data = (i_size_read(sb->s_bdev->bd_inode) >> SCOUTFS_BLOCK_SM_SHIFT) - 1;

	return invalid_extent(start, start + len - 1, SCOUTFS_DATA_DEV_START_BLKNO, last_data);
}

void scoutfs_alloc_init(struct scoutfs_alloc *alloc,
			struct scoutfs_alloc_list_head *avail,
			struct scoutfs_alloc_list_head *freed)
{
	memset(alloc, 0, sizeof(struct scoutfs_alloc));

	seqlock_init(&alloc->seqlock);
	mutex_init(&alloc->mutex);
	alloc->avail = *avail;
	alloc->freed = *freed;
}

/*
 * We're about to commit the transaction that used this allocator, drop
 * its block references.
 */
int scoutfs_alloc_prepare_commit(struct super_block *sb,
				 struct scoutfs_alloc *alloc,
				 struct scoutfs_block_writer *wri)
{
	scoutfs_block_put(sb, alloc->dirty_avail_bl);
	alloc->dirty_avail_bl = NULL;
	scoutfs_block_put(sb, alloc->dirty_freed_bl);
	alloc->dirty_freed_bl = NULL;

	return 0;
}

static u32 list_block_space(__le32 nr)
{
	return SCOUTFS_ALLOC_LIST_MAX_BLOCKS - le32_to_cpu(nr);
}

static u64 list_block_peek(struct scoutfs_alloc_list_block *lblk,
			   unsigned int skip)
{
	BUG_ON(skip >= le32_to_cpu(lblk->nr));

	return le64_to_cpu(lblk->blknos[le32_to_cpu(lblk->start) + skip]);
}

/*
 * Add a blkno to the array.  Typically we append of the array.  But we
 * can also prepend once there's no more room at the end.  Consumers of
 * the blocks sort before removing them.
 */
static void list_block_add(struct scoutfs_alloc_list_head *lhead,
			   struct scoutfs_alloc_list_block *lblk, u64 blkno)
{
	u32 start = le32_to_cpu(lblk->start);
	u32 nr = le32_to_cpu(lblk->nr);

	BUG_ON(lhead->ref.blkno != lblk->hdr.blkno);
	BUG_ON(list_block_space(lblk->nr) == 0);

	if (start + nr < SCOUTFS_ALLOC_LIST_MAX_BLOCKS) {
		lblk->blknos[start + nr] = cpu_to_le64(blkno);
	} else {
		start--;
		lblk->blknos[start] = cpu_to_le64(blkno);
		lblk->start = cpu_to_le32(start);
	}

	le32_add_cpu(&lblk->nr, 1);
	le64_add_cpu(&lhead->total_nr, 1);
	le32_add_cpu(&lhead->first_nr, 1);
}

/*
 * Remove blknos from the start of the array.
 */
static void list_block_remove(struct scoutfs_alloc_list_head *lhead,
			      struct scoutfs_alloc_list_block *lblk,
			      unsigned int count)
{
	BUG_ON(lhead->ref.blkno != lblk->hdr.blkno);
	BUG_ON(count > SCOUTFS_ALLOC_LIST_MAX_BLOCKS);
	BUG_ON(le32_to_cpu(lblk->nr) < count);

	le32_add_cpu(&lblk->nr, -count);
	if (lblk->nr == 0)
		lblk->start = 0;
	else
		le32_add_cpu(&lblk->start, count);
	le64_add_cpu(&lhead->total_nr, -(u64)count);
	le32_add_cpu(&lhead->first_nr, -count);
}

static int cmp_le64(const void *A, const void *B)
{
	const __le64 *a = A;
	const __le64 *b = B;

	return scoutfs_cmp_u64s(le64_to_cpu(*a), le64_to_cpu(*b));
}

static void swap_le64(void *A, void *B, int size)
{
	__le64 *a = A;
	__le64 *b = B;

	swap(*a, *b);
}

static void list_block_sort(struct scoutfs_alloc_list_block *lblk)
{
	sort(&lblk->blknos[le32_to_cpu(lblk->start)], le32_to_cpu(lblk->nr),
			   sizeof(lblk->blknos[0]), cmp_le64, swap_le64);
}

/*
 * We're always reading blocks that we own, so we shouldn't see stale
 * references but we could retry reads after dropping stale cached
 * blocks.  If we do see a stale error then we've hit persistent
 * corruption.
 */
static int read_list_block(struct super_block *sb, struct scoutfs_block_ref *ref,
			   struct scoutfs_block **bl_ret)
{
	int ret;

	ret = scoutfs_block_read_ref(sb, ref, SCOUTFS_BLOCK_MAGIC_ALLOC_LIST, bl_ret);
	if (ret < 0) {
		if (ret == -ESTALE) {
			scoutfs_inc_counter(sb, alloc_stale_list_block);
			ret = -EIO;
		}
	};

	return ret;
}

/*
 * Give the caller a dirty list block, always allocating a new block if
 * the ref is empty.
 *
 * If the caller gives us an allocated blkno for the cow then we know
 * that they're taking care of allocating and freeing the blknos, if not
 * we call meta alloc and free.
 */
static int dirty_list_block(struct super_block *sb,
			    struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_block_ref *ref,
			    u64 dirty, u64 *old,
			    struct scoutfs_block **bl_ret)
{
	return scoutfs_block_dirty_ref(sb, alloc, wri, ref, SCOUTFS_BLOCK_MAGIC_ALLOC_LIST,
				       bl_ret, dirty, old);
}

/* Allocate a new dirty list block if we fill up more than 3/4 of the block. */
#define EMPTY_FREED_THRESH	(SCOUTFS_ALLOC_LIST_MAX_BLOCKS / 4)

/*
 * Get dirty avail and freed list blocks that will be used for meta
 * allocations during our transaction.  We peek at the next avail blknos
 * for the cow allocations and manually record the cow frees rather than
 * recursively calling into alloc_meta and free_meta.
 *
 * In the client the server will have emptied the freed list so it will
 * always allocate a new first empty block for frees.  But in the server
 * it might have long lists of frees that it's trying to merge in to
 * extents over multiple transactions.  If the head of the freed list
 * doesn't have room we add a new empty block.
 */
static int dirty_alloc_blocks(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri)
{
	struct scoutfs_block_ref orig_freed;
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block *av_bl = NULL;
	struct scoutfs_block *fr_bl = NULL;
	struct scoutfs_block *bl;
	bool link_orig = false;
	u64 av_peek;
	u64 av_old;
	u64 fr_peek;
	u64 fr_old;
	int ret;

	if (alloc->dirty_avail_bl != NULL)
		return 0;

	mutex_lock(&alloc->mutex);

	/* undo dirty freed if we get an error after */
	orig_freed = alloc->freed.ref;

	if (alloc->dirty_avail_bl != NULL) {
		ret = 0;
		goto out;
	}

	/* caller must ensure that transactions commit before running out */
	if (WARN_ON_ONCE(alloc->avail.ref.blkno == 0) ||
	    WARN_ON_ONCE(le32_to_cpu(alloc->avail.first_nr) < 2)) {
		ret = -ENOSPC;
		goto out;
	}

	ret = read_list_block(sb, &alloc->avail.ref, &bl);
	if (ret < 0)
		goto out;

	lblk = bl->data;
	av_peek = list_block_peek(lblk, 0);
	fr_peek = list_block_peek(lblk, 1);
	scoutfs_block_put(sb, bl);
	lblk = NULL;

	if (alloc->freed.ref.blkno &&
	    list_block_space(alloc->freed.first_nr) < EMPTY_FREED_THRESH) {
		/* zero ref to force alloc of new block... */
		memset(&alloc->freed.ref, 0, sizeof(alloc->freed.ref));
		alloc->freed.first_nr = 0;
		link_orig = true;
	}

	/* dirty the first free block */
	ret = dirty_list_block(sb, alloc, wri, &alloc->freed.ref,
			       fr_peek, &fr_old, &fr_bl);
	if (ret < 0)
		goto out;

	if (link_orig) {
		/* .. and point the new block at the rest of the list */
		lblk = fr_bl->data;
		lblk->next = orig_freed;
		lblk = NULL;
	}

	ret = dirty_list_block(sb, alloc, wri, &alloc->avail.ref,
			       av_peek, &av_old, &av_bl);
	if (ret < 0)
		goto out;

	list_block_remove(&alloc->avail, av_bl->data, 2);
	/* sort dirty avail to encourage contiguous sorted meta blocks */
	list_block_sort(av_bl->data);

	if (av_old)
		list_block_add(&alloc->freed, fr_bl->data, av_old);
	if (fr_old)
		list_block_add(&alloc->freed, fr_bl->data, fr_old);

	alloc->dirty_avail_bl = av_bl;
	av_bl = NULL;
	alloc->dirty_freed_bl = fr_bl;
	fr_bl = NULL;
	ret = 0;

out:
	if (ret < 0 && alloc->freed.ref.blkno != orig_freed.blkno) {
		if (fr_bl)
			scoutfs_block_writer_forget(sb, wri, fr_bl);
		alloc->freed.ref = orig_freed;
	}

	mutex_unlock(&alloc->mutex);
	scoutfs_block_put(sb, av_bl);
	scoutfs_block_put(sb, fr_bl);
	return ret;
}

/*
 * Alloc a metadata block for a transaction in either the client or the
 * server.  The list block in the allocator was prepared for the transaction.
 */
int scoutfs_alloc_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri, u64 *blkno)
{
	struct scoutfs_alloc_list_block *lblk;
	int ret;

	ret = dirty_alloc_blocks(sb, alloc, wri);
	if (ret < 0)
		goto out;

	write_seqlock(&alloc->seqlock);

	lblk = alloc->dirty_avail_bl->data;
	if (WARN_ON_ONCE(lblk->nr == 0)) {
		/* shouldn't happen, transaction should commit first */
		ret = -ENOSPC;
	} else {
		*blkno = list_block_peek(lblk, 0);
		list_block_remove(&alloc->avail, lblk, 1);
		ret = 0;
	}

	write_sequnlock(&alloc->seqlock);

out:
	if (ret < 0)
		*blkno = 0;
	scoutfs_inc_counter(sb, alloc_alloc_meta);
	trace_scoutfs_alloc_alloc_meta(sb, *blkno, ret);
	return ret;
}

int scoutfs_free_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri, u64 blkno)
{
	struct scoutfs_alloc_list_block *lblk;
	int ret;

	if (WARN_ON_ONCE(invalid_meta_blkno(sb, blkno)))
		return -EINVAL;

	ret = dirty_alloc_blocks(sb, alloc, wri);
	if (ret < 0)
		goto out;

	write_seqlock(&alloc->seqlock);

	lblk = alloc->dirty_freed_bl->data;
	if (WARN_ON_ONCE(list_block_space(lblk->nr) == 0)) {
		/* shouldn't happen, transaction should commit first */
		ret = -EIO;
	} else {
		list_block_add(&alloc->freed, lblk, blkno);
		ret = 0;
	}

	write_sequnlock(&alloc->seqlock);

out:
	scoutfs_inc_counter(sb, alloc_free_meta);
	trace_scoutfs_alloc_free_meta(sb, blkno, ret);
	return ret;
}

void scoutfs_dalloc_init(struct scoutfs_data_alloc *dalloc,
			 struct scoutfs_alloc_root *data_avail)
{
	dalloc->root = *data_avail;
	memset(&dalloc->cached, 0, sizeof(dalloc->cached));
	atomic64_set(&dalloc->total_len, le64_to_cpu(dalloc->root.total_len));
}

void scoutfs_dalloc_get_root(struct scoutfs_data_alloc *dalloc,
			     struct scoutfs_alloc_root *data_avail)
{
	*data_avail = dalloc->root;
}

static void dalloc_update_total_len(struct scoutfs_data_alloc *dalloc)
{
	atomic64_set(&dalloc->total_len, le64_to_cpu(dalloc->root.total_len) +
		     dalloc->cached.len);
}

u64 scoutfs_dalloc_total_len(struct scoutfs_data_alloc *dalloc)
{
	return atomic64_read(&dalloc->total_len);
}

/*
 * Return the current in-memory cached free extent to extent items in
 * the avail root.  This should be locked by the caller just like
 * _alloc_data and _free_data.
 */
int scoutfs_dalloc_return_cached(struct super_block *sb,
				 struct scoutfs_alloc *alloc,
				 struct scoutfs_block_writer *wri,
				 struct scoutfs_data_alloc *dalloc)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = &dalloc->root,
		.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE,
	};
	int ret = 0;

	if (dalloc->cached.len) {
		ret = scoutfs_ext_insert(sb, &alloc_ext_ops, &args,
					 dalloc->cached.start,
					 dalloc->cached.len, 0, 0);
		if (ret == 0)
			memset(&dalloc->cached, 0, sizeof(dalloc->cached));
	}

	return ret;
}

/*
 * Allocate a data extent.  An extent that's smaller than the requested
 * size can be returned.
 *
 * The caller can provide a cached extent that can satisfy allocations
 * and will be refilled by allocations.  The caller is responsible for
 * freeing any remaining cached extent back into persistent items before
 * committing.
 *
 * Unlike meta allocations, the caller is expected to serialize
 * allocations from the root.
 *
 * ENOBUFS is returned if the data allocator ran out of space and we can
 * probably refill it from the server.  The caller is expected to back
 * out, commit the transaction, and try again.
 *
 * ENOSPC is returned if the data allocator ran out of space but we have
 * a flag from the server telling us that there's no more space
 * available.  This is a hard error and should be returned.
 */
int scoutfs_alloc_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_data_alloc *dalloc, u64 count,
		       u64 *blkno_ret, u64 *count_ret)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = &dalloc->root,
		.zone = SCOUTFS_FREE_EXTENT_ORDER_ZONE,
	};
	struct scoutfs_extent ext;
	u64 len;
	int ret;

	/* large allocations come straight from the allocator */
	if (count >= SCOUTFS_ALLOC_DATA_LG_THRESH) {
		ret = scoutfs_ext_alloc(sb, &alloc_ext_ops, &args,
					0, 0, count, &ext);
		if (ret < 0)
			goto out;

		*blkno_ret = ext.start;
		*count_ret = ext.len;
		ret = 0;
		goto out;
	}

	/* smaller allocations come from a cached extent */
	if (dalloc->cached.len == 0) {
		ret = scoutfs_ext_alloc(sb, &alloc_ext_ops, &args, 0, 0,
					SCOUTFS_ALLOC_DATA_LG_THRESH,
					&dalloc->cached);
		if (ret < 0)
			goto out;
	}

	len = min(count, dalloc->cached.len);

	*blkno_ret = dalloc->cached.start;
	*count_ret = len;

	dalloc->cached.start += len;
	dalloc->cached.len -= len;
	ret = 0;
out:
	if (ret < 0) {
		if (ret == -ENOENT) {
			if (le32_to_cpu(dalloc->root.flags) & SCOUTFS_ALLOC_FLAG_LOW)
				ret = -ENOSPC;
			else
				ret = -ENOBUFS;
		}

		*blkno_ret = 0;
		*count_ret = 0;
	} else {
		dalloc_update_total_len(dalloc);
	}

	scoutfs_inc_counter(sb, alloc_alloc_data);
	trace_scoutfs_alloc_alloc_data(sb, count, *blkno_ret, *count_ret, ret);
	return ret;
}

/*
 * Free data extents into the freed tree that will be reclaimed by the
 * server and made available for future allocators only if our
 * transaction succeeds.  We don't want to overwrite existing data if
 * our transaction fails.
 *
 * Unlike meta allocations, the caller is expected to serialize data
 * allocations.
 */
int scoutfs_free_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_alloc_root *root, u64 blkno, u64 count)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE,
	};
	int ret;

	if (WARN_ON_ONCE(invalid_data_extent(sb, blkno, count)))
		return -EINVAL;

	ret = scoutfs_ext_insert(sb, &alloc_ext_ops, &args, blkno, count, 0, 0);
	scoutfs_inc_counter(sb, alloc_free_data);
	trace_scoutfs_alloc_free_data(sb, blkno, count, ret);
	return ret;
}

/*
 * Return the first zone bit that the extent intersects with.
 */
static int first_extent_zone(struct scoutfs_extent *ext,  __le64 *zones, u64 zone_blocks)
{
	int first;
	int last;
	int nr;

	first = div64_u64(ext->start, zone_blocks);
	last = div64_u64(ext->start + ext->len - 1, zone_blocks);

	nr = find_next_bit_le(zones, SCOUTFS_DATA_ALLOC_MAX_ZONES, first);
	if (nr <= last)
		return nr;

	return SCOUTFS_DATA_ALLOC_MAX_ZONES;
}

/*
 * Find an extent in specific zones to satisfy an allocation.  We use
 * the order items to search for the largest extent that intersects with
 * the zones whose bits are set in the caller's bitmap.
 */
static int find_zone_extent(struct super_block *sb, struct scoutfs_alloc_root *root,
			    __le64 *zones, u64 zone_blocks,
			    struct scoutfs_extent *found_ret, u64 count,
			    struct scoutfs_extent *ext_ret)
{
	struct alloc_ext_args args = {
		.root = root,
		.zone = SCOUTFS_FREE_EXTENT_ORDER_ZONE,
	};
	struct scoutfs_extent found;
	struct scoutfs_extent ext;
	u64 start;
	u64 len;
	int nr;
	int ret;

	/* don't bother when there are no bits set */
	if (find_next_bit_le(zones, SCOUTFS_DATA_ALLOC_MAX_ZONES, 0) ==
	    SCOUTFS_DATA_ALLOC_MAX_ZONES)
		return -ENOENT;

	/* start searching for largest extent from the first zone */
	len = smallest_order_length(SCOUTFS_BLOCK_SM_MAX);
	nr = 0;

	for (;;) {
		/* search for extents in the next zone at our order */
		nr = find_next_bit_le(zones, SCOUTFS_DATA_ALLOC_MAX_ZONES, nr);
		if (nr >= SCOUTFS_DATA_ALLOC_MAX_ZONES) {
			/* wrap down to next smaller order if we run out of bits */
			len >>= 3;
			if (len == 0) {
				ret = -ENOENT;
				break;
			}
			nr = find_next_bit_le(zones, SCOUTFS_DATA_ALLOC_MAX_ZONES, 0);
		}

		start = (u64)nr * zone_blocks;

		ret = scoutfs_ext_next(sb, &alloc_ext_ops, &args, start, len, &found);
		if (ret < 0)
			break;

		/* see if the next extent intersects any zones */
		nr = first_extent_zone(&found, zones, zone_blocks);
		if (nr < SCOUTFS_DATA_ALLOC_MAX_ZONES) {
			start = (u64)nr * zone_blocks;

			ext.start = max(start, found.start);
			ext.len = min(count, found.start + found.len - ext.start);

			*found_ret = found;
			*ext_ret = ext;
			ret = 0;
			break;
		}

		/* continue searching past extent */
		nr = div64_u64(found.start + found.len - 1, zone_blocks) + 1;
		len = smallest_order_length(found.len);
	}

	return ret;
}

/*
 * Move extent items adding up to the requested total length from the
 * src to the dst tree.  The caller is responsible for locking the
 * trees, usually because they're also looking at total_len to decide
 * how much to move.
 *
 * -ENOENT is returned if we run out of extents in the source tree
 * before moving the total.
 *
 * The caller can specify that extents in the source tree should first
 * be found based on their zone bitmaps.  We'll first try to find
 * extents in the exclusive zones, then vacant zones, and then we'll
 * fall back to normal allocation that ignores zones.
 *
 * This first pass is not optimal because it performs full btree walks
 * per extent.  We could optimize this with more clever btree item
 * manipulation functions which can iterate through src and dst blocks
 * and let callbacks indicate how to change items.
 */
int scoutfs_alloc_move(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_alloc_root *dst,
		       struct scoutfs_alloc_root *src, u64 total,
		       __le64 *exclusive, __le64 *vacant, u64 zone_blocks)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
	};
	struct scoutfs_extent found;
	struct scoutfs_extent ext;
	u64 moved = 0;
	u64 count;
	int ret = 0;
	int err;

	if (zone_blocks == 0) {
		exclusive = NULL;
		vacant = NULL;
	}

	while (moved < total) {
		count = total - moved;

		if (exclusive) {
			/* first try to find extents in our exclusive zones */
			ret = find_zone_extent(sb, src, exclusive, zone_blocks,
					       &found, count, &ext);
			if (ret == -ENOENT) {
				exclusive = NULL;
				continue;
			}
		} else if (vacant) {
			/* then try to find extents in vacant zones */
			ret = find_zone_extent(sb, src, vacant, zone_blocks,
					       &found, count, &ext);
			if (ret == -ENOENT) {
				vacant = NULL;
				continue;
			}
		} else {
			/* otherwise fall back to finding extents anywhere */
			args.root = src;
			args.zone = SCOUTFS_FREE_EXTENT_ORDER_ZONE;
			ret = scoutfs_ext_next(sb, &alloc_ext_ops, &args, 0, 0, &found);
			if (ret == 0) {
				ext.start = found.start;
				ext.len = min(count, found.len);
			}
		}
		if (ret < 0)
			break;

		/* searching set start/len, finish initializing alloced extent */
		ext.map = found.map ? ext.start - found.start + found.map : 0;
		ext.flags = found.flags;

		/* remove the allocation from the found extent */
		args.root = src;
		args.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE;
		ret = scoutfs_ext_remove(sb, &alloc_ext_ops, &args, ext.start, ext.len);
		if (ret < 0)
			break;

		/* insert the allocated extent into the dest */
		args.root = dst;
		args.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE;
		ret = scoutfs_ext_insert(sb, &alloc_ext_ops, &args, ext.start,
					 ext.len, ext.map, ext.flags);
		if (ret < 0) {
			/* and put it back in src if insertion failed */
			args.root = src;
			args.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE;
			err = scoutfs_ext_insert(sb, &alloc_ext_ops, &args,
						 ext.start, ext.len, ext.map,
						 ext.flags);
			BUG_ON(err); /* inconsistent */
			break;
		}

		moved += ext.len;
		scoutfs_inc_counter(sb, alloc_moved_extent);
	}

	scoutfs_inc_counter(sb, alloc_move);
	trace_scoutfs_alloc_move(sb, total, moved, ret);

	return ret;
}

/*
 * Add new free space to an allocator.  _ext_insert will make sure that it doesn't
 * overlap with any existing extents.  This is done by the server in a transaction that
 * also updates total_*_blocks in the super so we don't verify.
 */
int scoutfs_alloc_insert(struct super_block *sb, struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri, struct scoutfs_alloc_root *root,
			 u64 start, u64 len)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE,
	};

	return scoutfs_ext_insert(sb, &alloc_ext_ops, &args, start, len, 0, 0);
}

int scoutfs_alloc_remove(struct super_block *sb, struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri, struct scoutfs_alloc_root *root,
			 u64 start, u64 len)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE,
	};

	return scoutfs_ext_remove(sb, &alloc_ext_ops, &args, start, len);
}

/*
 * We only trim one block, instead of looping trimming all, because the
 * caller is assuming that we do a fixed amount of work when they check
 * that their allocator has enough remaining free blocks for us.
 */
static int trim_empty_first_block(struct super_block *sb,
				  struct scoutfs_alloc *alloc,
				  struct scoutfs_block_writer *wri,
				  struct scoutfs_alloc_list_head *lhead)
{
	struct scoutfs_alloc_list_block *one = NULL;
	struct scoutfs_alloc_list_block *two = NULL;
	struct scoutfs_block *one_bl = NULL;
	struct scoutfs_block *two_bl = NULL;
	int ret;

	if (WARN_ON_ONCE(lhead->ref.blkno == 0) ||
	    WARN_ON_ONCE(lhead->first_nr != 0))
		return 0;

	ret = read_list_block(sb, &lhead->ref, &one_bl);
	if (ret < 0)
		goto out;
	one = one_bl->data;

	if (one->next.blkno) {
		ret = read_list_block(sb, &one->next, &two_bl);
		if (ret < 0)
			goto out;
		two = two_bl->data;
	}

	ret = scoutfs_free_meta(sb, alloc, wri, le64_to_cpu(lhead->ref.blkno));
	if (ret < 0)
		goto out;

	lhead->ref = one->next;
	lhead->first_nr = two ? two->nr : 0;
	ret = 0;
out:
	scoutfs_block_put(sb, one_bl);
	scoutfs_block_put(sb, two_bl);
	return ret;
}

/*
 * True if the allocator has enough blocks in the avail list and space
 * in the freed list to be able to perform the callers operations.  If
 * false the caller should back off and return partial progress rather
 * than completely exhausting the avail list or overflowing the freed
 * list.
 *
 * An extent modification dirties three distinct leaves of an allocator
 * btree as it adds and removes the blkno and size sorted items for the
 * old and new lengths of the extent.  Dirtying the paths to these
 * leaves can grow the tree and grow/shrink neighbours at each level.
 * We over-estimate the number of blocks allocated and freed (the paths
 * share a root, growth doesn't free) to err on the simpler and safer
 * side.  The overhead is minimal given the relatively large list blocks
 * and relatively short allocator trees.
 *
 * The caller tells us how many extents they're about to modify and how
 * many other additional blocks they may cow manually.  And finally, the
 * caller could be the first to dirty the avail and freed blocks in the
 * allocator,
 */
static bool list_has_blocks(struct super_block *sb, struct scoutfs_alloc *alloc,
			    struct scoutfs_alloc_root *root, u32 extents, u32 addl_blocks)
{
	u32 tree_blocks = (((1 + root->root.height) * 2) * 3) * extents;
	u32 most = 1 + tree_blocks + addl_blocks;

	if (le32_to_cpu(alloc->avail.first_nr) < most) {
		scoutfs_inc_counter(sb, alloc_list_avail_lo);
		return false;
	}

	if (list_block_space(alloc->freed.first_nr) < most) {
		scoutfs_inc_counter(sb, alloc_list_freed_hi);
		return false;
	}

	return true;
}

static bool lhead_in_alloc(struct scoutfs_alloc *alloc,
			   struct scoutfs_alloc_list_head *lhead)
{
	return lhead == &alloc->avail || lhead == &alloc->freed;
}

/*
 * Move free blocks from extent items in the root into only the first
 * block in the list towards the target if it's fallen below the lo
 * threshold.  This can return success without necessarily moving as
 * much as was requested if its meta allocator runs low, the caller is
 * expected to check the counts and act accordingly.
 *
 * -ENOSPC is returned if the root runs out of extents before the list
 * reaches the target.
 */
int scoutfs_alloc_fill_list(struct super_block *sb,
			    struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_alloc_list_head *lhead,
			    struct scoutfs_alloc_root *root,
			    u64 lo, u64 target)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.zone = SCOUTFS_FREE_EXTENT_ORDER_ZONE,
	};
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_extent ext;
	int ret = 0;
	int i;

	if (WARN_ON_ONCE(target < lo) ||
	    WARN_ON_ONCE(lo > SCOUTFS_ALLOC_LIST_MAX_BLOCKS) ||
	    WARN_ON_ONCE(target > SCOUTFS_ALLOC_LIST_MAX_BLOCKS) ||
	    WARN_ON_ONCE(lhead_in_alloc(alloc, lhead)))
		return -EINVAL;

	if (le32_to_cpu(lhead->first_nr) >= lo)
		return 0;

	ret = dirty_list_block(sb, alloc, wri, &lhead->ref, 0, NULL, &bl);
	if (ret < 0)
		goto out;
	lblk = bl->data;

	while (le32_to_cpu(lblk->nr) < target && list_has_blocks(sb, alloc, root, 1, 0)) {

		ret = scoutfs_ext_alloc(sb, &alloc_ext_ops, &args, 0, 0,
					target - le32_to_cpu(lblk->nr), &ext);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = -ENOSPC;
			break;
		}

		for (i = 0; i < ext.len; i++)
			list_block_add(lhead, lblk, ext.start + i);
	}

out:
	scoutfs_block_put(sb, bl);
	return ret;
}

/*
 * Move blknos from all the blocks in the list into extents in the root,
 * removing empty blocks as we go.  This can return success and leave blocks
 * on the list if its metadata alloc runs out of space.
 */
int scoutfs_alloc_empty_list(struct super_block *sb,
			     struct scoutfs_alloc *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_alloc_root *root,
			     struct scoutfs_alloc_list_head *lhead)
{
	struct alloc_ext_args args = {
		.alloc = alloc,
		.wri = wri,
		.root = root,
		.zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE,
	};
	struct scoutfs_alloc_list_block *lblk = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_extent ext;
	int ret = 0;

	if (WARN_ON_ONCE(lhead_in_alloc(alloc, lhead)))
		return -EINVAL;

	while (lhead->ref.blkno && list_has_blocks(sb, alloc, args.root, 1, 1)) {

		if (lhead->first_nr == 0) {
			ret = trim_empty_first_block(sb, alloc, wri, lhead);
			if (ret < 0)
				break;

			scoutfs_block_put(sb, bl);
			bl = NULL;
			continue;
		}

		if (bl == NULL) {
			ret = dirty_list_block(sb, alloc, wri, &lhead->ref,
					       0, NULL, &bl);
			if (ret < 0)
				break;
			lblk = bl->data;

			/* sort to encourage forming extents */
			list_block_sort(lblk);
		}

		/* combine free blknos into extents and insert them */
		ext.start = list_block_peek(lblk, 0);
		ext.len = 1;
		while ((le32_to_cpu(lblk->nr) > ext.len) &&
		       (list_block_peek(lblk, ext.len) == ext.start + ext.len))
			ext.len++;

		ret = scoutfs_ext_insert(sb, &alloc_ext_ops, &args,
					 ext.start, ext.len, 0, 0);
		if (ret < 0)
			break;

		list_block_remove(lhead, lblk, ext.len);
	}

	scoutfs_block_put(sb, bl);

	return ret;
}

/*
 * Insert the source list at the head of the destination list, leaving
 * the source empty.
 *
 * This looks bad because the lists are singly-linked and we have to cow
 * the entire src lsit to update its tail block next ref to the start of
 * the dst list.
 *
 * In practice, this isn't a problem because the server only calls this
 * with small lists that it's going to use soon.
 */
int scoutfs_alloc_splice_list(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_alloc_list_head *dst,
			      struct scoutfs_alloc_list_head *src)
{
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block_ref *ref;
	struct scoutfs_block *prev = NULL;
	struct scoutfs_block *bl = NULL;
	int ret = 0;

	if (WARN_ON_ONCE(lhead_in_alloc(alloc, dst)) ||
	    WARN_ON_ONCE(lhead_in_alloc(alloc, src)))
		return -EINVAL;

	if (src->ref.blkno == 0)
		return 0;

	ref = &src->ref;
	while (ref->blkno) {
		ret = dirty_list_block(sb, alloc, wri, ref, 0, NULL, &bl);
		if (ret < 0)
			goto out;

		lblk = bl->data;
		ref = &lblk->next;

		scoutfs_block_put(sb, prev);
		prev = bl;
		bl = NULL;
	}

	*ref = dst->ref;
	dst->ref = src->ref;
	dst->first_nr = src->first_nr;
	le64_add_cpu(&dst->total_nr, le64_to_cpu(src->total_nr));

	memset(src, 0, sizeof(struct scoutfs_alloc_list_head));
	ret = 0;
out:
	scoutfs_block_put(sb, prev);
	scoutfs_block_put(sb, bl);
	return ret;
}

/*
 * Returns true if meta avail and free don't have room for the given
 * number of allocations or frees.  This is called at a significantly
 * higher frequency than allocations as writers try to enter
 * transactions.  This is the only reader of the seqlock which gives
 * read-mostly sampling instead of bouncing a spinlock around all the
 * cores.
 */
bool scoutfs_alloc_meta_low(struct super_block *sb,
			    struct scoutfs_alloc *alloc, u32 nr)
{
	unsigned int seq;
	bool lo;

	do {
		seq = read_seqbegin(&alloc->seqlock);
		lo = le32_to_cpu(alloc->avail.first_nr) < nr ||
		     list_block_space(alloc->freed.first_nr) < nr;
	} while (read_seqretry(&alloc->seqlock, seq));

	return lo;
}

bool scoutfs_alloc_test_flag(struct super_block *sb,
			    struct scoutfs_alloc *alloc, u32 flag)
{
	unsigned int seq;
	bool set;

	do {
		seq = read_seqbegin(&alloc->seqlock);
		set = !!(le32_to_cpu(alloc->avail.flags) & flag);
	} while (read_seqretry(&alloc->seqlock, seq));

	return set;
}

/*
 * Call the callers callback for every persistent allocator structure
 * we can find.
 */
int scoutfs_alloc_foreach(struct super_block *sb,
			  scoutfs_alloc_foreach_cb_t cb, void *arg)
{
	struct scoutfs_block_ref stale_refs[2] = {{0,}};
	struct scoutfs_block_ref refs[2] = {{0,}};
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_srch_compact *sc;
	struct scoutfs_log_merge_request *lmreq;
	struct scoutfs_log_merge_complete *lmcomp;
	struct scoutfs_log_trees lt;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int expected;
	u64 avail_tot;
	u64 freed_tot;
	u64 id;
	int ret;

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	sc = kmalloc(sizeof(struct scoutfs_srch_compact), GFP_NOFS);
	if (!super || !sc) {
		ret = -ENOMEM;
		goto out;
	}

retry:
	ret = scoutfs_read_super(sb, super);
	if (ret < 0)
		goto out;

	refs[0] = super->logs_root.ref;
	refs[1] = super->srch_root.ref;

	/* all the server allocators */
	ret = cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 0, true, true,
		 le64_to_cpu(super->meta_alloc[0].total_len)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 0, true, true,
		 le64_to_cpu(super->meta_alloc[1].total_len)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 0, false, true,
		 le64_to_cpu(super->data_alloc.total_len)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, true,
		 le64_to_cpu(super->server_meta_avail[0].total_nr)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, true,
		 le64_to_cpu(super->server_meta_avail[1].total_nr)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, false,
		 le64_to_cpu(super->server_meta_freed[0].total_nr)) ?:
	      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SERVER, 1, true, false,
		 le64_to_cpu(super->server_meta_freed[1].total_nr));
	if (ret < 0)
		goto out;

	/* mount fs transaction allocators */
	scoutfs_key_init_log_trees(&key, 0, 0);
	for (;;) {
		ret = scoutfs_btree_next(sb, &super->logs_root, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret < 0)
			goto out;

		if (iref.val_len == sizeof(lt)) {
			key = *iref.key;
			memcpy(&lt, iref.val, sizeof(lt));
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
		if (ret < 0)
			goto out;

		ret = cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), true, true,
			 le64_to_cpu(lt.meta_avail.total_nr)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), true, false,
			 le64_to_cpu(lt.meta_freed.total_nr)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), false, true,
			 le64_to_cpu(lt.data_avail.total_len)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_MOUNT,
			 le64_to_cpu(key.sklt_rid), false, false,
			 le64_to_cpu(lt.data_freed.total_len));
		if (ret < 0)
			goto out;

		scoutfs_key_inc(&key);
	}

	/* srch compaction allocators */
	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_SRCH_ZONE;
	key.sk_type = SCOUTFS_SRCH_PENDING_TYPE;

	for (;;) {
		/* _PENDING_ and _BUSY_ are last, _next won't see other types */
		ret = scoutfs_btree_next(sb, &super->srch_root, &key, &iref);
		if (ret == -ENOENT)
			break;
		if (ret == 0) {
			if (iref.val_len == sizeof(*sc)) {
				key = *iref.key;
				memcpy(sc, iref.val, iref.val_len);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0)
			goto out;

		ret = cb(sb, arg, SCOUTFS_ALLOC_OWNER_SRCH,
			 le64_to_cpu(sc->id), true, true,
			 le64_to_cpu(sc->meta_avail.total_nr)) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_SRCH,
			 le64_to_cpu(sc->id), true, false,
			 le64_to_cpu(sc->meta_freed.total_nr));
		if (ret < 0)
			goto out;

		scoutfs_key_inc(&key);
	}

	/* log merge allocators */
	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_LOG_MERGE_REQUEST_ZONE;
	expected = sizeof(*lmreq);
	id = 0;
	avail_tot = 0;
	freed_tot = 0;

	for (;;) {
		ret = scoutfs_btree_next(sb, &super->log_merge, &key, &iref);
		if (ret == 0) {
			if (iref.key->sk_zone != key.sk_zone) {
				ret = -ENOENT;
			} else if (iref.val_len == expected) {
				key = *iref.key;
				if (key.sk_zone == SCOUTFS_LOG_MERGE_REQUEST_ZONE) {
					lmreq = iref.val;
					id = le64_to_cpu(lmreq->rid);
					avail_tot = le64_to_cpu(lmreq->meta_avail.total_nr);
					freed_tot = le64_to_cpu(lmreq->meta_freed.total_nr);
				} else {
					lmcomp = iref.val;
					id = le64_to_cpu(lmcomp->rid);
					avail_tot = le64_to_cpu(lmcomp->meta_avail.total_nr);
					freed_tot = le64_to_cpu(lmcomp->meta_freed.total_nr);
				}
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret == -ENOENT) {
			if (key.sk_zone == SCOUTFS_LOG_MERGE_REQUEST_ZONE) {
				memset(&key, 0, sizeof(key));
				key.sk_zone = SCOUTFS_LOG_MERGE_COMPLETE_ZONE;
				expected = sizeof(*lmcomp);
				continue;
			}
			break;
		}
		if (ret < 0)
			goto out;

		ret = cb(sb, arg, SCOUTFS_ALLOC_OWNER_LOG_MERGE, id, true, true, avail_tot) ?:
		      cb(sb, arg, SCOUTFS_ALLOC_OWNER_LOG_MERGE, id, true, false, freed_tot);
		if (ret < 0)
			goto out;

		scoutfs_key_inc(&key);
	}

	ret = 0;
out:
	if (ret == -ESTALE) {
		if (memcmp(&stale_refs, &refs, sizeof(refs)) == 0) {
			ret = -EIO;
		} else {
			BUILD_BUG_ON(sizeof(stale_refs) != sizeof(refs));
			memcpy(stale_refs, refs, sizeof(stale_refs));
			goto retry;
		}
	}

	kfree(super);
	kfree(sc);
	return ret;
}


struct foreach_cb_args {
	scoutfs_alloc_extent_cb_t cb;
	void *cb_arg;
};

static int alloc_btree_extent_item_cb(struct super_block *sb, struct scoutfs_key *key,
				      void *val, int val_len, void *arg)
{
	struct foreach_cb_args *cba = arg;
	struct scoutfs_extent ext;

	if (key->sk_zone != SCOUTFS_FREE_EXTENT_BLKNO_ZONE)
		return -ENOENT;

	ext_from_key(&ext, key);
	cba->cb(sb, cba->cb_arg, &ext);

	return 0;
}

/*
 * Call the caller's callback on each extent stored in the allocator's
 * btree.  The callback sees extents called in order by starting blkno.
 */
int scoutfs_alloc_extents_cb(struct super_block *sb, struct scoutfs_alloc_root *root,
			     scoutfs_alloc_extent_cb_t cb, void *cb_arg)
{
	struct foreach_cb_args cba = {
		.cb = cb,
		.cb_arg = cb_arg,
	};
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct scoutfs_key key;
	int ret;

	init_ext_key(&key, SCOUTFS_FREE_EXTENT_BLKNO_ZONE, 0, 1);

	for (;;) {
		/* will stop at order items before getting stuck in final block */
		BUILD_BUG_ON(SCOUTFS_FREE_EXTENT_BLKNO_ZONE > SCOUTFS_FREE_EXTENT_ORDER_ZONE);
		init_ext_key(&start, SCOUTFS_FREE_EXTENT_BLKNO_ZONE, 0, 1);
		init_ext_key(&end, SCOUTFS_FREE_EXTENT_ORDER_ZONE, 0, 1);

		ret = scoutfs_btree_read_items(sb, &root->root, &key, &start, &end,
					       alloc_btree_extent_item_cb, &cba);
		if (ret < 0 || end.sk_zone != SCOUTFS_FREE_EXTENT_BLKNO_ZONE) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		key = end;
		scoutfs_key_inc(&key);
	}

	return ret;
}
