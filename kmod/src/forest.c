/*
 * Copyright (C) 2019 Versity Software, Inc.  All rights reserved.
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
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "lock.h"
#include "btree.h"
#include "client.h"
#include "alloc.h"
#include "block.h"
#include "forest.h"
#include "hash.h"
#include "srch.h"
#include "counters.h"
#include "xattr.h"
#include "scoutfs_trace.h"

/*
 * scoutfs items are stored in a forest of btrees.  Each mount writes
 * items into its own relatively small log btree.  Each mount can also
 * have a few finalized log btrees sitting around that it is no longer
 * writing to.  Finally a much larger core fs btree is the final home
 * for metadata.
 *
 * The log btrees are modified by multiple transactions over time so
 * there is no consistent ordering relationship between the items in
 * different btrees.  Each item in a log btree stores a seq for the
 * item.  Readers check log btrees for the most recent seq that it
 * should use.
 *
 * The item cache reads items in bulk from stable btrees, and writes a
 * transaction's worth of dirty items into the item log btree.
 *
 * Log btrees are typically very sparse.  It would be wasteful for
 * readers to read every log btree looking for an item.  Each log btree
 * contains a bloom filter keyed on the starting key of locks.  This
 * lets lock holders quickly eliminate log trees that cannot contain
 * keys protected by their lock.
 */

struct forest_info {
	struct super_block *sb;

	struct mutex mutex;
	struct scoutfs_alloc *alloc;
	struct scoutfs_block_writer *wri;
	struct scoutfs_log_trees our_log;

	struct mutex srch_mutex;
	struct scoutfs_srch_file srch_file;
	struct scoutfs_block *srch_bl;

	struct workqueue_struct *workq;
	struct delayed_work log_merge_dwork;

	atomic64_t inode_count_delta;
};

#define DECLARE_FOREST_INFO(sb, name) \
	struct forest_info *name = SCOUTFS_SB(sb)->forest_info

struct forest_refs {
	struct scoutfs_block_ref fs_ref;
	struct scoutfs_block_ref logs_ref;
};

/* initialize some refs that initially aren't equal */
#define DECLARE_STALE_TRACKING_SUPER_REFS(a, b)		\
	struct forest_refs a = {{cpu_to_le64(0),}};	\
	struct forest_refs b = {{cpu_to_le64(1),}}

struct forest_bloom_nrs {
	unsigned int nrs[SCOUTFS_FOREST_BLOOM_NRS];
};

static void calc_bloom_nrs(struct forest_bloom_nrs *bloom,
			    struct scoutfs_key *key)
{
	u64 hash;
	int i;

	BUILD_BUG_ON((SCOUTFS_FOREST_BLOOM_FUNC_BITS *
		      SCOUTFS_FOREST_BLOOM_NRS) > 64);

	hash = scoutfs_hash64(key, sizeof(struct scoutfs_key));

	for (i = 0; i < ARRAY_SIZE(bloom->nrs); i++) {
		bloom->nrs[i] = (u32)hash % SCOUTFS_FOREST_BLOOM_BITS;
		hash >>= SCOUTFS_FOREST_BLOOM_FUNC_BITS;
	}
}

static struct scoutfs_block *read_bloom_ref(struct super_block *sb, struct scoutfs_block_ref *ref)
{
	struct scoutfs_block *bl;
	int ret;

	ret = scoutfs_block_read_ref(sb, ref, SCOUTFS_BLOCK_MAGIC_BLOOM, &bl);
	if (ret < 0) {
		if (ret == -ESTALE)
			scoutfs_inc_counter(sb, forest_bloom_stale);
		bl = ERR_PTR(ret);
	}

	return bl;
}

/*
 * This is an unlocked iteration across all the btrees to find a hint at
 * the next key that the caller could read.  It's used to find out what
 * next key range to lock, presuming you're allowed to only see items
 * that have been synced.  We ask the server for the current roots to
 * check.
 *
 * We don't bother skipping deletion items here.  The caller will safely
 * skip over them when really reading from their locked region and will
 * call again after them to find the next hint.
 *
 * We're reading from stable persistent trees so we don't need to lock
 * against writers, their writes are cow into free blocks.
 */
int scoutfs_forest_next_hint(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_key *next)
{
	DECLARE_STALE_TRACKING_SUPER_REFS(prev_refs, refs);
	struct scoutfs_net_roots roots;
	struct scoutfs_btree_root item_root;
	struct scoutfs_log_trees *lt;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key found;
	struct scoutfs_key ltk;
	bool checked_fs;
	bool have_next;
	int ret;

	scoutfs_inc_counter(sb, forest_roots_next_hint);

retry:
	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	trace_scoutfs_forest_using_roots(sb, &roots.fs_root, &roots.logs_root);
	refs.fs_ref = roots.fs_root.ref;
	refs.logs_ref = roots.logs_root.ref;

	scoutfs_key_init_log_trees(&ltk, 0, 0);
	checked_fs = false;
	have_next = false;

	for (;;) {
		if (!checked_fs) {
			checked_fs = true;
			item_root = roots.fs_root;
		} else {
			ret = scoutfs_btree_next(sb, &roots.logs_root, &ltk,
						 &iref);
			if (ret == -ENOENT) {
				if (have_next)
					ret = 0;
				break;
			}
			if (ret == -ESTALE)
				break;
			if (ret < 0)
				goto out;

			if (iref.val_len == sizeof(*lt)) {
				ltk = *iref.key;
				scoutfs_key_inc(&ltk);
				lt = iref.val;
				item_root = lt->item_root;
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
			if (ret < 0)
				goto out;

			if (item_root.ref.blkno == 0)
				continue;
		}

		ret = scoutfs_btree_next(sb, &item_root, key, &iref);
		if (ret == -ENOENT)
			continue;
		if (ret == -ESTALE)
			break;
		if (ret < 0)
			goto out;

		found = *iref.key;
		scoutfs_btree_put_iref(&iref);

		if (!have_next || scoutfs_key_compare(&found, next) < 0) {
			have_next = true;
			*next = found;
		}
	}

	if (ret == -ESTALE) {
		if (memcmp(&prev_refs, &refs, sizeof(refs)) == 0)
			return -EIO;
		prev_refs = refs;
		goto retry;
	}
out:

	return ret;
}

struct forest_read_items_data {
	int fic;
	scoutfs_forest_item_cb cb;
	void *cb_arg;
};

static int forest_read_items(struct super_block *sb, struct scoutfs_key *key, u64 seq, u8 flags,
			     void *val, int val_len, void *arg)
{
	struct forest_read_items_data *rid = arg;

	return rid->cb(sb, key, seq, flags, val, val_len, rid->fic, rid->cb_arg);
}

/*
 * For each forest btree whose bloom block indicates that the lock might
 * have items stored, call the caller's callback for every item in the
 * leaf block in each tree which contains the key.
 *
 * The btree iter calls clamp the caller's range to the tightest range
 * that covers all the blocks.  Any keys outside of this range can't be
 * trusted because we didn't visit all the trees to check their items.
 *
 * We return -ESTALE if we hit stale blocks to give the caller a chance
 * to reset their state and retry with a newer version of the btrees.
 */
int scoutfs_forest_read_items(struct super_block *sb,
			      struct scoutfs_key *key,
			      struct scoutfs_key *bloom_key,
			      struct scoutfs_key *start,
			      struct scoutfs_key *end,
			      scoutfs_forest_item_cb cb, void *arg)
{
	struct forest_read_items_data rid = {
		.cb = cb,
		.cb_arg = arg,
	};
	struct scoutfs_log_trees lt;
	struct scoutfs_net_roots roots;
	struct scoutfs_bloom_block *bb;
	struct forest_bloom_nrs bloom;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_block *bl;
	struct scoutfs_key ltk;
	struct scoutfs_key orig_start = *start;
	struct scoutfs_key orig_end = *end;
	int ret;
	int i;

	scoutfs_inc_counter(sb, forest_read_items);
	calc_bloom_nrs(&bloom, bloom_key);

	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	trace_scoutfs_forest_using_roots(sb, &roots.fs_root, &roots.logs_root);

	*start = orig_start;
	*end = orig_end;

	/* start with fs root items */
	rid.fic |= FIC_FS_ROOT;
	ret = scoutfs_btree_read_items(sb, &roots.fs_root, key, start, end,
				       forest_read_items, &rid);
	if (ret < 0)
		goto out;
	rid.fic &= ~FIC_FS_ROOT;

	scoutfs_key_init_log_trees(&ltk, 0, 0);
	for (;; scoutfs_key_inc(&ltk)) {
		ret = scoutfs_btree_next(sb, &roots.logs_root, &ltk, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(lt)) {
				ltk = *iref.key;
				memcpy(&lt, iref.val, sizeof(lt));
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				break;
			goto out; /* including stale */
		}

		if (lt.bloom_ref.blkno == 0)
			continue;

		bl = read_bloom_ref(sb, &lt.bloom_ref);
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto out;
		}
		bb = bl->data;

		for (i = 0; i < ARRAY_SIZE(bloom.nrs); i++) {
			if (!test_bit_le(bloom.nrs[i], bb->bits))
				break;
		}

		scoutfs_block_put(sb, bl);

		/* one of the bloom bits wasn't set */
		if (i != ARRAY_SIZE(bloom.nrs)) {
			scoutfs_inc_counter(sb, forest_bloom_fail);
			continue;
		}

		scoutfs_inc_counter(sb, forest_bloom_pass);

		if ((le64_to_cpu(lt.flags) & SCOUTFS_LOG_TREES_FINALIZED))
			rid.fic |= FIC_FINALIZED;

		ret = scoutfs_btree_read_items(sb, &lt.item_root, key, start,
					       end, forest_read_items, &rid);
		if (ret < 0)
			goto out;

		rid.fic &= ~FIC_FINALIZED;
	}

	ret = 0;
out:
	return ret;
}

/*
 * If the items are deltas then combine the src with the destination
 * value and store the result in the destination.
 *
 * Returns:
 *  -errno: fatal error, no change
 *  0: not delta items, no change
 *  +ve: SCOUTFS_DELTA_ values indicating when dst and/or src can be dropped
 */
int scoutfs_forest_combine_deltas(struct scoutfs_key *key, void *dst, int dst_len,
				  void *src, int src_len)
{
	if (key->sk_zone == SCOUTFS_XATTR_TOTL_ZONE)
		return scoutfs_xattr_combine_totl(dst, dst_len, src, src_len);

	return 0;
}

/*
 * Make sure that the bloom bits for the lock's start key are all set in
 * the current log's bloom block.  We record the nr of our log tree in
 * the lock so that we only try to cow and set the bits once per tree
 * across multiple commits as long as the lock isn't purged.
 *
 * This is using a coarse mutex to serialize cowing the block.  It could
 * be much finer grained, but it's infrequent.  We'll keep an eye on if
 * it gets expensive enough to warrant fixing.
 */
int scoutfs_forest_set_bloom_bits(struct super_block *sb,
				  struct scoutfs_lock *lock)
{
	DECLARE_FOREST_INFO(sb, finf);
	struct scoutfs_block *bl = NULL;
	struct scoutfs_bloom_block *bb;
	struct scoutfs_block_ref *ref;
	struct forest_bloom_nrs bloom;
	int nr_set = 0;
	u64 nr;
	int ret;
	int i;

	nr = le64_to_cpu(finf->our_log.nr);

	/* our rid is constant */
	if (atomic64_read(&lock->forest_bloom_nr) == nr) {
		ret = 0;
		goto out;
	}

	mutex_lock(&finf->mutex);

	scoutfs_inc_counter(sb, forest_set_bloom_bits);
	calc_bloom_nrs(&bloom, &lock->start);

	ref = &finf->our_log.bloom_ref;

	ret = scoutfs_block_dirty_ref(sb, finf->alloc, finf->wri, ref, SCOUTFS_BLOCK_MAGIC_BLOOM,
				      &bl, 0, NULL);
	if (ret < 0)
		goto unlock;
	bb = bl->data;

	for (i = 0; i < ARRAY_SIZE(bloom.nrs); i++) {
		if (!test_and_set_bit_le(bloom.nrs[i], bb->bits)) {
			le64_add_cpu(&bb->total_set, 1);
			nr_set++;
		}
	}

	trace_scoutfs_forest_bloom_set(sb, &lock->start,
				le64_to_cpu(finf->our_log.rid),
				le64_to_cpu(finf->our_log.nr),
				le64_to_cpu(finf->our_log.bloom_ref.blkno),
				le64_to_cpu(finf->our_log.bloom_ref.seq),
				nr_set);

	atomic64_set(&lock->forest_bloom_nr,  nr);
	ret = 0;
unlock:
	mutex_unlock(&finf->mutex);
out:
	scoutfs_block_put(sb, bl);
	return ret;
}

/*
 * The caller is commiting items in the transaction and has found the
 * greatest item seq amongst them.  We store it in the log_trees root
 * to send to the server.
 */
void scoutfs_forest_set_max_seq(struct super_block *sb, u64 max_seq)
{
	DECLARE_FOREST_INFO(sb, finf);

	finf->our_log.max_item_seq = cpu_to_le64(max_seq);
}

/*
 * The server is calling during setup to find the greatest item seq
 * amongst all the log tree roots.  They have the authoritative current
 * super.
 *
 * Item seqs are only used to compare items in log trees, not in the
 * main fs tree.  All we have to do is find the greatest seq amongst the
 * log_trees so that the core seq will have a greater seq than all the
 * items in the log_trees.
 */
int scoutfs_forest_get_max_seq(struct super_block *sb,
			       struct scoutfs_super_block *super,
			       u64 *seq)
{
	struct scoutfs_log_trees *lt;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key ltk;
	int ret;

	scoutfs_key_init_log_trees(&ltk, 0, 0);
	*seq = 0;

	for (;; scoutfs_key_inc(&ltk)) {
		ret = scoutfs_btree_next(sb, &super->logs_root, &ltk, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(struct scoutfs_log_trees)) {
				ltk = *iref.key;
				lt = iref.val;
				*seq = max(*seq, le64_to_cpu(lt->max_item_seq));
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				break;
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

int scoutfs_forest_insert_list(struct super_block *sb, scoutfs_btree_item_iter_cb cb,
			       void *pos, void *arg)
{
	DECLARE_FOREST_INFO(sb, finf);

	return scoutfs_btree_insert_list(sb, finf->alloc, finf->wri,
					 &finf->our_log.item_root, cb, pos, arg);
}

/*
 * Add a srch entry to the current transaction's log file.  It will be
 * committed in a transaction along with the dirty btree blocks that
 * hold dirty items.  The srch entries aren't governed by lock
 * consistency.
 *
 * We lock here because of the shared file and block reference.
 * Typically these calls are a quick appending to the end of the block,
 * but they will allocate or cow blocks every few thousand calls.
 */
int scoutfs_forest_srch_add(struct super_block *sb, u64 hash, u64 ino, u64 id)
{
	DECLARE_FOREST_INFO(sb, finf);
	int ret;

	mutex_lock(&finf->srch_mutex);
	ret = scoutfs_srch_add(sb, finf->alloc, finf->wri, &finf->srch_file,
			       &finf->srch_bl, hash, ino, id);
	mutex_unlock(&finf->srch_mutex);
	return ret;
}

void scoutfs_forest_inc_inode_count(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	atomic64_inc(&finf->inode_count_delta);
}

void scoutfs_forest_dec_inode_count(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	atomic64_dec(&finf->inode_count_delta);
}

/*
 * Return the total inode count from the super block and all the
 * log_btrees it references.   This assumes it's working with a block
 * reference hierarchy that should be fully consistent.   If we see
 * ESTALE we've hit persistent corruption.
 */
int scoutfs_forest_inode_count(struct super_block *sb, struct scoutfs_super_block *super,
			       u64 *inode_count)
{
	struct scoutfs_log_trees *lt;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	*inode_count = le64_to_cpu(super->inode_count);

	scoutfs_key_init_log_trees(&key, 0, 0);
	for (;;) {
		ret = scoutfs_btree_next(sb, &super->logs_root, &key, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(*lt)) {
				key = *iref.key;
				scoutfs_key_inc(&key);
				lt = iref.val;
				*inode_count += le64_to_cpu(lt->inode_count_delta);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			else if (ret == -ESTALE)
				ret = -EIO;
			break;
		}
	}

	return ret;
}

/*
 * This is called from transactions as a new transaction opens and is
 * serialized with all writers.
 */
void scoutfs_forest_init_btrees(struct super_block *sb,
				struct scoutfs_alloc *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_log_trees *lt)
{
	DECLARE_FOREST_INFO(sb, finf);

	mutex_lock(&finf->mutex);

	finf->alloc = alloc;
	finf->wri = wri;

	/* the lt allocator fields have been used by the caller */
	memset(&finf->our_log, 0, sizeof(finf->our_log));
	finf->our_log.item_root = lt->item_root;
	finf->our_log.bloom_ref = lt->bloom_ref;
	finf->our_log.max_item_seq = lt->max_item_seq;
	finf->our_log.rid = lt->rid;
	finf->our_log.nr = lt->nr;
	finf->srch_file = lt->srch_file;

	WARN_ON_ONCE(finf->srch_bl); /* commiting should have put the block */
	finf->srch_bl = NULL;

	atomic64_set(&finf->inode_count_delta, le64_to_cpu(lt->inode_count_delta));

	trace_scoutfs_forest_init_our_log(sb, le64_to_cpu(lt->rid),
					  le64_to_cpu(lt->nr),
					  le64_to_cpu(lt->item_root.ref.blkno),
					  le64_to_cpu(lt->item_root.ref.seq));

	mutex_unlock(&finf->mutex);
}

/*
 * This is called during transaction commit which excludes forest writer
 * calls.  The caller has already written all the dirty blocks that the
 * forest roots reference.  They're getting the roots to send to the server
 * for the commit.
 */
void scoutfs_forest_get_btrees(struct super_block *sb,
			       struct scoutfs_log_trees *lt)
{
	DECLARE_FOREST_INFO(sb, finf);

	lt->item_root = finf->our_log.item_root;
	lt->bloom_ref = finf->our_log.bloom_ref;
	lt->srch_file = finf->srch_file;
	lt->max_item_seq = finf->our_log.max_item_seq;

	scoutfs_block_put(sb, finf->srch_bl);
	finf->srch_bl = NULL;

	lt->inode_count_delta = cpu_to_le64(atomic64_read(&finf->inode_count_delta));

	trace_scoutfs_forest_prepare_commit(sb, &lt->item_root.ref,
					    &lt->bloom_ref);
}

#define LOG_MERGE_DELAY_MS (5 * MSEC_PER_SEC)

/*
 * Regularly try to get a log merge request from the server.  If we get
 * a request we walk the log_trees items to find input trees and pass
 * them to btree_merge.  All of our work is done in dirty blocks
 * allocated from available free blocks that the server gave us.  If we
 * hit an error then we drop our dirty blocks without writing them and
 * send an error flag to the server so they can reclaim our allocators
 * and ignore the rest of our work.
 */
static void scoutfs_forest_log_merge_worker(struct work_struct *work)
{
	struct forest_info *finf = container_of(work, struct forest_info,
						log_merge_dwork.work);
	struct super_block *sb = finf->sb;
	struct scoutfs_btree_root_head *rhead = NULL;
	struct scoutfs_btree_root_head *tmp;
	struct scoutfs_log_merge_complete comp;
	struct scoutfs_log_merge_request req;
	struct scoutfs_log_trees *lt;
	struct scoutfs_block_writer wri;
	struct scoutfs_alloc alloc;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key next;
	struct scoutfs_key key;
	unsigned long delay;
	LIST_HEAD(inputs);
	int ret;

	ret = scoutfs_client_get_log_merge(sb, &req);
	if (ret < 0)
		goto resched;

	comp.root = req.root;
	comp.start = req.start;
	comp.end = req.end;
	comp.remain = req.end;
	comp.rid = req.rid;
	comp.seq = req.seq;
	comp.flags = 0;

	scoutfs_alloc_init(&alloc, &req.meta_avail, &req.meta_freed);
	scoutfs_block_writer_init(sb, &wri);

	/* find finalized input log trees within the input seq */
	for (scoutfs_key_init_log_trees(&key, 0, 0); ; scoutfs_key_inc(&key)) {

		if (!rhead) {
			rhead = kmalloc(sizeof(*rhead), GFP_NOFS);
			if (!rhead) {
				ret = -ENOMEM;
				goto out;
			}
		}

		ret = scoutfs_btree_next(sb, &req.logs_root, &key, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(*lt)) {
				key = *iref.key;
				lt = iref.val;
				if (lt->item_root.ref.blkno != 0 &&
				    (le64_to_cpu(lt->flags) & SCOUTFS_LOG_TREES_FINALIZED) &&
				    (le64_to_cpu(lt->finalize_seq) < le64_to_cpu(req.input_seq))) {
					rhead->root = lt->item_root;
					list_add_tail(&rhead->head, &inputs);
					rhead = NULL;
				}
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT) {
				ret = 0;
				break;
			}
			goto out;
		}
	}

	/* shouldn't be possible, but it's harmless */
	if (list_empty(&inputs)) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_btree_merge(sb, &alloc, &wri, &req.start, &req.end,
				  &next, &comp.root, &inputs,
				  !!(req.flags & cpu_to_le64(SCOUTFS_LOG_MERGE_REQUEST_SUBTREE)),
				  SCOUTFS_LOG_MERGE_DIRTY_BYTE_LIMIT, 10);
	if (ret == -ERANGE) {
		comp.remain = next;
		le64_add_cpu(&comp.flags, SCOUTFS_LOG_MERGE_COMP_REMAIN);
		ret = 0;
	}

out:
	scoutfs_alloc_prepare_commit(sb, &alloc, &wri);
	if (ret == 0)
	      ret = scoutfs_block_writer_write(sb, &wri);
	scoutfs_block_writer_forget_all(sb, &wri);

	comp.meta_avail = alloc.avail;
	comp.meta_freed = alloc.freed;
	if (ret < 0)
		le64_add_cpu(&comp.flags, SCOUTFS_LOG_MERGE_COMP_ERROR);

	ret = scoutfs_client_commit_log_merge(sb, &comp);

	kfree(rhead);
	list_for_each_entry_safe(rhead, tmp, &inputs, head)
		kfree(rhead);

resched:
	delay = ret == 0 ? 0 : msecs_to_jiffies(LOG_MERGE_DELAY_MS);
	queue_delayed_work(finf->workq, &finf->log_merge_dwork, delay);
}

int scoutfs_forest_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct forest_info *finf;
	int ret;

	finf = kzalloc(sizeof(struct forest_info), GFP_KERNEL);
	if (!finf) {
		ret = -ENOMEM;
		goto out;
	}

	/* the finf fields will be setup as we open a transaction */
	finf->sb = sb;
	mutex_init(&finf->mutex);
	mutex_init(&finf->srch_mutex);
	INIT_DELAYED_WORK(&finf->log_merge_dwork,
			  scoutfs_forest_log_merge_worker);
	sbi->forest_info = finf;

	finf->workq = alloc_workqueue("scoutfs_log_merge", WQ_NON_REENTRANT |
				      WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!finf->workq) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;
out:
	if (ret)
		scoutfs_forest_destroy(sb);

	return 0;
}

void scoutfs_forest_start(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	queue_delayed_work(finf->workq, &finf->log_merge_dwork,
			   msecs_to_jiffies(LOG_MERGE_DELAY_MS));
}

void scoutfs_forest_stop(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	if (finf && finf->workq) {
		cancel_delayed_work_sync(&finf->log_merge_dwork);
		destroy_workqueue(finf->workq);
	}
}

void scoutfs_forest_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct forest_info *finf = SCOUTFS_SB(sb)->forest_info;

	if (finf) {
		scoutfs_block_put(sb, finf->srch_bl);

		kfree(finf);
		sbi->forest_info = NULL;
	}
}
