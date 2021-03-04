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
#include <linux/atomic.h>

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
#include "scoutfs_trace.h"
#include "inode.h"

/*
 * scoutfs items are stored in a forest of btrees.  Each mount writes
 * items into its own relatively small log btree.  Each mount can also
 * have a few finalized log btrees sitting around that it is no longer
 * writing to.  Finally a much larger core fs btree is the final home
 * for metadata.
 *
 * The log btrees are modified by multiple transactions over time so
 * there is no consistent ordering relationship between the items in
 * different btrees.  Each item in a log btree stores a version number
 * for the item.  Readers check log btrees for the most recent version
 * that it should use.
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

	atomic_t *oino_counted_bloom;
	struct scoutfs_block *oino_bl;
	struct delayed_work oino_work;

	struct scoutfs_sysfs_attrs ssa;
	bool orphan_list_present_hint;

	bool shutdown;
};

#define OINO_WORK_DELAY_MS 1000

#define DECLARE_FOREST_INFO(sb, name) \
	struct forest_info *name = SCOUTFS_SB(sb)->forest_info
#define DECLARE_FOREST_INFO_KOBJ(kobj, name) \
	DECLARE_FOREST_INFO(SCOUTFS_SYSFS_ATTRS_SB(kobj), name)

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
	bool is_fs;
	scoutfs_forest_item_cb cb;
	void *cb_arg;
};

static int forest_read_items(struct super_block *sb, struct scoutfs_key *key,
			     void *val, int val_len, void *arg)
{
	struct forest_read_items_data *rid = arg;
	struct scoutfs_log_item_value _liv = {0,};
	struct scoutfs_log_item_value *liv = &_liv;

	if (!rid->is_fs) {
		liv = val;
		val += sizeof(struct scoutfs_log_item_value);
		val_len -= sizeof(struct scoutfs_log_item_value);
	}

	return rid->cb(sb, key, liv, val, val_len, rid->cb_arg);
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
 * If we hit stale blocks and retry we can call the callback for
 * duplicate items.  This is harmless because the items are stable while
 * the caller holds their cluster lock and the caller has to filter out
 * item versions anyway.
 */
int scoutfs_forest_read_items(struct super_block *sb,
			      struct scoutfs_lock *lock,
			      struct scoutfs_key *key,
			      struct scoutfs_key *start,
			      struct scoutfs_key *end,
			      scoutfs_forest_item_cb cb, void *arg)
{
	DECLARE_STALE_TRACKING_SUPER_REFS(prev_refs, refs);
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
	int ret;
	int i;

	scoutfs_inc_counter(sb, forest_read_items);
	calc_bloom_nrs(&bloom, &lock->start);

	roots = lock->roots;
retry:
	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	trace_scoutfs_forest_using_roots(sb, &roots.fs_root, &roots.logs_root);
	refs.fs_ref = roots.fs_root.ref;
	refs.logs_ref = roots.logs_root.ref;

	*start = lock->start;
	*end = lock->end;

	/* start with fs root items */
	rid.is_fs = true;
	ret = scoutfs_btree_read_items(sb, &roots.fs_root, key, start, end,
				       forest_read_items, &rid);
	if (ret < 0)
		goto out;
	rid.is_fs = false;

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

		ret = scoutfs_btree_read_items(sb, &lt.item_root, key, start,
					       end, forest_read_items, &rid);
		if (ret < 0)
			goto out;
	}

	ret = 0;
out:
	if (ret == -ESTALE) {
		if (memcmp(&prev_refs, &refs, sizeof(refs)) == 0) {
			ret = -EIO;
			goto out;
		}
		prev_refs = refs;

		ret = scoutfs_client_get_roots(sb, &roots);
		if (ret)
			goto out;
		goto retry;
	}

	return ret;
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
 * greatest item version amongst them.  We store it in the log_trees root
 * to send to the server.
 */
void scoutfs_forest_set_max_vers(struct super_block *sb, u64 max_vers)
{
	DECLARE_FOREST_INFO(sb, finf);

	finf->our_log.max_item_vers = cpu_to_le64(max_vers);
}

/*
 * The server is calling during setup to find the greatest item version
 * amongst all the log tree roots.  They have the authoritative current
 * super.
 *
 * Item versions are only used to compare items in log trees, not in the
 * main fs tree.  All we have to do is find the greatest version amongst
 * the log_trees so that new locks will have a write_version greater
 * than all the items in the log_trees.
 */
int scoutfs_forest_get_max_vers(struct super_block *sb,
				struct scoutfs_super_block *super,
				u64 *vers)
{
	struct scoutfs_log_trees *lt;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key ltk;
	int ret;

	scoutfs_key_init_log_trees(&ltk, 0, 0);
	*vers = 0;

	for (;; scoutfs_key_inc(&ltk)) {
		ret = scoutfs_btree_next(sb, &super->logs_root, &ltk, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(struct scoutfs_log_trees)) {
				ltk = *iref.key;
				lt = iref.val;
				*vers = max(*vers,
					    le64_to_cpu(lt->max_item_vers));
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

int scoutfs_forest_insert_list(struct super_block *sb,
			       struct scoutfs_btree_item_list *lst)
{
	DECLARE_FOREST_INFO(sb, finf);

	return scoutfs_btree_insert_list(sb, finf->alloc, finf->wri,
					 &finf->our_log.item_root, lst);
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
	finf->our_log.oino_bloom_ref = lt->oino_bloom_ref;
	finf->our_log.max_item_vers = lt->max_item_vers;
	finf->our_log.rid = lt->rid;
	finf->our_log.nr = lt->nr;
	finf->srch_file = lt->srch_file;

	WARN_ON_ONCE(finf->srch_bl); /* committing should have put these blocks */
	finf->srch_bl = NULL;
	WARN_ON_ONCE(finf->oino_bl);
	finf->oino_bl = NULL;

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
	lt->oino_bloom_ref = finf->our_log.oino_bloom_ref;
	lt->srch_file = finf->srch_file;
	lt->max_item_vers = finf->our_log.max_item_vers;

	scoutfs_block_put(sb, finf->srch_bl);
	finf->srch_bl = NULL;

	trace_scoutfs_forest_prepare_commit(sb, &lt->item_root.ref,
					    &lt->bloom_ref);
}

void scoutfs_oino_delete_work(struct work_struct * work);

static ssize_t orphan_list_present_hint_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	DECLARE_FOREST_INFO_KOBJ(kobj, finf);

	return snprintf(buf, PAGE_SIZE, "%u", finf->orphan_list_present_hint);
}
SCOUTFS_ATTR_RO(orphan_list_present_hint);

static struct attribute *forest_attrs[] = {
	SCOUTFS_ATTR_PTR(orphan_list_present_hint),
	NULL,
};

int scoutfs_forest_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct forest_info *finf;
	int ret;
	int i;

	finf = kzalloc(sizeof(struct forest_info), GFP_KERNEL);
	if (!finf) {
		ret = -ENOMEM;
		goto out;
	}

	/* the finf fields will be setup as we open a transaction */
	finf->sb = sb;
	mutex_init(&finf->mutex);
	mutex_init(&finf->srch_mutex);

	finf->oino_counted_bloom = vmalloc(sizeof(atomic_t)
					   * SCOUTFS_FOREST_BLOOM_BITS);
	if (!finf->oino_counted_bloom) {
		kfree(finf);
		return -ENOMEM;
	}

	for (i = 0; i < SCOUTFS_FOREST_BLOOM_BITS; i++) {
		atomic_set(&finf->oino_counted_bloom[i], 0);
	}
	INIT_DELAYED_WORK(&finf->oino_work, scoutfs_oino_delete_work);
	scoutfs_sysfs_init_attrs(sb, &finf->ssa);

	sbi->forest_info = finf;
	ret = scoutfs_sysfs_create_attrs(sb, &finf->ssa, forest_attrs,
					 "forest");
	if (ret < 0)
		goto out;

	ret = 0;
out:
	if (ret)
		scoutfs_forest_destroy(sb);

	return 0;
}

void scoutfs_forest_shutdown(struct super_block *sb)
{
	struct forest_info *finf = SCOUTFS_SB(sb)->forest_info;

	if (finf) {
		finf->shutdown = true;
		cancel_delayed_work_sync(&finf->oino_work);
	}
}

void scoutfs_forest_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct forest_info *finf = SCOUTFS_SB(sb)->forest_info;

	if (finf) {
		scoutfs_sysfs_destroy_attrs(sb, &finf->ssa);
		scoutfs_block_put(sb, finf->srch_bl);
		scoutfs_block_put(sb, finf->oino_bl);
		vfree(finf->oino_counted_bloom);
		kfree(finf);
		sbi->forest_info = NULL;
	}
}

/*
 * Track current open inodes in a counted bloom filter. Save a much smaller
 * classic BF of open inodes in each transaction, allowing orphan processing to
 * know when an orphan inode is no longer open on any node.
 *
 * Let's call this code: open inode tracking (OINO)
 */

void scoutfs_forest_oino_inc(struct super_block *sb, u64 ino)
{
	__le64 le_ino = cpu_to_le64(ino);
	DECLARE_FOREST_INFO(sb, finf);
	u64 hash;
	int val;
	int i;

	hash = scoutfs_hash64(&le_ino, sizeof(le_ino));
	for (i = 0; i < SCOUTFS_FOREST_BLOOM_NRS; i++) {
		u32 idx = (u32)hash % SCOUTFS_FOREST_BLOOM_BITS;
		val = atomic_inc_return(&finf->oino_counted_bloom[idx]);
		WARN_ON_ONCE(val < 0);

		hash >>= SCOUTFS_FOREST_BLOOM_FUNC_BITS;
	}
}

void scoutfs_forest_oino_dec(struct super_block *sb, u64 ino)
{
	__le64 le_ino = cpu_to_le64(ino);
	DECLARE_FOREST_INFO(sb, finf);
	u64 hash;
	int val;
	int i;

	hash = scoutfs_hash64(&le_ino, sizeof(le_ino));
	for (i = 0; i < SCOUTFS_FOREST_BLOOM_NRS; i++) {
		u32 idx = (u32)hash % SCOUTFS_FOREST_BLOOM_BITS;
		val = atomic_dec_return(&finf->oino_counted_bloom[idx]);
		WARN_ON_ONCE(val < 0);

		hash >>= SCOUTFS_FOREST_BLOOM_FUNC_BITS;
	}
}

/*
 * Notify us when a file is orphaned, for debug/test purposes
 */
void scoutfs_forest_oino_new_orphan(struct super_block *sb)
{
	DECLARE_FOREST_INFO(sb, finf);

	finf->orphan_list_present_hint = true;
}

/*
 * Alloc a dirty block and initialize as an oino bloom block.
 */
struct scoutfs_block *scoutfs_forest_oino_alloc(struct super_block *sb,
						struct scoutfs_alloc *alloc,
						struct scoutfs_block_writer *wri,
						u64 trans_seq)
{
	struct scoutfs_block *new_bl = NULL;
	struct scoutfs_block_ref ref = {0};
	struct scoutfs_bloom_block *bb;
	u64 blkno;
	int ret;

	ret = scoutfs_block_dirty_ref(sb, alloc, wri, &ref, SCOUTFS_BLOCK_MAGIC_BLOOM,
				      &new_bl, 0, &blkno);
	if (ret < 0)
		return ERR_PTR(ret);

	bb = new_bl->data;

	bb->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BLOOM);
	bb->hdr.fsid = SCOUTFS_SB(sb)->super.hdr.fsid;
	bb->hdr.blkno = cpu_to_le64(blkno);
	bb->hdr.seq = cpu_to_le64(trans_seq);

	return new_bl;
}

/*
 * At the start of the transaction, alloc and mark dirty a meta block in
 * anticipation of updating the OINO BF at the end of the transaction.
 */
int scoutfs_forest_oino_newtrans_alloc(struct super_block *sb, u64 trans_seq)
{
	struct scoutfs_block *new_bl = NULL;
	struct scoutfs_bloom_block *bb;
	struct scoutfs_block_ref *ref;
	DECLARE_FOREST_INFO(sb, finf);
	int ret;

	WARN_ON_ONCE(finf->oino_bl);

	new_bl = scoutfs_forest_oino_alloc(sb, finf->alloc, finf->wri, trans_seq);
	if (IS_ERR(new_bl)) {
		ret = PTR_ERR(new_bl);
		goto out;
	}

	ref = &finf->our_log.oino_bloom_ref;

	/* free previous oino block, if any */
	if (ref->blkno) {
		ret = scoutfs_free_meta(sb, finf->alloc, finf->wri,
					le64_to_cpu(ref->blkno));
		BUG_ON(ret);
	}

	bb = new_bl->data;
	ref->blkno = bb->hdr.blkno;
	ref->seq = bb->hdr.seq;

	finf->oino_bl = new_bl;

out:
	return ret;
}

int scoutfs_forest_oino_update(struct super_block *sb)
{
	struct scoutfs_bloom_block *bb;
	DECLARE_FOREST_INFO(sb, finf);
	u64 last_seq;
	int ret;
	int i;

	if (!finf->oino_bl)
		return 0;

	bb = finf->oino_bl->data;

	ret = scoutfs_client_get_last_seq(sb, &last_seq);
	if (ret)
		return ret;

	bb->last_seq = cpu_to_le64(last_seq);
	finf->our_log.oino_bloom_ref.seq = bb->hdr.seq;

	/* Turn the counted BF into a classic BF */
	for (i = 0; i < SCOUTFS_FOREST_BLOOM_BITS; i++) {
		if (atomic_read(&finf->oino_counted_bloom[i]))
			set_bit_le(i, bb->bits);
	}
	scoutfs_block_put(sb, finf->oino_bl);
	finf->oino_bl = NULL;

	if (!finf->shutdown)
		schedule_delayed_work(&finf->oino_work, msecs_to_jiffies(OINO_WORK_DELAY_MS));

	return 0;
}

#define MAX_ORPHAN_DELETE_BATCH 4096

void scoutfs_oino_delete_work(struct work_struct *work)
{
	struct forest_info *finf = container_of(work, struct forest_info,
						oino_work.work);
	struct super_block *sb = finf->sb;
	struct scoutfs_net_roots roots;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees lt = {{{ 0 }}};
	struct scoutfs_bloom_block *bb;
	struct scoutfs_bloom_block *tmp_bb = NULL;
	struct scoutfs_block *bl;
	struct scoutfs_key ltk;
	int ret = 0;

	scoutfs_inc_counter(sb, forest_oino_delete_work);

	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

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

		if (lt.oino_bloom_ref.blkno == 0)
			continue;

		bl = read_bloom_ref(sb, &lt.oino_bloom_ref);
		if (IS_ERR(bl)) {
			ret = PTR_ERR(bl);
			goto out;
		}
		bb = bl->data;

		if (!tmp_bb) {
			tmp_bb = vmalloc(SCOUTFS_BLOCK_LG_SIZE);
			if (!tmp_bb) {
				ret = -ENOMEM;
				goto out;
			}
			memset(tmp_bb, 0, SCOUTFS_BLOCK_LG_SIZE);
			tmp_bb->last_seq = cpu_to_le64(U64_MAX);
		}

		/* Use oldest block's seq */
		tmp_bb->last_seq = cpu_to_le64(
			min(le64_to_cpu(bb->last_seq),
			    le64_to_cpu(tmp_bb->last_seq)));

		bitmap_or((long unsigned int *) &tmp_bb->bits,
			  (const long unsigned int *) &tmp_bb->bits,
			  (const long unsigned int *) &bb->bits,
			  SCOUTFS_FOREST_BLOOM_BITS);

		scoutfs_block_put(sb, bl);
	}

	if (tmp_bb) {
		ret = scoutfs_delete_orphans(sb, tmp_bb, MAX_ORPHAN_DELETE_BATCH);
		if (!finf->shutdown) {
			if (ret > 0) {
				/* Deleted some. May be more. Try again immediately. */
				schedule_delayed_work(&finf->oino_work, 0);
			} else if (ret == -ENOENT) {
				/* Race OK here -- it's just a hint for observability/testing */
				finf->orphan_list_present_hint = false;
			}
		}
		ret = 0;
	}

out:
	vfree(tmp_bb);
	if (ret == -ESTALE && !finf->shutdown) {
		scoutfs_inc_counter(sb, forest_oino_bloom_stale);
		schedule_delayed_work(&finf->oino_work, msecs_to_jiffies(OINO_WORK_DELAY_MS));
	} else {
		WARN_ON_ONCE(ret);
	}
}

/*
 * Use merged bloom filter to detect if an inode is likely open on another node.
 */
bool scoutfs_forest_oino_deletable(struct super_block *sb,
				   __le64 le_ino,
				   u64 orphan_seq,
				   struct scoutfs_bloom_block *bb)
{
	u64 hash;
	int i;

	/* ino not deletable until orphan seq older than merged bloom's seq */
	if (orphan_seq > le64_to_cpu(bb->last_seq)) {
		scoutfs_inc_counter(sb, forest_oino_seq_hit);
		return false;
	}

	/* ino not deletable until bloom says it's closed everywhere */
	hash = scoutfs_hash64(&le_ino, sizeof(le_ino));
	for (i = 0; i < SCOUTFS_FOREST_BLOOM_NRS; i++) {
		u32 idx = (u32)hash % SCOUTFS_FOREST_BLOOM_BITS;
		if (!test_bit_le(idx, bb->bits))
			break;

		hash >>= SCOUTFS_FOREST_BLOOM_FUNC_BITS;
	}

	if (i == SCOUTFS_FOREST_BLOOM_NRS) {
		scoutfs_inc_counter(sb, forest_oino_bloom_hit);
		return false;
	} else {
		scoutfs_inc_counter(sb, forest_oino_bloom_miss);
		return true;
	}
}
