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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mpage.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>
#include <linux/hash.h>
#include <linux/log2.h>
#include <linux/falloc.h>
#include <linux/writeback.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "alloc.h"
#include "data.h"
#include "trans.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "ioctl.h"
#include "btree.h"
#include "lock.h"
#include "file.h"
#include "msg.h"
#include "ext.h"
#include "util.h"

/*
 * We want to amortize work done after dirtying the shared transaction
 * accounting, but we don't want to blow out dirty allocator btree
 * blocks.  Each allocation can dirty quite a few allocator btree blocks
 * so we check in pretty often.
 */
#define EXTENTS_PER_HOLD 8

struct data_info {
	struct super_block *sb;
	struct mutex mutex;
	struct scoutfs_alloc *alloc;
	struct scoutfs_block_writer *wri;
	struct scoutfs_alloc_root data_freed;
	struct scoutfs_data_alloc dalloc;
};

#define DECLARE_DATA_INFO(sb, name) \
	struct data_info *name = SCOUTFS_SB(sb)->data_info

struct data_ext_args {
	u64 ino;
	struct inode *inode;
	struct scoutfs_lock *lock;
};

static void item_from_extent(struct scoutfs_key *key,
			     struct scoutfs_data_extent_val *dv, u64 ino,
			     u64 start, u64 len, u64 map, u8 flags)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skdx_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_DATA_EXTENT_TYPE,
		.skdx_end = cpu_to_le64(start + len - 1),
		.skdx_len = cpu_to_le64(len),
	};
	dv->blkno = cpu_to_le64(map);
	dv->flags = flags;
}

static void ext_from_item(struct scoutfs_extent *ext,
			  struct scoutfs_key *key,
			  struct scoutfs_data_extent_val *dv)
{
	ext->start = le64_to_cpu(key->skdx_end) -
		     le64_to_cpu(key->skdx_len) + 1;
	ext->len = le64_to_cpu(key->skdx_len);
	ext->map = le64_to_cpu(dv->blkno);
	ext->flags = dv->flags;
}

static void data_ext_op_warn(struct inode *inode)
{
	struct scoutfs_inode_info *si;

	if (inode) {
		si = SCOUTFS_I(inode);
		WARN_ON_ONCE(!rwsem_is_locked(&si->extent_sem));
	}
}

static int data_ext_next(struct super_block *sb, void *arg, u64 start, u64 len,
			 struct scoutfs_extent *ext)
{
	struct data_ext_args *args = arg;
	struct scoutfs_data_extent_val dv;
	struct scoutfs_key key;
	struct scoutfs_key last;
	int ret;

	data_ext_op_warn(args->inode);

	item_from_extent(&last, &dv, args->ino, U64_MAX, 1, 0, 0);
	item_from_extent(&key, &dv, args->ino, start, len, 0, 0);

	ret = scoutfs_item_next(sb, &key, &last, &dv, sizeof(dv), args->lock);
	if (ret == sizeof(dv)) {
		ext_from_item(ext, &key, &dv);
		ret = 0;
	} else if (ret >= 0) {
		ret = -EIO;
	}

	if (ret < 0)
		memset(ext, 0, sizeof(struct scoutfs_extent));
	return ret;
}

static void add_onoff(struct inode *inode, u64 map, u8 flags, s64 len)
{
	s64 on = 0;
	s64 off = 0;

	if (map && !(flags & SEF_UNWRITTEN))
		on += len;
	else if (flags & SEF_OFFLINE)
		off += len;

	scoutfs_inode_add_onoff(inode, on, off);
}

static int data_ext_insert(struct super_block *sb, void *arg, u64 start,
			   u64 len, u64 map, u8 flags)
{
	struct data_ext_args *args = arg;
	struct scoutfs_data_extent_val dv;
	struct scoutfs_key key;
	int ret;

	data_ext_op_warn(args->inode);

	item_from_extent(&key, &dv, args->ino, start, len, map, flags);
	ret = scoutfs_item_create(sb, &key, &dv, sizeof(dv), args->lock);
	if (ret == 0 && args->inode)
		add_onoff(args->inode, map, flags, len);
	return ret;
}

static int data_ext_remove(struct super_block *sb, void *arg, u64 start,
			   u64 len, u64 map, u8 flags)
{
	struct data_ext_args *args = arg;
	struct scoutfs_data_extent_val dv;
	struct scoutfs_key key;
	int ret;

	data_ext_op_warn(args->inode);

	item_from_extent(&key, &dv, args->ino, start, len, map, flags);
	ret = scoutfs_item_delete(sb, &key, args->lock);
	if (ret == 0 && args->inode)
		add_onoff(args->inode, map, flags, -len);
	return ret;
}

static struct scoutfs_ext_ops data_ext_ops = {
	.next = data_ext_next,
	.insert = data_ext_insert,
	.remove = data_ext_remove,
};

/*
 * Find and remove or mark offline the block mappings that intersect
 * with the caller's range.  The caller is responsible for transactions
 * and locks.
 *
 * Returns:
 *  - -errno on errors
 *  - 0 if there are no more extents to stop iteration
 *  - +iblock of next logical block to truncate the next block from
 */
static s64 truncate_extents(struct super_block *sb, struct inode *inode,
			    u64 ino, u64 iblock, u64 last, bool offline,
			    struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	struct data_ext_args args = {
		.ino = ino,
		.inode = inode,
		.lock = lock,
	};
	struct scoutfs_extent ext;
	struct scoutfs_extent tr;
	u64 offset;
	s64 ret;
	u8 flags;
	int err;
	int i;

	flags = offline ? SEF_OFFLINE : 0;
	ret = 0;

	for (i = 0; iblock <= last; i++) {
		if (i == EXTENTS_PER_HOLD) {
			ret = iblock;
			break;
		}

		ret = scoutfs_ext_next(sb, &data_ext_ops, &args,
				       iblock, 1, &ext);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		/* done if we went past the region */
		if (ext.start > last) {
			ret = 0;
			break;
		}

		/* nothing to do when already offline and unmapped */
		if ((offline && (ext.flags & SEF_OFFLINE)) && !ext.map) {
			iblock = ext.start + ext.len;
			continue;
		}

		iblock = max(ext.start, iblock);
		offset = iblock - ext.start;

		tr.start = iblock;
		tr.map = ext.map ? ext.map + offset : 0;
		tr.len = min(ext.len - offset, last - iblock + 1);
		tr.flags = ext.flags;

		trace_scoutfs_data_extent_truncated(sb, ino, &tr);

		ret = scoutfs_ext_set(sb, &data_ext_ops, &args,
				      tr.start, tr.len, 0, flags);
		if (ret < 0) {
			if (WARN_ON_ONCE(ret == -EINVAL)) {
				scoutfs_err(sb, "unexpected truncate inconsistency: ino %llu iblock %llu last %llu, start %llu len %llu",
					    ino, iblock, last, tr.start, tr.len);
			}
			break;
		}

		if (tr.map) {
			mutex_lock(&datinf->mutex);
			ret = scoutfs_free_data(sb, datinf->alloc,
						datinf->wri,
						&datinf->data_freed,
						tr.map, tr.len);
			mutex_unlock(&datinf->mutex);
			if (ret < 0) {
				err = scoutfs_ext_set(sb, &data_ext_ops, &args,
						      tr.start, tr.len, tr.map, tr.flags);
				if (err < 0)
					scoutfs_err(sb, "truncate err %d restoring extent after error %lld: ino %llu start %llu len %llu",
						    err, ret, ino, tr.start, tr.len);
				break;
			}
		}

		iblock += tr.len;
	}

	return ret;
}

/*
 * Free blocks inside the logical block range from 'iblock' to 'last',
 * inclusive.
 *
 * If 'offline' is given then blocks are freed an offline mapping is
 * left behind.  Only blocks that have been allocated can be marked
 * offline.
 *
 * If the inode is provided then we update its tracking of the online
 * and offline blocks.  If it's not provided then the inode is being
 * destroyed and isn't reachable, we don't need to update it.
 *
 * The caller is in charge of locking the inode and data, but we may
 * have to modify far more items than fit in a transaction so we're in
 * charge of batching updates into transactions.  If the inode is
 * provided then we're responsible for updating its item as we go.
 */
int scoutfs_data_truncate_items(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, bool offline,
				struct scoutfs_lock *lock)
{
	struct scoutfs_inode_info *si = NULL;
	LIST_HEAD(ind_locks);
	s64 ret = 0;

	WARN_ON_ONCE(inode && !inode_is_locked(inode));

	/* clamp last to the last possible block? */
	if (last > SCOUTFS_BLOCK_SM_MAX)
		last = SCOUTFS_BLOCK_SM_MAX;

	trace_scoutfs_data_truncate_items(sb, iblock, last, offline);

	if (WARN_ON_ONCE(last < iblock))
		return -EINVAL;

	if (inode) {
		si = SCOUTFS_I(inode);
		down_write(&si->extent_sem);
	}

	while (iblock <= last) {
		if (inode)
			ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, true, false);
		else
			ret = scoutfs_hold_trans(sb, false);
		if (ret)
			break;

		if (inode)
			ret = scoutfs_dirty_inode_item(inode, lock);
		else
			ret = 0;

		if (ret == 0)
			ret = truncate_extents(sb, inode, ino, iblock, last,
					       offline, lock);

		if (inode)
			scoutfs_update_inode_item(inode, lock, &ind_locks);
		scoutfs_release_trans(sb);
		if (inode)
			scoutfs_inode_index_unlock(sb, &ind_locks);

		if (ret <= 0)
			break;

		iblock = ret;
		ret = 0;
	}

	if (si)
		up_write(&si->extent_sem);

	return ret;
}

static inline u64 ext_last(struct scoutfs_extent *ext)
{
	return ext->start + ext->len - 1;
}

/*
 * The caller is writing to a logical iblock that doesn't have an
 * allocated extent.  The caller has searched for an extent containing
 * iblock.  If it already existed then it must be unallocated and
 * offline.
 *
 * We implement two preallocation strategies.  Typically we only
 * preallocate for simple streaming writes and limit preallocation while
 * the file is small.   The largest efficient allocation size is
 * typically large enough that it would be unreasonable to allocate that
 * much for all small files.
 *
 * Optionally, we can simply preallocate large empty aligned regions.
 * This can waste a lot of space for small or sparse files but is
 * reasonable when a file population is known to be large and dense but
 * known to be written with non-streaming write patterns.
 */
static int alloc_block(struct super_block *sb, struct inode *inode,
		       struct scoutfs_extent *ext, u64 iblock,
		       struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	struct scoutfs_mount_options opts;
	const u64 ino = scoutfs_ino(inode);
	struct data_ext_args args = {
		.ino = ino,
		.inode = inode,
		.lock = lock,
	};
	struct scoutfs_extent found;
	struct scoutfs_extent pre = {0,};
	bool undo_pre = false;
	u64 blkno = 0;
	u64 online;
	u64 offline;
	u8 flags;
	u64 start;
	u64 count;
	u64 rem;
	int ret;
	int err;

	trace_scoutfs_data_alloc_block_enter(sb, ino, iblock, ext);

	scoutfs_options_read(sb, &opts);

	/* can only allocate over existing unallocated offline extent */
	if (WARN_ON_ONCE(ext->len &&
			 !(iblock >= ext->start && iblock <= ext_last(ext) &&
			  ext->map == 0 && (ext->flags & SEF_OFFLINE))))
		return -EINVAL;

	mutex_lock(&datinf->mutex);

	/* default to single allocation at the written block */
	start = iblock;
	count = 1;
	/* copy existing flags for preallocated regions */
	flags = ext->len ? ext->flags : 0;

	if (ext->len) {
		/*
		 * Assume that offline writers are going to be writing
		 * all the offline extents and try to preallocate the
		 * rest of the unwritten extent.
		 */
		count = ext->len - (iblock - ext->start);

	} else if (opts.data_prealloc_contig_only) {
		/*
		 * Only preallocate when a quick test of the online
		 * block counts looks like we're a simple streaming
		 * write.  Try to write until the next extent but limit
		 * the preallocation size to the number of online
		 * blocks.
		 */
		scoutfs_inode_get_onoff(inode, &online, &offline);
		if (iblock > 1 && iblock == online) {
			ret = scoutfs_ext_next(sb, &data_ext_ops, &args,
					       iblock, 1, &found);
			if (ret < 0 && ret != -ENOENT)
				goto out;
			if (found.len && found.start > iblock)
				count = found.start - iblock;
			else
				count = opts.data_prealloc_blocks;

			count = min(iblock, count);
		}

	} else {
		/*
		 * Preallocation within aligned regions tries to
		 * allocate an extent to fill the hole in the region
		 * that contains iblock.  We'd have to add a bit of plumbing
		 * to find previous extents so we only search for a next
		 * extent from the front of the region and from iblock.
		 */
		div64_u64_rem(iblock, opts.data_prealloc_blocks, &rem);
		start = iblock - rem;
		count = opts.data_prealloc_blocks;
		ret = scoutfs_ext_next(sb, &data_ext_ops, &args, start, 1, &found);
		if (ret < 0 && ret != -ENOENT)
			goto out;

		/* trim count if there's an extent in the region before iblock */
		if (found.len && found.start < iblock) {
			count -= iblock - start;
			start = iblock;
			/* see if there's also an extent after iblock */
			ret = scoutfs_ext_next(sb, &data_ext_ops, &args, iblock, 1, &found);
			if (ret < 0 && ret != -ENOENT)
				goto out;
		}

		/* trim count by next extent after iblock */
		if (found.len && found.start > start && found.start < start + count)
			count = (found.start - start);
	}

	/* overall prealloc limit */
	count = min_t(u64, count, opts.data_prealloc_blocks);

	ret = scoutfs_alloc_data(sb, datinf->alloc, datinf->wri,
				 &datinf->dalloc, count, &blkno, &count);
	if (ret < 0)
		goto out;

	/*
	 * An aligned prealloc attempt that gets a smaller extent can
	 * fail to cover iblock, make sure that it does.  This is a
	 * pathological case so we don't try to move the window past
	 * iblock.  Just enough to cover it, which we know is safe.
	 */
	if (start + count <= iblock)
		start += (iblock - (start + count) + 1);

	if (count > 1) {
		pre.start = start;
		pre.len = count;
		pre.map = blkno;
		pre.flags = flags | SEF_UNWRITTEN;
		ret = scoutfs_ext_set(sb, &data_ext_ops, &args, pre.start,
				      pre.len, pre.map, pre.flags);
		if (ret < 0)
			goto out;
		undo_pre = true;
	}

	ret = scoutfs_ext_set(sb, &data_ext_ops, &args, iblock, 1, blkno + (iblock - start), 0);
	if (ret < 0)
		goto out;

	/* tell the caller we have a single block, could check next? */
	ext->start = iblock;
	ext->len = 1;
	ext->map = blkno + (iblock - start);
	ext->flags = 0;
	ret = 0;
out:
	if (ret < 0 && blkno > 0) {
		if (undo_pre) {
			err = scoutfs_ext_set(sb, &data_ext_ops, &args,
					      pre.start, pre.len, 0, flags);
			BUG_ON(err); /* leaked preallocated extent */
		}
		err = scoutfs_free_data(sb, datinf->alloc, datinf->wri,
				        &datinf->data_freed, blkno, count);
		BUG_ON(err); /* leaked free blocks */
	}

	if (ret == 0) {
		trace_scoutfs_data_alloc(sb, ino, ext);
		trace_scoutfs_data_prealloc(sb, ino, &pre);
	}

	mutex_unlock(&datinf->mutex);

	return ret;
}

static int scoutfs_get_block(struct inode *inode, sector_t iblock,
			     struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	const u64 ino = scoutfs_ino(inode);
	struct super_block *sb = inode->i_sb;
	struct data_ext_args args;
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_extent ext = {0,};
	struct scoutfs_extent un;
	u64 offset;
	int ret;

	WARN_ON_ONCE(create && !inode_is_locked(inode));

	/* make sure caller holds a cluster lock */
	lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!lock)) {
		ret = -EINVAL;
		goto out;
	}

	args.ino = ino;
	args.inode = inode;
	args.lock = lock;

	ret = scoutfs_ext_next(sb, &data_ext_ops, &args, iblock, 1, &ext);
	if (ret == -ENOENT || (ret == 0 && ext.start > iblock))
		memset(&ext, 0, sizeof(ext));
	else if (ret < 0)
		goto out;

	if (ext.len)
		trace_scoutfs_data_get_block_found(sb, ino, &ext);

	/* non-staging callers should have waited on offline blocks */
	if (WARN_ON_ONCE(ext.map && (ext.flags & SEF_OFFLINE) && !si->staging)){
		ret = -EIO;
		goto out;
	}

	/* convert unwritten to written, could be staging */
	if (create && ext.map && (ext.flags & SEF_UNWRITTEN)) {
		un.start = iblock;
		un.len = 1;
		un.map = ext.map + (iblock - ext.start);
		un.flags = ext.flags & ~(SEF_OFFLINE|SEF_UNWRITTEN);
		ret = scoutfs_ext_set(sb, &data_ext_ops, &args,
				      un.start, un.len, un.map, un.flags);
		if (ret == 0) {
			ext = un;
			set_buffer_new(bh);
		}
		goto out;
	}

	/* allocate and map blocks containing our logical block */
	if (create && !ext.map) {
		ret = alloc_block(sb, inode, &ext, iblock, lock);
		if (ret == 0)
			set_buffer_new(bh);
	} else {
		ret = 0;
	}
out:
	/* map usable extent, else leave bh unmapped for sparse reads */
	if (ret == 0 && ext.map && !(ext.flags & SEF_UNWRITTEN)) {
		offset = iblock - ext.start;
		map_bh(bh, inode->i_sb, ext.map + offset);
		bh->b_size = min_t(u64, bh->b_size,
				(ext.len - offset) << SCOUTFS_BLOCK_SM_SHIFT);
		trace_scoutfs_data_get_block_mapped(sb, ino, &ext);
	}

	trace_scoutfs_get_block(sb, scoutfs_ino(inode), iblock, create,
				&ext, ret, bh->b_blocknr, bh->b_size);
	return ret;
}

/*
 * Typically extent item users are serialized by i_mutex.  But page
 * readers only hold the page lock and need to be protected from writers
 * in other pages which can be manipulating neighbouring extents as
 * they split and merge.
 */
static int scoutfs_get_block_read(struct inode *inode, sector_t iblock,
				  struct buffer_head *bh, int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	int ret;

	down_read(&si->extent_sem);
	ret = scoutfs_get_block(inode, iblock, bh, create);
	up_read(&si->extent_sem);

	return ret;
}

int scoutfs_get_block_write(struct inode *inode, sector_t iblock, struct buffer_head *bh,
			    int create)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	int ret;

	down_write(&si->extent_sem);
	ret = scoutfs_get_block(inode, iblock, bh, create);
	up_write(&si->extent_sem);

	return ret;
}

/*
 * This is almost never used.  We can't block on a cluster lock while
 * holding the page lock because lock invalidation gets the page lock
 * while blocking locks.  If a non blocking lock attempt fails we unlock
 * the page and block acquiring the lock.  We unlocked the page so it
 * could have been truncated away, or whatever, so we return
 * AOP_TRUNCATED_PAGE to have the caller try again.
 *
 * A similar process happens if we try to read from an offline extent
 * that a caller hasn't already waited for.  Instead of blocking
 * acquiring the lock we block waiting for the offline extent.  The page
 * lock protects the page from release while we're checking and
 * reading the extent.
 *
 * We can return errors from locking and checking offline extents.  The
 * page is unlocked if we return an error.
 */
static int scoutfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file->f_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	DECLARE_DATA_WAIT(dw);
	int flags;
	int ret;

	flags = SCOUTFS_LKF_REFRESH_INODE | SCOUTFS_LKF_NONBLOCK;
	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, flags, inode,
				 &inode_lock);
	if (ret < 0) {
		unlock_page(page);
		if (ret == -EAGAIN) {
			flags &= ~SCOUTFS_LKF_NONBLOCK;
			ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, flags,
						 inode, &inode_lock);
			if (ret == 0) {
				scoutfs_unlock(sb, inode_lock,
					       SCOUTFS_LOCK_READ);
				ret = AOP_TRUNCATED_PAGE;
			}
		}
		return ret;
	}

	if (scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_ent, inode_lock)) {
		ret = scoutfs_data_wait_check(inode, page_offset(page),
					      PAGE_SIZE, SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_READ, &dw,
					      inode_lock);
		if (ret != 0) {
			unlock_page(page);
			scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
			scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
		}
		if (ret > 0) {
			ret = scoutfs_data_wait(inode, &dw);
			if (ret == 0)
				ret = AOP_TRUNCATED_PAGE;
		}
		if (ret != 0)
			return ret;
	}

	ret = mpage_readpage(page, scoutfs_get_block_read);

	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);

	return ret;
}

#ifndef KC_FILE_AOPS_READAHEAD
/*
 * This is used for opportunistic read-ahead which can throw the pages
 * away if it needs to.  If the caller didn't deal with offline extents
 * then we drop those pages rather than trying to wait.  Whoever is
 * staging offline extents should be doing it in enormous chunks so that
 * read-ahead can ramp up within each staged region.  The check for
 * offline extents is cheap when the inode has no offline extents.
 */
static int scoutfs_readpages(struct file *file, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	struct page *page;
	struct page *tmp;
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &inode_lock);
	if (ret)
		goto out;

	list_for_each_entry_safe(page, tmp, pages, lru) {
		ret = scoutfs_data_wait_check(inode, page_offset(page),
					      PAGE_SIZE, SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_READ, NULL,
					      inode_lock);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			list_del(&page->lru);
			put_page(page);
			if (--nr_pages == 0) {
				ret = 0;
				goto out;
			}
		}
	}

	ret = mpage_readpages(mapping, pages, nr_pages, scoutfs_get_block_read);
out:
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	BUG_ON(!list_empty(pages));
	return ret;
}
#else
static void scoutfs_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->file->f_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &inode_lock);
	if (ret)
		return;

	ret = scoutfs_data_wait_check(inode, readahead_pos(rac),
				      readahead_length(rac), SEF_OFFLINE,
				      SCOUTFS_IOC_DWO_READ, NULL,
				      inode_lock);
	if (ret == 0)
		mpage_readahead(rac, scoutfs_get_block_read);

	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
}
#endif

static int scoutfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, scoutfs_get_block_write, wbc);
}

static int scoutfs_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, scoutfs_get_block_write);
}

/* fsdata allocated in write_begin and freed in write_end */
struct write_begin_data {
	struct list_head ind_locks;
	struct scoutfs_lock *lock;
};

static int scoutfs_write_begin(struct file *file,
			       struct address_space *mapping, loff_t pos,
			       unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd;
	u64 ind_seq;
	int ret;

	trace_scoutfs_write_begin(sb, scoutfs_ino(inode), (__u64)pos, len);

	wbd = kmalloc(sizeof(struct write_begin_data), GFP_NOFS);
	if (!wbd)
		return -ENOMEM;

	INIT_LIST_HEAD(&wbd->ind_locks);
	*fsdata = wbd;

	wbd->lock = scoutfs_per_task_get(&si->pt_data_lock);
	if (WARN_ON_ONCE(!wbd->lock)) {
		ret = -EINVAL;
		goto out;
	}

retry:
	do {
		ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
		      scoutfs_inode_index_prepare(sb, &wbd->ind_locks, inode,
						  true) ?:
		      scoutfs_inode_index_try_lock_hold(sb, &wbd->ind_locks, ind_seq, true);
	} while (ret > 0);
	if (ret < 0)
		goto out;

	/* can't re-enter fs, have trans */
	flags |= AOP_FLAG_NOFS;

	/* generic write_end updates i_size and calls dirty_inode */
	ret = scoutfs_dirty_inode_item(inode, wbd->lock) ?:
	      block_write_begin(mapping, pos, len, flags, pagep,
				scoutfs_get_block_write);
	if (ret < 0) {
		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
		if (ret == -ENOBUFS) {
			/* Retry with a new transaction. */
			scoutfs_inc_counter(sb, data_write_begin_enobufs_retry);
			goto retry;
		}
	}

out:
	if (ret < 0)
		kfree(wbd);
        return ret;
}

/* kinda like __filemap_fdatawrite_range! :P */
static int writepages_sync_none(struct address_space *mapping, loff_t start,
				loff_t end)
{
        struct writeback_control wbc = {
                .sync_mode = WB_SYNC_NONE,
                .nr_to_write = LONG_MAX,
                .range_start = start,
                .range_end = end,
        };

	return mapping->a_ops->writepages(mapping, &wbc);
}

static int scoutfs_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned copied,
			     struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct write_begin_data *wbd = fsdata;
	int ret;

	trace_scoutfs_write_end(sb, scoutfs_ino(inode), page->index, (u64)pos,
				len, copied);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret > 0) {
		if (!si->staging) {
			scoutfs_inode_set_data_seq(inode);
			scoutfs_inode_inc_data_version(inode);
		}

		inode_inc_iversion(inode);
		scoutfs_update_inode_item(inode, wbd->lock, &wbd->ind_locks);
		scoutfs_inode_queue_writeback(inode);
	}
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &wbd->ind_locks);
	kfree(wbd);

	/*
	 * Currently transactions are kept very simple.  Only one is
	 * open at a time and commit excludes concurrent dirtying.  It
	 * writes out all dirty file data during commit.  This can lead
	 * to very long commit latencies with lots of dirty file data.
	 *
	 * This hack tries to minimize these writeback latencies while
	 * keeping concurrent large file strreaming writes from
	 * suffering too terribly.  Every N bytes we kick off background
	 * writbeack on the previous N bytes.  By the time transaction
	 * commit comes along it will find that dirty file blocks have
	 * already been written.
	 */
#define BACKGROUND_WRITEBACK_BYTES (16 * 1024 * 1024)
#define BACKGROUND_WRITEBACK_MASK (BACKGROUND_WRITEBACK_BYTES - 1)
	if (ret > 0 && ((pos + ret) & BACKGROUND_WRITEBACK_MASK) == 0)
		writepages_sync_none(mapping,
				     pos + ret - BACKGROUND_WRITEBACK_BYTES,
				     pos + ret - 1);

	return ret;
}

/*
 * Try to allocate unwritten extents for any unallocated regions of the
 * logical block extent from the caller.  The caller manages locks and
 * transactions.  We limit ourselves to a reasonable number of extents
 * before returning to open another transaction.
 *
 * We return an error or the number of blocks starting at iblock that
 * were successfully processed.  The caller will continue after those
 * blocks until they reach last.
 */
static s64 fallocate_extents(struct super_block *sb, struct inode *inode,
			     u64 iblock, u64 last, struct scoutfs_lock *lock)
{
	DECLARE_DATA_INFO(sb, datinf);
	struct data_ext_args args = {
		.ino = scoutfs_ino(inode),
		.inode = inode,
		.lock = lock,
	};
	struct scoutfs_extent ext;
	u8 ext_fl;
	u64 blkno;
	u64 count;
	s64 done = 0;
	int ret = 0;
	int err;
	int i;

	for (i = 0; iblock <= last && i < EXTENTS_PER_HOLD; i++) {

		ret = scoutfs_ext_next(sb, &data_ext_ops, &args,
				       iblock, 1, &ext);
		if (ret == -ENOENT)
			ret = 0;
		else if (ret < 0)
			break;

		/* default to allocate to end of region */
		count = last - iblock + 1;
		ext_fl = 0;

		if (!ext.len) {
			/* no extent, default alloc from above */

		} else if (ext.start <= iblock && ext.map) {
			/* skip portion of allocated extent */
			count = min_t(u64, count,
				      ext.len - (iblock - ext.start));
			iblock += count;
			done += count;
			continue;

		} else if (ext.start <= iblock && !ext.map) {
			/* alloc portion of unallocated extent */
			count = min_t(u64, count,
				      ext.len - (iblock - ext.start));
			ext_fl = ext.flags;

		} else if (iblock < ext.start) {
			/* alloc hole until next extent */
			count = min_t(u64, count, ext.start - iblock);
		}

		/* limit allocation attempts */
		count = min_t(u64, count, SCOUTFS_FALLOCATE_ALLOC_LIMIT);

		mutex_lock(&datinf->mutex);

		ret = scoutfs_alloc_data(sb, datinf->alloc, datinf->wri,
					 &datinf->dalloc, count,
					 &blkno, &count);
		if (ret == 0) {
			ret = scoutfs_ext_set(sb, &data_ext_ops, &args, iblock,
					      count, blkno,
					      ext_fl | SEF_UNWRITTEN);
			if (ret < 0) {
				err = scoutfs_free_data(sb, datinf->alloc,
							datinf->wri,
							&datinf->data_freed,
							blkno, count);
				BUG_ON(err); /* inconsistent */
			}
		}

		mutex_unlock(&datinf->mutex);

		if (ret < 0)
			break;

		iblock += count;
		done += count;
	}

	if (ret == 0)
		ret = done;

	return ret;
}

/*
 * Modify the extents that map the blocks that store the len byte region
 * starting at offset.
 *
 * The caller has only prevented freezing by entering a fs write
 * context.  We're responsible for all other locking and consistency.
 *
 * This can be used to preallocate files for staging.  We find existing
 * offline extents and allocate block for them and set unwritten.
 */
long scoutfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_lock *lock = NULL;
	LIST_HEAD(ind_locks);
	loff_t end;
	u64 iblock;
	u64 last;
	s64 ret;

	/* XXX support more flags */
        if (mode & ~(FALLOC_FL_KEEP_SIZE)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* catch wrapping */
	if (offset + len < offset) {
		ret = -EINVAL;
		goto out;
	}

	if (len == 0) {
		ret = 0;
		goto out;
	}

	inode_lock(inode);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto out_mutex;

	inode_dio_wait(inode);

	down_write(&si->extent_sem);

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (offset + len > i_size_read(inode))) {
                ret = inode_newsize_ok(inode, offset + len);
                if (ret)
                        goto out_extent;
        }

	iblock = offset >> SCOUTFS_BLOCK_SM_SHIFT;
	last = (offset + len - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

	while(iblock <= last) {

		ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, false, true);
		if (ret)
			goto out_extent;

		ret = fallocate_extents(sb, inode, iblock, last, lock);

		if (ret >= 0 && !(mode & FALLOC_FL_KEEP_SIZE)) {
			end = (iblock + ret) << SCOUTFS_BLOCK_SM_SHIFT;
			if (end > offset + len)
				end = offset + len;
			if (end > i_size_read(inode)) {
				i_size_write(inode, end);
				inode_inc_iversion(inode);
				scoutfs_inode_inc_data_version(inode);
			}
		}
		if (ret >= 0)
			scoutfs_update_inode_item(inode, lock, &ind_locks);
		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &ind_locks);

		/* txn couldn't meet the request. Let's try with a new txn */
		if (ret == -ENOBUFS) {
			scoutfs_inc_counter(sb, data_fallocate_enobufs_retry);
			continue;
		}

		if (ret <= 0)
			goto out_extent;

		iblock += ret;
		ret = 0;
	}

out_extent:
	up_write(&si->extent_sem);
out_mutex:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	inode_unlock(inode);

out:
	trace_scoutfs_data_fallocate(sb, ino, mode, offset, len, ret);
	return ret;
}

/*
 * A special case of initializing a single large offline extent.  This
 * chooses not to deal with any existing extents.  It can only be used
 * on regular files with no data extents.  It's used to restore a file
 * with an offline extent which can then trigger staging.
 *
 * The caller has taken care of locking the inode.  We're updating the
 * inode offline count as we create the offline extent so we take care
 * of the index locking, updating, and transaction.
 */
int scoutfs_data_init_offline_extent(struct inode *inode, u64 size,
				     struct scoutfs_lock *lock)

{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct data_ext_args args = {
		.ino = scoutfs_ino(inode),
		.inode = inode,
		.lock = lock,
	};
	const u64 count = DIV_ROUND_UP(size, SCOUTFS_BLOCK_SM_SIZE);
	LIST_HEAD(ind_locks);
	u64 on;
	u64 off;
	int ret;

	scoutfs_inode_get_onoff(inode, &on, &off);

	/* caller should have checked */
	if (on > 0 || off > 0) {
		ret = -EINVAL;
		goto out;
	}

	/* we're updating meta_seq with offline block count */
	ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, false, true);
	if (ret < 0)
		goto out;

	ret = scoutfs_dirty_inode_item(inode, lock);
	if (ret < 0)
		goto unlock;

	down_write(&si->extent_sem);
	ret = scoutfs_ext_insert(sb, &data_ext_ops, &args,
				 0, count, 0, SEF_OFFLINE);
	up_write(&si->extent_sem);
	if (ret < 0)
		goto unlock;

	scoutfs_update_inode_item(inode, lock, &ind_locks);

unlock:
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
	ret = 0;
out:
	return ret;
}

/*
 * We're using truncate_inode_pages_range to maintain consistency
 * between the page cache and extents that just changed.  We have to
 * call with full aligned page offsets or it thinks that it should leave
 * behind a zeroed partial page.
 */
static void truncate_inode_pages_extent(struct inode *inode, u64 start, u64 len)
{
	truncate_inode_pages_range(&inode->i_data,
				start << SCOUTFS_BLOCK_SM_SHIFT,
				((start + len) << SCOUTFS_BLOCK_SM_SHIFT) - 1);
}

/*
 * Move extents from one file to another.  The behaviour is more fully
 * explained above the move_blocks ioctl argument structure definition.
 *
 * The caller has processed the ioctl args and performed the most basic
 * argument sanity and inode checks, but we perform more detailed inode
 * checks once we have the inode lock and refreshed inodes.  Our job is
 * to safely lock the two files and move the extents.
 */
#define MOVE_DATA_EXTENTS_PER_HOLD 16
int scoutfs_data_move_blocks(struct inode *from, u64 from_off,
			     u64 byte_len, struct inode *to, u64 to_off, bool is_stage,
			     u64 data_version)
{
	struct scoutfs_inode_info *from_si = SCOUTFS_I(from);
	struct scoutfs_inode_info *to_si = SCOUTFS_I(to);
	struct super_block *sb = from->i_sb;
	struct scoutfs_lock *from_lock = NULL;
	struct scoutfs_lock *to_lock = NULL;
	struct data_ext_args from_args;
	struct data_ext_args to_args;
	struct scoutfs_extent ext;
	struct kc_timespec cur_time;
	LIST_HEAD(locks);
	bool done = false;
	loff_t from_size;
	loff_t to_size;
	u64 from_offline;
	u64 to_offline;
	u64 from_start;
	u64 to_start;
	u64 from_iblock;
	u64 to_iblock;
	u64 count;
	u64 junk;
	u64 seq;
	u64 map;
	u64 len;
	int ret;
	int err;
	int i;

	lock_two_nondirectories(from, to);

	ret = scoutfs_lock_inodes(sb, SCOUTFS_LOCK_WRITE,
				  SCOUTFS_LKF_REFRESH_INODE, from, &from_lock,
				  to, &to_lock, NULL, NULL, NULL, NULL);
	if (ret)
		goto out;

	if ((from_off & SCOUTFS_BLOCK_SM_MASK) ||
	    (to_off & SCOUTFS_BLOCK_SM_MASK) ||
	    ((byte_len & SCOUTFS_BLOCK_SM_MASK) &&
	     (from_off + byte_len != i_size_read(from)))) {
		ret = -EINVAL;
		goto out;
	}

	if (is_stage && (data_version != SCOUTFS_I(to)->data_version)) {
		ret = -ESTALE;
		goto out;
	}

	from_iblock = from_off >> SCOUTFS_BLOCK_SM_SHIFT;
	count = (byte_len + SCOUTFS_BLOCK_SM_MASK) >> SCOUTFS_BLOCK_SM_SHIFT;
	to_iblock = to_off >> SCOUTFS_BLOCK_SM_SHIFT;
	from_start = from_iblock;

	/* only move extent blocks inside i_size, careful not to wrap */
	from_size = i_size_read(from);
	if (from_off >= from_size) {
		ret = 0;
		goto out;
	}
	if (from_off + byte_len > from_size)
		count = ((from_size - from_off) + SCOUTFS_BLOCK_SM_MASK) >> SCOUTFS_BLOCK_SM_SHIFT;

	if (S_ISDIR(from->i_mode) || S_ISDIR(to->i_mode)) {
		ret = -EISDIR;
		goto out;
	}

	if (!S_ISREG(from->i_mode) || !S_ISREG(to->i_mode)) {
		ret = -EINVAL;
		goto out;
	}

	ret = inode_permission(from, MAY_WRITE) ?:
	      inode_permission(to, MAY_WRITE);
	if (ret < 0)
		goto out;

	/* can't stage once data_version changes */
	scoutfs_inode_get_onoff(from, &junk, &from_offline);
	scoutfs_inode_get_onoff(to, &junk, &to_offline);
	if (from_offline || (to_offline && !is_stage)) {
		ret = -ENODATA;
		goto out;
	}

	from_args = (struct data_ext_args) {
		.ino = scoutfs_ino(from),
		.inode = from,
		.lock = from_lock,
	};

	to_args = (struct data_ext_args) {
		.ino = scoutfs_ino(to),
		.inode = to,
		.lock = to_lock,
	};

	inode_dio_wait(from);
	inode_dio_wait(to);

	ret = filemap_write_and_wait_range(&from->i_data, from_off,
				   from_off + byte_len - 1);
	if (ret < 0)
		goto out;

	for (;;) {
		ret = scoutfs_inode_index_start(sb, &seq) ?:
		      scoutfs_inode_index_prepare(sb, &locks, from, true) ?:
		      scoutfs_inode_index_prepare(sb, &locks, to, true) ?:
		      scoutfs_inode_index_try_lock_hold(sb, &locks, seq, false);
		if (ret > 0)
			continue;
		if (ret < 0)
			goto out;

		ret = scoutfs_dirty_inode_item(from, from_lock) ?:
		      scoutfs_dirty_inode_item(to, to_lock);
		if (ret < 0)
			goto out;

		down_write_two(&from_si->extent_sem, &to_si->extent_sem);

		/* arbitrarily limit the number of extents per trans hold */
		for (i = 0; i < MOVE_DATA_EXTENTS_PER_HOLD; i++) {
			struct scoutfs_extent off_ext;

			/* find the next extent to move */
			ret = scoutfs_ext_next(sb, &data_ext_ops, &from_args,
					       from_start, 1, &ext);
			if (ret < 0) {
				if (ret == -ENOENT) {
					done = true;
					ret = 0;
				}
				break;
			}

			/* done if next extent starts after moving region */
			if (ext.start >= from_iblock + count) {
				done = true;
				ret = 0;
				break;
			}

			from_start = max(ext.start, from_iblock);
			map = ext.map + (from_start - ext.start);
			len = min(from_iblock + count, ext.start + ext.len) - from_start;
			to_start = to_iblock + (from_start - from_iblock);

			/* we'd get stuck, shouldn't happen */
			if (WARN_ON_ONCE(len == 0)) {
				ret = -EIO;
				goto out;
			}

			if (is_stage) {
				ret = scoutfs_ext_next(sb, &data_ext_ops, &to_args,
						       to_start, 1, &off_ext);
				if (ret)
					break;

				if (!scoutfs_ext_inside(to_start, len, &off_ext) ||
				    !(off_ext.flags & SEF_OFFLINE)) {
					ret = -EINVAL;
					break;
				}

				ret = scoutfs_ext_set(sb, &data_ext_ops, &to_args,
							 to_start, len,
							 map, ext.flags);
			} else {
				/* insert the new, fails if it overlaps */
				ret = scoutfs_ext_insert(sb, &data_ext_ops, &to_args,
							 to_start, len,
							 map, ext.flags);
			}
			if (ret < 0)
				break;

			/* remove the old, possibly splitting */
			ret = scoutfs_ext_set(sb, &data_ext_ops, &from_args,
					      from_start, len, 0, 0);
			if (ret < 0) {
				if (is_stage) {
					/* re-mark dest range as offline */
					WARN_ON_ONCE(!(off_ext.flags & SEF_OFFLINE));
					err = scoutfs_ext_set(sb, &data_ext_ops, &to_args,
							      to_start, len,
							      0, off_ext.flags);
				} else {
					/* remove inserted new on err */
					err = scoutfs_ext_remove(sb, &data_ext_ops,
								 &to_args, to_start,
								 len);
				}
				BUG_ON(err); /* XXX inconsistent */
				break;
			}

			trace_scoutfs_data_move_blocks(sb, scoutfs_ino(from),
						       from_start, len, map,
						       ext.flags,
						       scoutfs_ino(to),
						       to_start);

			/* moved extent might extend i_size */
			to_size = (to_start + len) << SCOUTFS_BLOCK_SM_SHIFT;
			if (to_size > i_size_read(to)) {
				/* while maintaining final partial */
				from_size = (from_start + len) <<
						SCOUTFS_BLOCK_SM_SHIFT;
				if (from_size > i_size_read(from))
					to_size -= from_size -
							i_size_read(from);
				i_size_write(to, to_size);
			}

			/* find next after moved extent, avoiding wrapping */
			if (from_start + len < from_start)
				from_start = from_iblock + count + 1;
			else
				from_start += len;
		}


		up_write(&from_si->extent_sem);
		up_write(&to_si->extent_sem);

		cur_time = current_time(from);
		if (!is_stage) {
			to->i_ctime = to->i_mtime = cur_time;
			inode_inc_iversion(to);
			scoutfs_inode_inc_data_version(to);
			scoutfs_inode_set_data_seq(to);
		}
		from->i_ctime = from->i_mtime = cur_time;
		inode_inc_iversion(from);
		scoutfs_inode_inc_data_version(from);
		scoutfs_inode_set_data_seq(from);

		scoutfs_update_inode_item(from, from_lock, &locks);
		scoutfs_update_inode_item(to, to_lock, &locks);
		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &locks);

		if (ret < 0 || done)
			break;
	}

	/* remove any cached pages from old extents */
	truncate_inode_pages_extent(from, from_iblock, count);
	truncate_inode_pages_extent(to, to_iblock, count);

out:
	scoutfs_unlock(sb, from_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, to_lock, SCOUTFS_LOCK_WRITE);

	unlock_two_nondirectories(from, to);

	return ret;
}

/*
 * This copies to userspace :/
 */
static int fill_extent(struct fiemap_extent_info *fieinfo,
		       struct scoutfs_extent *ext, u32 fiemap_flags)
{
	u32 flags;

	if (ext->len == 0)
		return 0;

	flags = fiemap_flags;
	if (ext->flags & SEF_OFFLINE)
		flags |= FIEMAP_EXTENT_UNKNOWN;
	else if (ext->flags & SEF_UNWRITTEN)
		flags |= FIEMAP_EXTENT_UNWRITTEN;

	return fiemap_fill_next_extent(fieinfo,
				       ext->start << SCOUTFS_BLOCK_SM_SHIFT,
				       ext->map << SCOUTFS_BLOCK_SM_SHIFT,
				       ext->len << SCOUTFS_BLOCK_SM_SHIFT,
				       flags);
}

/*
 * Return all the file's extents whose blocks overlap with the caller's
 * byte region.  We set _LAST on the last extent and _UNKNOWN on offline
 * extents.
 */
int scoutfs_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			u64 start, u64 len)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_extent ext;
	struct scoutfs_extent cur;
	struct data_ext_args args;
	u32 last_flags;
	u64 iblock;
	u64 last;
	int ret;

	if (len == 0) {
		ret = 0;
		goto out;
	}

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		goto out;

	inode_lock(inode);
	down_read(&si->extent_sem);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &lock);
	if (ret)
		goto unlock;

	args.ino = ino;
	args.inode = inode;
	args.lock = lock;

	/* use a dummy extent to track */
	memset(&cur, 0, sizeof(cur));
	last_flags = 0;

	iblock = start >> SCOUTFS_BLOCK_SM_SHIFT;
	last = (start + len - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

	while (iblock <= last) {
		ret = scoutfs_ext_next(sb, &data_ext_ops, &args,
				       iblock, 1, &ext);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			last_flags = FIEMAP_EXTENT_LAST;
			break;
		}

		trace_scoutfs_data_fiemap_extent(sb, ino, &ext);

		if (ext.start > last) {
			/* not setting _LAST, it's for end of file */
			ret = 0;
			break;
		}

		if (scoutfs_ext_can_merge(&cur, &ext)) {
			/* merged extents could be greater than input len */
			cur.len += ext.len;
		} else {
			ret = fill_extent(fieinfo, &cur, 0);
			if (ret != 0)
				goto unlock;
			cur = ext;
		}

		iblock = ext.start + ext.len;
	}

	if (cur.len)
		ret = fill_extent(fieinfo, &cur, last_flags);
unlock:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	up_read(&si->extent_sem);
	inode_unlock(inode);

out:
	if (ret == 1)
		ret = 0;

	trace_scoutfs_data_fiemap(sb, start, len, ret);

	return ret;
}

/*
 * Insert a new waiter.  This supports multiple tasks waiting for the
 * same ino and iblock by also comparing waiters by their addresses.
 */
static void insert_offline_waiting(struct rb_root *root,
				   struct scoutfs_data_wait *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_data_wait *dw;
	int cmp;

	while (*node) {
		parent = *node;
		dw = rb_entry(*node, struct scoutfs_data_wait, node);

		cmp = scoutfs_cmp_u64s(ins->ino, dw->ino) ?:
		      scoutfs_cmp_u64s(ins->iblock, dw->iblock) ?:
		      scoutfs_cmp(ins, dw);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else
			node = &(*node)->rb_right;
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);
}

static struct scoutfs_data_wait *next_data_wait(struct rb_root *root, u64 ino,
						u64 iblock)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct scoutfs_data_wait *next = NULL;
	struct scoutfs_data_wait *dw;
	int cmp;

	while (*node) {
		parent = *node;
		dw = rb_entry(*node, struct scoutfs_data_wait, node);

		/* go left when ino/iblock are equal to get first task */
		cmp = scoutfs_cmp_u64s(ino, dw->ino) ?:
		      scoutfs_cmp_u64s(iblock, dw->iblock);
		if (cmp <= 0) {
			node = &(*node)->rb_left;
			next = dw;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		}
	}

	return next;
}

static struct scoutfs_data_wait *dw_next(struct scoutfs_data_wait *dw)
{
	struct rb_node *node = rb_next(&dw->node);
	if (node)
		return container_of(node, struct scoutfs_data_wait, node);
	return NULL;
}

/*
 * Check if we should wait by looking for extents whose flags match.
 * Returns 0 if no extents were found or any error encountered.
 *
 * The caller must have acquired a cluster lock that covers the extent
 * items.  We acquire the extent_sem to protect our read from writers in
 * other tasks.
 *
 * Returns 1 if any file extents in the caller's region matched.  If the
 * wait struct is provided then it is initialized to be woken when the
 * extents change after the caller unlocks after the check.  The caller
 * must come through _data_wait() to clean up the wait struct if we set
 * it up.
 */
int scoutfs_data_wait_check(struct inode *inode, loff_t pos, loff_t len,
			    u8 sef, u8 op, struct scoutfs_data_wait *dw,
			    struct scoutfs_lock *lock)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct data_ext_args args = {
		.ino = ino,
		.inode = inode,
		.lock = lock,
	};
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	DECLARE_DATA_WAITQ(inode, wq);
	struct scoutfs_extent ext = {0,};
	u64 iblock;
	u64 last_block;
	u64 on;
	u64 off;
	int ret = 0;

	if (WARN_ON_ONCE(sef & SEF_UNKNOWN) ||
	    WARN_ON_ONCE(op & SCOUTFS_IOC_DWO_UNKNOWN) ||
	    WARN_ON_ONCE(dw && !RB_EMPTY_NODE(&dw->node)) ||
	    WARN_ON_ONCE(pos + len < pos)) {
		ret = -EINVAL;
		goto out;
	}

	if ((sef & SEF_OFFLINE)) {
		scoutfs_inode_get_onoff(inode, &on, &off);
		if (off == 0) {
			ret = 0;
			goto out;
		}
	}

	down_read(&si->extent_sem);

	iblock = pos >> SCOUTFS_BLOCK_SM_SHIFT;
	last_block = (pos + len - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

	while(iblock <= last_block) {
		ret = scoutfs_ext_next(sb, &data_ext_ops, &args,
				       iblock, 1, &ext);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		if (ext.start > last_block) {
			ret = 0;
			break;
		}

		if (sef & ext.flags) {
			if (dw) {
				dw->chg = atomic64_read(&wq->changed);
				dw->ino = ino;
				dw->iblock = max(iblock, ext.start);
				dw->op = op;

				spin_lock(&rt->lock);
				insert_offline_waiting(&rt->root, dw);
				spin_unlock(&rt->lock);
			}

			ret = 1;
			break;
		}

		iblock = ext.start + ext.len;
	}

	up_read(&si->extent_sem);

out:
	trace_scoutfs_data_wait_check(sb, ino, pos, len, sef, op, &ext, ret);

	return ret;
}

bool scoutfs_data_wait_found(struct scoutfs_data_wait *dw)
{
	return !RB_EMPTY_NODE(&dw->node);
}

int scoutfs_data_wait_check_iov(struct inode *inode, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos, u8 sef,
				u8 op, struct scoutfs_data_wait *dw,
				struct scoutfs_lock *lock)
{
	unsigned long i;
	int ret = 0;

	for (i = 0; i < nr_segs; i++) {
		if (iov[i].iov_len == 0)
			continue;

		ret = scoutfs_data_wait_check(inode, pos, iov[i].iov_len, sef,
					      op, dw, lock);
		if (ret != 0)
			break;

		pos += iov[i].iov_len;
	}

	return ret;
}

int scoutfs_data_wait(struct inode *inode, struct scoutfs_data_wait *dw)
{
	DECLARE_DATA_WAIT_ROOT(inode->i_sb, rt);
	DECLARE_DATA_WAITQ(inode, wq);
	int ret;

	ret = wait_event_interruptible(wq->waitq,
					atomic64_read(&wq->changed) != dw->chg);

	spin_lock(&rt->lock);
	rb_erase(&dw->node, &rt->root);
	RB_CLEAR_NODE(&dw->node);
	if (!ret && dw->err)
		ret = dw->err;
	spin_unlock(&rt->lock);

	return ret;
}

void scoutfs_data_wait_changed(struct inode *inode)
{
	DECLARE_DATA_WAITQ(inode, wq);

	atomic64_inc(&wq->changed);
	wake_up(&wq->waitq);
}

long scoutfs_data_wait_err(struct inode *inode, u64 sblock, u64 eblock,
			   u64 op, long err)
{
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	struct scoutfs_data_wait *dw;
	long nr = 0;

	if (!err)
		return 0;

	spin_lock(&rt->lock);

	for (dw = next_data_wait(&rt->root, ino, sblock);
	     dw; dw = dw_next(dw)) {
		if (dw->ino != ino || dw->iblock > eblock)
			break;
		if ((dw->op & op) && !dw->err) {
			dw->err = err;
			nr++;
		}
	}

	spin_unlock(&rt->lock);
	if (nr)
		scoutfs_data_wait_changed(inode);
	return nr;
}

int scoutfs_data_waiting(struct super_block *sb, u64 ino, u64 iblock,
			 struct scoutfs_ioctl_data_waiting_entry *dwe,
			 unsigned int nr)
{
	DECLARE_DATA_WAIT_ROOT(sb, rt);
	struct scoutfs_data_wait *dw;
	int ret = 0;

	spin_lock(&rt->lock);

	dw = next_data_wait(&rt->root, ino, iblock);
	while (dw && ret < nr) {

		dwe->ino = dw->ino;
		dwe->iblock = dw->iblock;
		dwe->op = dw->op;

		while ((dw = dw_next(dw)) &&
		       (dw->ino == dwe->ino && dw->iblock == dwe->iblock)) {
			dwe->op |= dw->op;
		}

		dwe++;
		ret++;
	}

	spin_unlock(&rt->lock);

	return ret;
}

const struct address_space_operations scoutfs_file_aops = {
	.readpage		= scoutfs_readpage,
#ifndef KC_FILE_AOPS_READAHEAD
	.readpages		= scoutfs_readpages,
#else
	.readahead		= scoutfs_readahead,
#endif
	.writepage		= scoutfs_writepage,
	.writepages		= scoutfs_writepages,
	.write_begin		= scoutfs_write_begin,
	.write_end		= scoutfs_write_end,
};

const struct file_operations scoutfs_file_fops = {
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= scoutfs_file_aio_read,
	.aio_write	= scoutfs_file_aio_write,
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
	.llseek		= scoutfs_file_llseek,
	.fallocate	= scoutfs_fallocate,
};

void scoutfs_data_init_btrees(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_log_trees *lt)
{
	DECLARE_DATA_INFO(sb, datinf);

	mutex_lock(&datinf->mutex);

	datinf->alloc = alloc;
	datinf->wri = wri;
	scoutfs_dalloc_init(&datinf->dalloc, &lt->data_avail);
	datinf->data_freed = lt->data_freed;

	mutex_unlock(&datinf->mutex);
}

void scoutfs_data_get_btrees(struct super_block *sb,
			     struct scoutfs_log_trees *lt)
{
	DECLARE_DATA_INFO(sb, datinf);

	mutex_lock(&datinf->mutex);

	scoutfs_dalloc_get_root(&datinf->dalloc, &lt->data_avail);
	lt->data_freed = datinf->data_freed;

	mutex_unlock(&datinf->mutex);
}

/*
 * This should be called before preparing the allocators for the commit
 * because it can allocate and free btree blocks in the data allocator.
 */
int scoutfs_data_prepare_commit(struct super_block *sb)
{
	DECLARE_DATA_INFO(sb, datinf);
	int ret;

	mutex_lock(&datinf->mutex);
	ret = scoutfs_dalloc_return_cached(sb, datinf->alloc, datinf->wri,
					   &datinf->dalloc);
	mutex_unlock(&datinf->mutex);

	return ret;
}

/*
 * Return true if the data allocator is lower than the caller's
 * requirement and we haven't been told by the server that we're out of
 * free extents.
 */
bool scoutfs_data_alloc_should_refill(struct super_block *sb, u64 blocks)
{
	DECLARE_DATA_INFO(sb, datinf);

	return (scoutfs_dalloc_total_len(&datinf->dalloc) < blocks) &&
	       !(le32_to_cpu(datinf->dalloc.root.flags) & SCOUTFS_ALLOC_FLAG_LOW);
}

int scoutfs_data_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf;

	datinf = kzalloc(sizeof(struct data_info), GFP_KERNEL);
	if (!datinf)
		return -ENOMEM;

	datinf->sb = sb;
	mutex_init(&datinf->mutex);

	sbi->data_info = datinf;
	return 0;
}

void scoutfs_data_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct data_info *datinf = sbi->data_info;

	if (datinf) {
		sbi->data_info = NULL;
		kfree(datinf);
	}
}
