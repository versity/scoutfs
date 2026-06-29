/*
 * Copyright (C) 2026 Versity Software, Inc.  All rights reserved.
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
#include <linux/pagemap.h>
#include <linux/iomap.h>

#include "format.h"
#include "super.h"
#include "inode.h"
#include "key.h"
#include "counters.h"
#include "scoutfs_trace.h"
#include "item.h"
#include "btree.h"
#include "lock.h"
#include "ext.h"
#include "iomap.h"
#include "msg.h"
#include "trans.h"

static void scoutfs_set_iomap(struct inode *inode, struct iomap *iomap,
			      struct scoutfs_extent *ext, loff_t offset,
			      u64 iblock, loff_t length)
{
	struct super_block *sb = inode->i_sb;

	iomap->flags |= IOMAP_F_BUFFER_HEAD;
	iomap->bdev = sb->s_bdev;

	if (offset + length > i_size_read(inode))
		iomap->flags |= IOMAP_F_DIRTY;

	if (ext->len == 0 || ext->start > iblock) {
		iomap->type = IOMAP_HOLE;
		iomap->addr = IOMAP_NULL_ADDR;
		iomap->offset = offset;

		if (ext->len > 0) {
			/* There's a hole at the starting offset */
			iomap->length = min_t(loff_t,
					(ext->start - iblock) << SCOUTFS_BLOCK_SM_SHIFT,
					length);
		} else {
			/* There's an implicit hole at EOF */
			iomap->length = length;
		}

		goto out;
	}

	if (ext->flags & SEF_OFFLINE) {
		iomap->type = IOMAP_DELALLOC;
		iomap->addr = IOMAP_NULL_ADDR;
	} else if (ext->flags & SEF_UNWRITTEN) {
		iomap->type = IOMAP_UNWRITTEN;
		iomap->addr = (u64) ext->map << SCOUTFS_BLOCK_SM_SHIFT;
		iomap->flags |= IOMAP_F_NEW;
	} else if (ext->map) {
		iomap->type = IOMAP_MAPPED;
		iomap->addr = (u64) ext->map << SCOUTFS_BLOCK_SM_SHIFT;
	} else {
		WARN_ON(true); /* holes should've been handled above */
	}

	iomap->offset = (u64) ext->start << SCOUTFS_BLOCK_SM_SHIFT;
	iomap->length = (u64) ext->len << SCOUTFS_BLOCK_SM_SHIFT;

out:
	trace_scoutfs_set_iomap(sb, scoutfs_ino(inode), iblock, length, iomap->type,
				iomap->flags, iomap->offset, iomap->length, ext->map);
}

static int scoutfs_iomap_begin_report(struct inode *inode, loff_t offset, loff_t length,
				      unsigned int flags, struct iomap *iomap,
				      struct iomap *srcmap)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_extent ext;
	struct data_ext_args args;
	u64 iblock;
	int ret;

	WARN_ON_ONCE(flags & ~(IOMAP_REPORT|IOMAP_DIRECT|IOMAP_WRITE|IOMAP_NOWAIT));
	WARN_ON(!inode_is_locked(inode));

	iblock = offset >> SCOUTFS_BLOCK_SM_SHIFT;

	/* make sure caller holds a cluster lock */
	lock = scoutfs_per_task_get(&si->pt_data_lock);
	BUG_ON(!lock);

	args.ino = ino;
	args.inode = inode;
	args.lock = lock;

	memset(&ext, 0, sizeof(ext));

	down_read(&si->extent_sem);

	ret = scoutfs_ext_next(sb, &data_ext_ops, &args, iblock, 1, &ext);

	up_read(&si->extent_sem);

	if (ret == -ENOENT)
		ret = 0;

	if (ret == 0)
		scoutfs_set_iomap(inode, iomap, &ext, offset, iblock, length);

	return ret;
}

static int scoutfs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
			       unsigned int flags, struct iomap *iomap,
			       struct iomap *srcmap)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_lock *data_lock = NULL;
	struct scoutfs_extent ext;
	struct data_ext_args args;
	u64 iblock;
	int ret;

	WARN_ON_ONCE(flags & ~(IOMAP_REPORT|IOMAP_DIRECT|IOMAP_WRITE|IOMAP_NOWAIT));
	WARN_ON_ONCE(!rwsem_is_locked(&si->extent_sem));

	iblock = offset >> SCOUTFS_BLOCK_SM_SHIFT;

	/* make sure caller holds a cluster lock */
	data_lock = scoutfs_per_task_get(&si->pt_data_lock);
	BUG_ON(!data_lock);

	args.ino = ino;
	args.inode = inode;
	args.lock = data_lock;

	memset(&ext, 0, sizeof(ext));

	if (flags & IOMAP_WRITE) {
		ret = scoutfs_ext_next(sb, &data_ext_ops, &args, iblock, 1, &ext);

		if (ret == -ENOENT)
			ret = 0;
		if (ret < 0)
			goto out;

		/* non-staging callers should have waited on offline blocks */
		if (WARN_ON_ONCE(ext.map && (ext.flags & SEF_OFFLINE) && !si->staging)){
			ret = -EIO;
			goto out;
		}

		if (!si->staging) {
			ret = scoutfs_inode_check_retention(inode);
			if (ret < 0)
				goto out;
		}

		if (ext.start > iblock)
			memset(&ext, 0, sizeof(ext));

		/* No need to allocate space */
		if (ext.map) {
			trace_scoutfs_data_get_block_found(sb, ino, &ext);
			goto out;
		}

		ret = scoutfs_data_alloc_block(sb, inode, &ext, iblock, data_lock);
		if (ret == 0)
			iomap->flags |= IOMAP_F_NEW;
	} else {
		ret = scoutfs_ext_next(sb, &data_ext_ops, &args, iblock, 1, &ext);

		if (ret == -ENOENT)
			ret = 0;

		if (ext.len)
			trace_scoutfs_data_get_block_found(sb, ino, &ext);
	}

out:
	if (ret == 0)
		scoutfs_set_iomap(inode, iomap, &ext, offset, iblock, length);

	return ret;
}

static int scoutfs_iomap_end(struct inode *inode, loff_t offset, loff_t length,
			     ssize_t written, unsigned flags, struct iomap *iomap)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *data_lock = NULL;
	struct list_head *inode_locks = NULL;
	struct scoutfs_extent un;
	struct data_ext_args args;
	u64 end_blk;
	int ret;

	if (!(flags & IOMAP_WRITE))
		return 0;

	/*
	 * If we hit an error during a direct I/O write, tell the iomap layer to fall
	 * back to buffered I/O by returning the magic value -ENOTBLK.
	 */
	if (flags & (IOMAP_WRITE | IOMAP_DIRECT) && written == 0)
		return -ENOTBLK;

	data_lock = scoutfs_per_task_get(&si->pt_data_lock);
	BUG_ON(!data_lock);

	inode_locks = scoutfs_per_task_get(&si->pt_inode_locks);
	BUG_ON(!inode_locks);

	/* convert unwritten to written, could be staging */
	if (iomap->type == IOMAP_UNWRITTEN) {
		args.ino = scoutfs_ino(inode);
		args.inode = inode;
		args.lock = data_lock;

		/* This is the file block where this write began */
		un.start = offset >> SCOUTFS_BLOCK_SM_SHIFT;

		/* This is the file block where this write ended */
		end_blk = (offset + written - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

		/* We wrote this many blocks (rounded up) */
		un.len = (end_blk - un.start) + 1;

		/* Move the phys map start forward to reflect the start of this write */
		un.map = (iomap->addr >> SCOUTFS_BLOCK_SM_SHIFT) +
			 (un.start - (iomap->offset >> SCOUTFS_BLOCK_SM_SHIFT));

		un.flags = 0;

		ret = scoutfs_ext_set(sb, &data_ext_ops, &args, un.start, un.len,
				      un.map, un.flags);
		BUG_ON(ret);  /* uh-oh, we already wrote those blocks */
	}

	if (offset + written > i_size_read(inode))
		i_size_write(inode, offset + written);

	return ret;
}

const struct iomap_ops scoutfs_iomap_report_ops = {
	.iomap_begin    = scoutfs_iomap_begin_report,
};

const struct iomap_ops scoutfs_iomap_ops = {
	.iomap_begin	= scoutfs_iomap_begin,
	.iomap_end	= scoutfs_iomap_end,
};
