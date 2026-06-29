/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <linux/aio.h>
#include <linux/iomap.h>

#include "format.h"
#include "super.h"
#include "data.h"
#include "scoutfs_trace.h"
#include "lock.h"
#include "file.h"
#include "inode.h"
#include "per_task.h"
#include "omap.h"
#include "quota.h"
#include "iomap.h"
#include "trans.h"
#include "msg.h"

#ifdef KC_USE_IOMAP_FOR_IO
static bool scoutfs_should_use_dio(struct kiocb *iocb, struct iov_iter *iter)
{
	/* Current offset must be aligned */
	if (iocb->ki_pos & SCOUTFS_BLOCK_SM_MASK)
		return false;

	if (iov_iter_alignment(iter) & SCOUTFS_BLOCK_SM_MASK)
		return false;

	return true;
}

/* copied from fs/gfs2/file.c */
static inline bool should_fault_in_pages(struct iov_iter *i,
					 struct kiocb *iocb,
					 size_t *prev_count,
					 size_t *window_size)
{
	size_t count = iov_iter_count(i);
	size_t size, offs;

	if (!count)
		return false;
	if (!user_backed_iter(i))
		return false;

	size = PAGE_SIZE;
	offs = offset_in_page(iocb->ki_pos);
	if (*prev_count != count || !*window_size) {
		size_t nr_dirtied;

		nr_dirtied = max(current->nr_dirtied_pause -
				current->nr_dirtied, 8);
		size = min_t(size_t, SZ_1M, nr_dirtied << PAGE_SHIFT);
	}

	*prev_count = count;
	*window_size = size - offs;
	return true;
}

static int lock_for_iomap_read(struct inode *inode, bool nowait,
			       struct scoutfs_per_task_entry *pt_extent_ent)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	if (nowait) {
		if (!down_read_trylock(&si->extent_sem))
			return -EAGAIN;
	} else {
		down_read(&si->extent_sem);
	}

	if (!scoutfs_per_task_add_excl(&si->pt_extent_sem, pt_extent_ent, pt_extent_ent))
		WARN_ON_ONCE(true);

	return 0;
}

static void unlock_for_iomap_read(struct inode *inode,
				  struct scoutfs_per_task_entry *pt_extent_ent)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	scoutfs_per_task_del(&si->pt_extent_sem, pt_extent_ent);
	up_read(&si->extent_sem);
}

static ssize_t scoutfs_file_buffered_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_extent_ent);
	size_t prev_count = 0;
	size_t window_size = 0;
	size_t read = 0;
	bool locked = false;
	ssize_t ret;

	pagefault_disable();
	iocb->ki_flags |= IOCB_NOIO;
	ret = generic_file_read_iter(iocb, to);
	iocb->ki_flags &= ~IOCB_NOIO;
	pagefault_enable();

	if (ret >= 0) {
		if (iov_iter_count(to) == 0)
			return ret;
		read = ret;
	} else if (ret != -EFAULT) {
		if (ret != -EAGAIN)
			return ret;
	}

retry:
	ret = lock_for_iomap_read(inode, false, &pt_extent_ent);
	if (ret)
		return ret;
	locked = true;

	pagefault_disable();
	ret = generic_file_read_iter(iocb, to);
	pagefault_enable();
	if (ret <= 0 && ret != -EFAULT)
		goto out_unlock;
	if (ret > 0)
		read += ret;

	if (should_fault_in_pages(to, iocb, &prev_count, &window_size)) {
		unlock_for_iomap_read(inode, &pt_extent_ent);
		locked = false;
		window_size -= fault_in_iov_iter_writeable(to, window_size);
		if (window_size != 0)
			goto retry;
	}

out_unlock:
	if (locked)
		unlock_for_iomap_read(inode, &pt_extent_ent);

	return read ? read : ret;
}

static ssize_t scoutfs_file_direct_read(struct kiocb *iocb, struct iov_iter *to,
					bool nowait)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_extent_ent);
	size_t prev_count = 0;
	size_t window_size = 0;
	size_t read = 0;
	bool locked = false;
	ssize_t ret;

	if (!scoutfs_should_use_dio(iocb, to)) {
		iocb->ki_flags &= ~IOCB_DIRECT;
		return scoutfs_file_buffered_read(iocb, to);
	}

retry:
	ret = lock_for_iomap_read(inode, nowait, &pt_extent_ent);
	if (ret)
		return ret;

	locked = true;

	pagefault_disable();
	to->nofault = true;
	ret = iomap_dio_rw(iocb, to, &scoutfs_iomap_ops, NULL, IOMAP_DIO_PARTIAL, 0);
	to->nofault = false;
	pagefault_enable();

	if (ret <= 0 && ret != -EFAULT)
		goto out_unlock;
	if (ret > 0)
		read = ret;

	if (should_fault_in_pages(to, iocb, &prev_count, &window_size)) {
		unlock_for_iomap_read(inode, &pt_extent_ent);
		locked = false;
		window_size -= fault_in_iov_iter_writeable(to, window_size);
		if (window_size != 0)
			goto retry;
	}

out_unlock:
	if (locked)
		unlock_for_iomap_read(inode, &pt_extent_ent);

	file_accessed(file);

	if (ret < 0)
		return ret;

	return read;
}

ssize_t scoutfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *scoutfs_inode_lock;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_data_ent);
	DECLARE_DATA_WAIT(dw);
	int lock_flags = SCOUTFS_LKF_REFRESH_INODE;
	bool is_dio = (iocb->ki_flags & IOCB_DIRECT);
	bool nowait = (iocb->ki_flags & IOCB_NOWAIT);
	ssize_t ret;

	/* IOCB_NOWAIT is only for direct I/O */
	if (!is_dio && nowait)
		return -EOPNOTSUPP;

retry:
	scoutfs_inode_lock = NULL;

	/* protect checked extents from release */
	inode_lock(inode);
	atomic_inc(&inode->i_dio_count);
	inode_unlock(inode);

	if (is_dio) {
		if (nowait) {
			if (!inode_trylock_shared(inode)) {
				ret = -EAGAIN;
				goto out;
			}
			lock_flags |= SCOUTFS_LKF_NONBLOCK;
		} else {
			inode_lock_shared(inode);
		}
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 lock_flags, inode, &scoutfs_inode_lock);
	if (ret)
		goto out;

	if (scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_data_ent,
				      scoutfs_inode_lock)) {
		ret = scoutfs_data_wait_check(inode, iocb->ki_pos, iov_iter_count(to),
					      SEF_OFFLINE, SCOUTFS_IOC_DWO_READ, &dw,
					      scoutfs_inode_lock);
		if (ret != 0)
			goto out;
	} else {
		WARN_ON_ONCE(true);
	}

	if (is_dio)
		ret = scoutfs_file_direct_read(iocb, to, nowait);
	else
		ret = scoutfs_file_buffered_read(iocb, to);

out:
	inode_dio_end(inode);

	if (scoutfs_inode_lock) {
		scoutfs_per_task_del(&si->pt_data_lock, &pt_data_ent);
		scoutfs_unlock(sb, scoutfs_inode_lock, SCOUTFS_LOCK_READ);
	}

	if (is_dio)
		inode_unlock_shared(inode);

	if (scoutfs_data_wait_found(&dw)) {
		if (!nowait) {
			ret = scoutfs_data_wait(inode, &dw);
			if (ret == 0)
				goto retry;
		} else {
			ret = -EAGAIN;
		}
	}

	return ret;
}

/*
 * We need to complete all of our locking before we get into the iomap iterator.
 * The lock hierarchy isn't well defined, and some paths reverse the ordering of
 * the inode index lock and the extent_sem because of how the get_block functions
 * are called. So we have to use trylocks and retry as needed, unless nonblocking
 * mode was requested.
 */
static int lock_for_iomap_write(struct inode *inode, struct list_head *ind_locks,
				struct scoutfs_per_task_entry *pt_inode_ent,
				struct scoutfs_per_task_entry *pt_extent_ent,
				struct scoutfs_lock *scoutfs_inode_lock,
				bool nowait)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	u64 seq;
	int ret;

	do {
		ret = scoutfs_inode_index_start(sb, &seq) ?:
		      scoutfs_inode_index_prepare(sb, ind_locks, inode, true) ?:
		      scoutfs_inode_index_try_lock_hold(sb, ind_locks, seq, true);
		if (ret < 0)
			return ret;

		/* A return value > 0 means the seq number changed */
		if (ret > 0) {
			if (nowait)
				return -EAGAIN;
			continue;
		}

		if (!down_write_trylock(&si->extent_sem)) {
			scoutfs_release_trans(sb);
			scoutfs_inode_index_unlock(sb, ind_locks);
			if (nowait)
				return -EAGAIN;
			continue;
		}

		scoutfs_per_task_add_excl(&si->pt_inode_locks, pt_inode_ent, ind_locks);

		/*
		 * We need to assign a pointer value to the per-task var. Since this
		 * one is just a marker that we hold the extent_sem, it can be anything
		 * that's non-NULL. So just use the entry itself.
		 */
		scoutfs_per_task_add_excl(&si->pt_extent_sem, pt_extent_ent,
					  pt_extent_ent);

		ret = scoutfs_dirty_inode_item(inode, scoutfs_inode_lock);

		break;
	} while (true);

	return ret;
}

static void unlock_for_iomap_write(struct inode *inode,
				   struct scoutfs_lock *scoutfs_inode_lock,
				   struct list_head *ind_locks,
				   struct scoutfs_per_task_entry *pt_inode_ent,
				   struct scoutfs_per_task_entry *pt_extent_ent,
				   size_t written)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	bool t;

	if (written > 0)
		scoutfs_do_write_end(inode, scoutfs_inode_lock, ind_locks);

	scoutfs_release_trans(sb);

	t = scoutfs_per_task_del(&si->pt_inode_locks, pt_inode_ent);
	BUG_ON(!t);

	scoutfs_inode_index_unlock(sb, ind_locks);

	t = scoutfs_per_task_del(&si->pt_extent_sem, pt_extent_ent);
	BUG_ON(!t);

	up_write(&si->extent_sem);
}

static ssize_t scoutfs_file_direct_write(struct kiocb *iocb, struct iov_iter *from,
					 struct scoutfs_lock *scoutfs_inode_lock)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	bool nowait = (iocb->ki_flags & IOCB_NOWAIT);
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_inode_ent);
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_extent_ent);
	LIST_HEAD(ind_locks);
	size_t prev_count = 0;
	size_t window_size = 0;
	size_t written = 0;
	ssize_t ret = 0;
	bool locked = false;

	if (!scoutfs_should_use_dio(iocb, from)) {
		iocb->ki_flags &= ~IOCB_DIRECT;
		goto out;
	}

retry:
	ret = lock_for_iomap_write(inode, &ind_locks, &pt_inode_ent, &pt_extent_ent,
				   scoutfs_inode_lock, nowait);
	if (ret < 0)
		goto out;

	locked = true;

	/*
	 * Due to lock ordering issues, we need to disable page faults while we're
	 * doing the iomap iterations. Pass IOMAP_DIO_PARTIAL so that the iomap
	 * code knows it's OK to return a partial result. We will try to fault in
	 * any needed pages later on.
	 */
	from->nofault = true;
	ret = iomap_dio_rw(iocb, from, &scoutfs_iomap_ops, NULL, IOMAP_DIO_PARTIAL,
			   written);
	from->nofault = false;

	if (ret <= 0) {
		if (ret == -ENOTBLK)
			ret = 0;
		if (ret != -EFAULT)
			goto out;
	}

	/* No increment (+=) because iomap returns a cumulative value. */
	if (ret > 0)
		written = ret;

	/*
	 * We might have skipped some pages that needed to be faulted in. If so, drop
	 * our locks to avoid deadlock and try to fault them in. Then we can relock
	 * and try the remaining DIO writes.
	 */
	if (should_fault_in_pages(from, iocb, &prev_count, &window_size)) {
		unlock_for_iomap_write(inode, scoutfs_inode_lock, &ind_locks,
				       &pt_inode_ent, &pt_extent_ent, written);
		locked = false;
		window_size -= fault_in_iov_iter_readable(from, window_size);
		if (window_size != 0)
			goto retry;
	}

out:
	if (locked) {
		unlock_for_iomap_write(inode, scoutfs_inode_lock, &ind_locks,
				       &pt_inode_ent, &pt_extent_ent, written);
	}

	return ret < 0 ? ret : written;
}

static ssize_t scoutfs_file_buffered_write(struct kiocb *iocb, struct iov_iter *from,
					   struct scoutfs_lock *scoutfs_inode_lock)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_inode_ent);
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_extent_ent);
	LIST_HEAD(ind_locks);
	size_t prev_count = 0;
	size_t window_size = 0;
	size_t orig_count = iov_iter_count(from);
	size_t written = 0;
	ssize_t ret;

retry:
	/*
	 * Because of lock ordering issues with the page fault code, we need to
	 * try to manually fault in any pages before acquiring locks. Then we
	 * disable page faults while doing the iomap iterations.
	 */
	if (should_fault_in_pages(from, iocb, &prev_count, &window_size)) {
		window_size -= fault_in_iov_iter_readable(from, window_size);
		if (window_size == 0) {
			ret = -EFAULT;
			goto out;
		}
		from->count = min(from->count, window_size);
	}

	ret = lock_for_iomap_write(inode, &ind_locks, &pt_inode_ent, &pt_extent_ent,
				   scoutfs_inode_lock, false);
	if (ret < 0)
		goto out;

	pagefault_disable();
	ret = iomap_file_buffered_write(iocb, from, &scoutfs_iomap_ops);
	pagefault_enable();

	/* Accumlate the count of what's been written so far */
	if (ret > 0)
		written += ret;

	if (ret <= 0 && ret != -EFAULT)
		goto out_unlock;

	from->count = orig_count - written;
	if (should_fault_in_pages(from, iocb, &prev_count, &window_size)) {
		/*
		 * There are still some pages to be faulted in. Drop our locks and
		 * try another pass.
		 */
		unlock_for_iomap_write(inode, scoutfs_inode_lock, &ind_locks,
				       &pt_inode_ent, &pt_extent_ent, written);
		goto retry;
	}

out_unlock:
	unlock_for_iomap_write(inode, scoutfs_inode_lock, &ind_locks, &pt_inode_ent,
			       &pt_extent_ent, written);

out:
	from->count = orig_count - written;

	return written ? written : ret;
}

ssize_t scoutfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *scoutfs_inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_data_ent);
	DECLARE_DATA_WAIT(dw);
	int lock_flags = SCOUTFS_LKF_REFRESH_INODE;
	bool added_pt_data;
	bool is_dio = (iocb->ki_flags & IOCB_DIRECT);
	bool nowait = (iocb->ki_flags & IOCB_NOWAIT);
	bool is_sync = (iocb->ki_flags & IOCB_DSYNC);
	ssize_t written = 0;
	ssize_t written_buffered;
	loff_t endbyte;
	loff_t pos;
	loff_t start = iocb->ki_pos;
	ssize_t ret;

	/* We don't support O_DSYNC */
        iocb->ki_flags &= ~IOCB_DSYNC;

	/* IOCB_NOWAIT is only for direct I/O */
	if (!is_dio && nowait)
		return -EOPNOTSUPP;

	if (nowait)
		lock_flags |= SCOUTFS_LKF_NONBLOCK;

retry:

	added_pt_data = false;

	if (nowait) {
		if (!inode_trylock(inode)) {
			return -EAGAIN;
		}
	} else {
		inode_lock(inode);
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE, lock_flags,
				 inode, &scoutfs_inode_lock);
	if (ret == -EAGAIN)
		goto out;
	if (ret < 0)
		goto out;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	ret = scoutfs_inode_check_retention(inode);
	if (ret < 0)
		goto out;

	ret = scoutfs_complete_truncate(inode, scoutfs_inode_lock);
	if (ret)
		goto out;

	ret = scoutfs_quota_check_data(sb, inode);
	if (ret)
		goto out;

	if (scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_data_ent,
				      scoutfs_inode_lock)) {
		/* data_version is per inode, whole file must be online */
		/* @@@ need to handle nowait here too? */
		added_pt_data = true;

		ret = scoutfs_data_wait_check(inode, 0, i_size_read(inode), SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_WRITE, &dw,
					      scoutfs_inode_lock);
		if (ret != 0)
			goto out;
	}

	/* XXX: remove SUID bit */

	if (is_dio) {
		ret = scoutfs_file_direct_write(iocb, from, scoutfs_inode_lock);
		if (ret < 0 || !iov_iter_count(from))
			goto out;

		written = ret;

		pos = iocb->ki_pos;

		written_buffered = scoutfs_file_buffered_write(iocb, from,
							       scoutfs_inode_lock);
		if (written_buffered < 0) {
			ret = written_buffered;
			goto out;
		}

		/*
		 * Ensure all data is persisted. We want the next direct IO read to be
		 * able to read what was just written.
		 */
		endbyte = pos + written_buffered - 1;
		ret = filemap_fdatawait_range(file->f_mapping, pos, endbyte);
		if (ret)
			goto out;
		written += written_buffered;
		iocb->ki_pos = pos + written_buffered;
		invalidate_mapping_pages(file->f_mapping, pos >> PAGE_SHIFT,
					 endbyte >> PAGE_SHIFT);
	} else {
		ret = scoutfs_file_buffered_write(iocb, from, scoutfs_inode_lock);
	}

out:
	if (added_pt_data) {
		scoutfs_per_task_del(&si->pt_data_lock, &pt_data_ent);
		added_pt_data = false;
	}

	if (written > 0 && ((start + written) & BACKGROUND_WRITEBACK_MASK) == 0) {
		scoutfs_writepages_sync_none(inode->i_mapping,
					     start + written - BACKGROUND_WRITEBACK_BYTES,
					     start + written - 1);
	}

	scoutfs_unlock(sb, scoutfs_inode_lock, SCOUTFS_LOCK_WRITE);

	inode_unlock(inode);

	if (scoutfs_data_wait_found(&dw)) {
		if (!nowait) {
			ret = scoutfs_data_wait(inode, &dw);
			if (ret == 0)
				goto retry;
		} else {
			ret = -EAGAIN;
		}
	}

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	if (is_sync)
		iocb->ki_flags |= IOCB_DSYNC;

	return written ? written : ret;
}

#else

ssize_t scoutfs_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *scoutfs_inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	DECLARE_DATA_WAIT(dw);
	int ret;

retry:
	/* protect checked extents from release */
	inode_lock(inode);
	atomic_inc(&inode->i_dio_count);
	inode_unlock(inode);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &scoutfs_inode_lock);
	if (ret)
		goto out;

	if (scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_ent, scoutfs_inode_lock)) {
		ret = scoutfs_data_wait_check(inode, iocb->ki_pos, iov_iter_count(to), SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_READ, &dw, scoutfs_inode_lock);
		if (ret != 0)
			goto out;
	} else {
		WARN_ON_ONCE(true);
	}

	ret = generic_file_read_iter(iocb, to);

out:
	inode_dio_end(inode);
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
	scoutfs_unlock(sb, scoutfs_inode_lock, SCOUTFS_LOCK_READ);

	if (scoutfs_data_wait_found(&dw)) {
		ret = scoutfs_data_wait(inode, &dw);
		if (ret == 0)
			goto retry;
	}
	return ret;
}

ssize_t scoutfs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *scoutfs_inode_lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	DECLARE_DATA_WAIT(dw);
	ssize_t ret;

retry:
	inode_lock(inode);
	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &scoutfs_inode_lock);
	if (ret)
		goto out;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	ret = scoutfs_inode_check_retention(inode);
	if (ret < 0)
		goto out;

	ret = scoutfs_complete_truncate(inode, scoutfs_inode_lock);
	if (ret)
		goto out;

	ret = scoutfs_quota_check_data(sb, inode);
	if (ret)
		goto out;

	if (scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_ent, scoutfs_inode_lock)) {
		/* data_version is per inode, whole file must be online */
		ret = scoutfs_data_wait_check(inode, 0, i_size_read(inode), SEF_OFFLINE,
					      SCOUTFS_IOC_DWO_WRITE, &dw, scoutfs_inode_lock);
		if (ret != 0)
			goto out;
	}

	/* XXX: remove SUID bit */

	ret = __generic_file_write_iter(iocb, from);

out:
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
	scoutfs_unlock(sb, scoutfs_inode_lock, SCOUTFS_LOCK_WRITE);
	inode_unlock(inode);

	if (scoutfs_data_wait_found(&dw)) {
		ret = scoutfs_data_wait(inode, &dw);
		if (ret == 0)
			goto retry;
	}

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;
}

#endif

loff_t scoutfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	bool ilocked = false;
	int ret = 0;

	switch (whence) {
	case SEEK_END:
	case SEEK_DATA:
	case SEEK_HOLE:
		/*
		 * These require a lock and inode refresh as they reference i_size.
		 */
		inode_lock(inode);
		ilocked = true;

		ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
					 SCOUTFS_LKF_REFRESH_INODE, inode,
					 &lock);
		if (ret == 0) {
			if (!scoutfs_per_task_add_excl(&si->pt_data_lock, &pt_ent, lock))
				WARN_ON_ONCE(true);
		}
	case SEEK_SET:
	case SEEK_CUR:
		/* No lock required */
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret == 0) {
		if (whence == SEEK_DATA) {
			offset = iomap_seek_data(inode, offset,
						 &scoutfs_iomap_report_ops);
		} else if (whence == SEEK_HOLE) {
			offset = iomap_seek_hole(inode, offset,
						 &scoutfs_iomap_report_ops);
		} else {
			offset = generic_file_llseek(file, offset, whence);
		}
	}

	if (ilocked)
		inode_unlock(inode);

	if (lock) {
		scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
		scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	}

	/* The iomap functions don't update the file pointer */
	if (ret == 0 && offset >= 0)
		offset = vfs_setpos(file, offset, sb->s_maxbytes);

	return ret ? ret : offset;
}

int scoutfs_permission(KC_VFS_NS_DEF
		       struct inode *inode, int mask)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	int ret;

	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &inode_lock);
	if (ret)
		return ret;

	ret = generic_permission(KC_VFS_INIT_NS
				 inode, mask);

	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);

	return ret;
}
