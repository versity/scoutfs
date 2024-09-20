/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
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
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/compiler.h>
#include <linux/uio.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/aio.h>
#include <linux/list_sort.h>
#include <linux/backing-dev.h>

#include "format.h"
#include "key.h"
#include "dir.h"
#include "ioctl.h"
#include "super.h"
#include "inode.h"
#include "item.h"
#include "forest.h"
#include "data.h"
#include "client.h"
#include "lock.h"
#include "trans.h"
#include "xattr.h"
#include "hash.h"
#include "srch.h"
#include "alloc.h"
#include "server.h"
#include "counters.h"
#include "attr_x.h"
#include "totl.h"
#include "wkic.h"
#include "quota.h"
#include "scoutfs_trace.h"
#include "util.h"

/*
 * We make inode index items coherent by locking fixed size regions of
 * the key space.  But the inode index item key space is vast and can
 * have huge sparse regions.  To avoid trying every possible lock in the
 * sparse regions we use the manifest to find the next stable key in the
 * key space after we find no items in a given lock region.  This is
 * relatively cheap because reading is going to check the segments
 * anyway.
 */
static long scoutfs_ioc_walk_inodes(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_walk_inodes __user *uwalk = (void __user *)arg;
	struct scoutfs_ioctl_walk_inodes walk;
	struct scoutfs_ioctl_walk_inodes_entry *ent = NULL;
	struct scoutfs_ioctl_walk_inodes_entry *end;
	struct scoutfs_key next_key;
	struct scoutfs_key last_key;
	struct scoutfs_key key;
	struct scoutfs_lock *lock;
	struct page *page = NULL;
	u64 last_seq;
	u64 entries = 0;
	int ret = 0;
	int complete = 0;
	u32 nr = 0;
	u8 type;

	if (copy_from_user(&walk, uwalk, sizeof(walk)))
		return -EFAULT;

	trace_scoutfs_ioc_walk_inodes(sb, &walk);

	if (walk.index == SCOUTFS_IOC_WALK_INODES_META_SEQ)
		type = SCOUTFS_INODE_INDEX_META_SEQ_TYPE;
	else if (walk.index == SCOUTFS_IOC_WALK_INODES_DATA_SEQ)
		type = SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE;
	else
		return -EINVAL;

	/* clamp results to the inodes in the farthest stable seq */
	if (type == SCOUTFS_INODE_INDEX_META_SEQ_TYPE ||
	    type == SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE) {

		ret = scoutfs_client_get_last_seq(sb, &last_seq);
		if (ret)
			return ret;

		if (last_seq < walk.last.major) {
			walk.last.major = last_seq;
			walk.last.minor = ~0;
			walk.last.ino = ~0ULL;
		}
	}

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	scoutfs_inode_init_index_key(&key, type, walk.first.major,
				     walk.first.minor, walk.first.ino);
	scoutfs_inode_init_index_key(&last_key, type, walk.last.major,
				     walk.last.minor, walk.last.ino);

	/* cap nr to the max the ioctl can return to a compat task */
	walk.nr_entries = min_t(u64, walk.nr_entries, INT_MAX);

	end = page_address(page) + PAGE_SIZE;

	/* outer loop */
	for (nr = 0;;) {
		ent = page_address(page);
		/* make sure _pad and minor are zeroed */
		memset(ent, 0, PAGE_SIZE);

		ret = scoutfs_lock_inode_index(sb, SCOUTFS_LOCK_READ, type,
					       le64_to_cpu(key.skii_major),
					       le64_to_cpu(key.skii_ino),
					       &lock);
		if (ret)
			break;

		/* inner loop 1 */
		while (ent + 1 < end) {
			ret = scoutfs_item_next(sb, &key, &last_key, NULL, 0, lock);
			if (ret < 0 && ret != -ENOENT)
				break;

			if (ret == -ENOENT) {
				/* done if lock covers last iteration key */
				if (scoutfs_key_compare(&last_key, &lock->end) <= 0) {
					ret = 0;
					complete = 1;
					break;
				}

				/* continue iterating after locked empty region */
				key = lock->end;
				scoutfs_key_inc(&key);

				scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
				/* avoid double-unlocking here after break */
				lock = NULL;

				ret = scoutfs_forest_next_hint(sb, &key, &next_key);
				if (ret < 0 && ret != -ENOENT)
					break;

				if (ret == -ENOENT ||
				    scoutfs_key_compare(&next_key, &last_key) > 0) {
					ret = 0;
					complete = 1;
					break;
				}

				key = next_key;

				ret = scoutfs_lock_inode_index(sb, SCOUTFS_LOCK_READ,
							type,
							le64_to_cpu(key.skii_major),
							le64_to_cpu(key.skii_ino),
							&lock);
				if (ret)
					break;

				continue;
			}

			ent->major = le64_to_cpu(key.skii_major);
			ent->ino = le64_to_cpu(key.skii_ino);

			scoutfs_key_inc(&key);

			ent++;
			entries++;

			if (nr + entries >= walk.nr_entries) {
				complete = 1;
				break;
			}
		}

		scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
		if (ret < 0)
			break;

		/* inner loop 2 */
		ent = page_address(page);
		for (; entries > 0; entries--) {
			if (copy_to_user((void __user *)walk.entries_ptr, ent,
					 sizeof(struct scoutfs_ioctl_walk_inodes_entry))) {
				ret = -EFAULT;
				goto out;
			}
			walk.entries_ptr += sizeof(struct scoutfs_ioctl_walk_inodes_entry);
			ent++;
			nr++;
		}

		if (complete)
			break;
	}

out:
	if (page)
		__free_page(page);
	if (nr > 0)
		ret = nr;
	return ret;
}

/*
 * See the comment above the definition of struct scoutfs_ioctl_ino_path
 * for ioctl semantics.
 */
static long scoutfs_ioc_ino_path(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_ino_path_result __user *ures;
	struct scoutfs_link_backref_entry *last_ent;
	struct scoutfs_link_backref_entry *ent;
	struct scoutfs_ioctl_ino_path args;
	LIST_HEAD(list);
	u16 copied;
	char term;
	int ret;

	if (!capable(CAP_DAC_READ_SEARCH))
		return -EPERM;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	ures = (void __user *)(unsigned long)args.result_ptr;

	ret = scoutfs_dir_get_backref_path(sb, args.ino, args.dir_ino,
					   args.dir_pos, &list);
	if (ret < 0)
		goto out;

	last_ent = list_last_entry(&list, struct scoutfs_link_backref_entry,
				   head);
	copied = 0;
	list_for_each_entry(ent, &list, head) {

		if (offsetof(struct scoutfs_ioctl_ino_path_result,
			     path[copied + ent->name_len + 1])
				> args.result_bytes) {
			ret = -ENAMETOOLONG;
			goto out;
		}

		if (copy_to_user(&ures->path[copied],
				 ent->dent.name, ent->name_len)) {
			ret = -EFAULT;
			goto out;
		}

		copied += ent->name_len;

		if (ent == last_ent)
			term = '\0';
		else
			term = '/';

		if (put_user(term, &ures->path[copied])) {
			ret = -EFAULT;
			break;
		}

		copied++;
	}

	/* fill the result header now that we know the copied path length */
	if (put_user(last_ent->dir_ino, &ures->dir_ino) ||
	    put_user(last_ent->dir_pos, &ures->dir_pos) ||
	    put_user(copied, &ures->path_bytes)) {
		ret = -EFAULT;
	} else {
		ret = 0;
	}

out:
	scoutfs_dir_free_backref_path(sb, &list);
	return ret;
}

/*
 * The caller has a version of the data available in the given byte
 * range in an external archive.  As long as the data version still
 * matches we free the blocks fully contained in the range and mark them
 * offline.  Attempts to use the blocks in the future will trigger
 * recall from the archive.
 *
 * If the file's online blocks drop to 0 then we also truncate any
 * blocks beyond i_size.  This honors the intent of fully releasing a file
 * without the user needing to know to release past i_size or truncate.
 *
 * XXX permissions?
 * XXX a lot of this could be generic file write prep
 */
static long scoutfs_ioc_release(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_ioctl_release args;
	struct scoutfs_lock *lock = NULL;
	u64 sblock;
	u64 eblock;
	u64 online;
	u64 offline;
	u64 isize;
	int ret;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	trace_scoutfs_ioc_release(sb, scoutfs_ino(inode), &args);

	if (args.length == 0)
		return 0;
	if ((u64_region_wraps(args.offset, args.length)) ||
	    (args.offset & SCOUTFS_BLOCK_SM_MASK) ||
	    (args.length & SCOUTFS_BLOCK_SM_MASK))
		return -EINVAL;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	inode_lock(inode);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto out;

	if (!S_ISREG(inode->i_mode)) {
		ret = -EINVAL;
		goto out;
	}

	if (!(file->f_mode & FMODE_WRITE)) {
		ret = -EINVAL;
		goto out;
	}

	if (scoutfs_inode_data_version(inode) != args.data_version) {
		ret = -ESTALE;
		goto out;
	}

	inode_dio_wait(inode);

	/* drop all clean and dirty cached blocks in the range */
	truncate_inode_pages_range(&inode->i_data, args.offset,
				   args.offset + args.length - 1);

	sblock = args.offset >> SCOUTFS_BLOCK_SM_SHIFT;
	eblock = (args.offset + args.length - 1) >> SCOUTFS_BLOCK_SM_SHIFT;
	ret = scoutfs_data_truncate_items(sb, inode, scoutfs_ino(inode),
					  sblock,
					  eblock, true,
					  lock);
	if (ret == 0) {
		scoutfs_inode_get_onoff(inode, &online, &offline);
		isize = i_size_read(inode);
		if (online == 0 && isize) {
			sblock = (isize + SCOUTFS_BLOCK_SM_SIZE - 1)
					>> SCOUTFS_BLOCK_SM_SHIFT;
			ret = scoutfs_data_truncate_items(sb, inode,
							  scoutfs_ino(inode),
							  sblock, U64_MAX,
							  false, lock);
		}
	}

out:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	inode_unlock(inode);
	mnt_drop_write_file(file);

	trace_scoutfs_ioc_release_ret(sb, scoutfs_ino(inode), ret);
	return ret;
}

static long scoutfs_ioc_data_wait_err(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_data_wait_err args;
	struct scoutfs_lock *lock = NULL;
	struct inode *inode = NULL;
	u64 sblock;
	u64 eblock;
	long ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;
	if (args.count == 0)
		return 0;
	if ((args.op & SCOUTFS_IOC_DWO_UNKNOWN) || !IS_ERR_VALUE(args.err))
		return -EINVAL;
	if ((args.op & SCOUTFS_IOC_DWO_UNKNOWN) || !IS_ERR_VALUE(args.err))
		return -EINVAL;

	trace_scoutfs_ioc_data_wait_err(sb, &args);

	sblock = args.offset >> SCOUTFS_BLOCK_SM_SHIFT;
	eblock = (args.offset + args.count - 1) >> SCOUTFS_BLOCK_SM_SHIFT;

	if (sblock > eblock)
		return -EINVAL;

	inode = scoutfs_ilookup_nowait_nonewfree(sb, args.ino);
	if (!inode) {
		ret = -ESTALE;
		goto out;
	}

	inode_lock(inode);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto unlock;

	if (!S_ISREG(inode->i_mode)) {
		ret = -EINVAL;
	} else if (scoutfs_inode_data_version(inode) != args.data_version) {
		ret = -ESTALE;
	} else {
		ret = scoutfs_data_wait_err(inode, sblock, eblock, args.op,
					    args.err);
	}

	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
unlock:
	inode_unlock(inode);
	iput(inode);
out:
	return ret;
}

/*
 * Write the archived contents of the file back if the data_version
 * still matches.
 *
 * This is a data plane operation only.  We don't want the write to
 * change any fields in the inode.  It only changes the file contents.
 *
 * Keep in mind that the staging writes can easily span transactions and
 * can crash partway through.  If we called the normal write path and
 * restored the inode afterwards the modified inode could be commited
 * partway through by a transaction and then left that way by a crash
 * before the write finishes and we restore the fields.  It also
 * wouldn't be great if the temporarily updated inode was visible to
 * paths that don't serialize with write.
 *
 * We're implementing the buffered write path down to the start of
 * generic_file_buffered_writes() without all the stuff that would
 * change the inode: file_remove_suid(), file_update_time().  The
 * easiest way to do that is to call generic_file_buffered_write().
 * We're careful to only allow staging writes inside i_size.
 *
 * We set a  bool on the inode which tells our code to update the
 * offline extents and to not update the data_version counter.
 *
 * This doesn't support any fancy write modes or side-effects: aio,
 * direct, append, sync, breaking suid, sending rlimit signals.
 */
static long scoutfs_ioc_stage(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	struct scoutfs_ioctl_stage args;
	struct scoutfs_lock *lock = NULL;
	struct kiocb kiocb;
	struct iovec iov;
	size_t written;
	loff_t end_size;
	loff_t isize;
	loff_t pos;
	int ret;

	if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
		return -EFAULT;

	trace_scoutfs_ioc_stage(sb, scoutfs_ino(inode), &args);

	end_size = args.offset + args.length;

	/* verify arg constraints that aren't dependent on file */
	if (args.length < 0 || (end_size < args.offset) ||
	    args.offset & SCOUTFS_BLOCK_SM_MASK) {
		return -EINVAL;
	}

	if (args.length == 0)
		return 0;

	/* the iocb is really only used for the file pointer :P */
	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = args.offset;
#ifdef KC_LINUX_AIO_KI_LEFT
	kiocb.ki_left = args.length;
	kiocb.ki_nbytes = args.length;
#endif
	iov.iov_base = (void __user *)(unsigned long)args.buf_ptr;
	iov.iov_len = args.length;

	ret = mnt_want_write_file(file);
	if (ret)
		return ret;

	inode_lock(inode);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto out;

	scoutfs_per_task_add(&si->pt_data_lock, &pt_ent, lock);

	isize = i_size_read(inode);

	if (!S_ISREG(inode->i_mode) ||
	    !(file->f_mode & FMODE_WRITE) ||
	    (file->f_flags & (O_APPEND | O_DIRECT | O_DSYNC)) ||
	    IS_SYNC(file->f_mapping->host) ||
	    (end_size > isize) ||
	    ((end_size & SCOUTFS_BLOCK_SM_MASK) && (end_size != isize))) {
		ret = -EINVAL;
		goto out;
	}

	if (scoutfs_inode_data_version(inode) != args.data_version) {
		ret = -ESTALE;
		goto out;
	}

	si->staging = true;
	current->backing_dev_info = inode_to_bdi(inode);

	pos = args.offset;
	written = 0;
	do {
		ret = generic_file_buffered_write(&kiocb, &iov, 1, pos, &pos,
						  args.length, written);
		BUG_ON(ret == -EIOCBQUEUED);
		if (ret > 0)
			written += ret;
	} while (ret > 0 && written < args.length);

	si->staging = false;
	current->backing_dev_info = NULL;
out:
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	inode_unlock(inode);
	mnt_drop_write_file(file);

	trace_scoutfs_ioc_stage_ret(sb, scoutfs_ino(inode), ret);
	return ret;
}

static long scoutfs_ioc_stat_more(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct scoutfs_ioctl_inode_attr_x *iax = NULL;
	struct scoutfs_ioctl_stat_more *stm = NULL;
	int ret;

	iax = kmalloc(sizeof(struct scoutfs_ioctl_inode_attr_x), GFP_KERNEL);
	stm = kmalloc(sizeof(struct scoutfs_ioctl_stat_more), GFP_KERNEL);
	if (!iax || !stm) {
		ret = -ENOMEM;
		goto out;
	}

	iax->x_mask = SCOUTFS_IOC_IAX_META_SEQ | SCOUTFS_IOC_IAX_DATA_SEQ |
		      SCOUTFS_IOC_IAX_DATA_VERSION | SCOUTFS_IOC_IAX_ONLINE_BLOCKS |
		      SCOUTFS_IOC_IAX_OFFLINE_BLOCKS | SCOUTFS_IOC_IAX_CRTIME;
	iax->x_flags = 0;
	ret = scoutfs_get_attr_x(inode, iax);
	if (ret < 0)
		goto out;

	stm->meta_seq = iax->meta_seq;
	stm->data_seq = iax->data_seq;
	stm->data_version = iax->data_version;
	stm->online_blocks = iax->online_blocks;
	stm->offline_blocks = iax->offline_blocks;
	stm->crtime_sec = iax->crtime_sec;
	stm->crtime_nsec = iax->crtime_nsec;

	if (copy_to_user((void __user *)arg, stm, sizeof(struct scoutfs_ioctl_stat_more)))
		ret = -EFAULT;
	else
		ret = 0;
out:
	kfree(iax);
	kfree(stm);
	return ret;
}

static bool inc_wrapped(u64 *ino, u64 *iblock)
{
	return (++(*iblock) == 0) && (++(*ino) == 0);
}

static long scoutfs_ioc_data_waiting(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_data_waiting idw;
	struct scoutfs_ioctl_data_waiting_entry __user *udwe;
	struct scoutfs_ioctl_data_waiting_entry dwe[16];
	unsigned int nr;
	int total;
	int ret;

	if (copy_from_user(&idw, (void __user *)arg, sizeof(idw)))
		return -EFAULT;

	if (idw.flags & SCOUTFS_IOC_DATA_WAITING_FLAGS_UNKNOWN)
		return -EINVAL;

	udwe = (void __user *)(long)idw.ents_ptr;
	total = 0;
	ret = 0;
	while (idw.ents_nr && !inc_wrapped(&idw.after_ino, &idw.after_iblock)) {
		nr = min_t(size_t, idw.ents_nr, ARRAY_SIZE(dwe));

		ret = scoutfs_data_waiting(sb, idw.after_ino, idw.after_iblock,
					   dwe, nr);
		BUG_ON(ret > nr); /* stack overflow \o/ */
		if (ret <= 0)
			break;

		if (copy_to_user(udwe, dwe, ret * sizeof(dwe[0]))) {
			ret = -EFAULT;
			break;
		}

		idw.after_ino = dwe[ret - 1].ino;
		idw.after_iblock = dwe[ret - 1].iblock;

		udwe += ret;
		idw.ents_nr -= ret;
		total += ret;
		ret = 0;
	}

	return ret ?: total;
}

/*
 * This is used when restoring files, it lets the caller set all the
 * inode attributes which are otherwise unreachable.  Changing the file
 * size can only be done for regular files with a data_version of 0.
 *
 * We unconditionally fill the iax attributes from the sm set and let
 * set_attr_x check them.
 */
static long scoutfs_ioc_setattr_more(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct scoutfs_ioctl_setattr_more __user *usm = (void __user *)arg;
	struct scoutfs_ioctl_inode_attr_x *iax = NULL;
	struct scoutfs_ioctl_setattr_more sm;
	LIST_HEAD(ind_locks);
	int ret;

	if (!(file->f_mode & FMODE_WRITE)) {
		ret = -EBADF;
		goto out;
	}

	if (copy_from_user(&sm, usm, sizeof(sm))) {
		ret = -EFAULT;
		goto out;
	}

	if (sm.flags & SCOUTFS_IOC_SETATTR_MORE_UNKNOWN) {
		ret = -EINVAL;
		goto out;
	}

	iax = kzalloc(sizeof(struct scoutfs_ioctl_inode_attr_x), GFP_KERNEL);
	if (!iax) {
		ret = -ENOMEM;
		goto out;
	}

	iax->x_mask = SCOUTFS_IOC_IAX_DATA_VERSION | SCOUTFS_IOC_IAX_CTIME |
		      SCOUTFS_IOC_IAX_CRTIME | SCOUTFS_IOC_IAX_SIZE;
	iax->data_version = sm.data_version;
	iax->ctime_sec = sm.ctime_sec;
	iax->ctime_nsec = sm.ctime_nsec;
	iax->crtime_sec = sm.crtime_sec;
	iax->crtime_nsec = sm.crtime_nsec;
	iax->size = sm.i_size;

	if (sm.flags & SCOUTFS_IOC_SETATTR_MORE_OFFLINE)
		iax->x_flags |= SCOUTFS_IOC_IAX_F_SIZE_OFFLINE;

	ret = mnt_want_write_file(file);
	if (ret < 0)
		goto out;

	ret = scoutfs_set_attr_x(inode, iax);

	mnt_drop_write_file(file);
out:
	kfree(iax);
	return ret;
}

/*
 * This lists .hide. attributes on the inode.  It doesn't include normal
 * xattrs that are visible to listxattr because we don't perform as
 * rigorous security access checks as normal vfs listxattr does.
 */
static long scoutfs_ioc_listxattr_hidden(struct file *file, unsigned long arg)
{
	struct inode *inode = file->f_inode;
	struct scoutfs_ioctl_listxattr_hidden __user *ulxr = (void __user *)arg;
	struct scoutfs_ioctl_listxattr_hidden lxh;
	struct page *page = NULL;
	unsigned int bytes;
	int total = 0;
	int ret;

	ret = inode_permission(KC_VFS_INIT_NS
			       inode, MAY_READ);
	if (ret < 0)
		goto out;

	if (copy_from_user(&lxh, ulxr, sizeof(lxh))) {
		ret = -EFAULT;
		goto out;
	}

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	while (lxh.buf_bytes) {
		bytes = min_t(int, lxh.buf_bytes, PAGE_SIZE);
		ret = scoutfs_list_xattrs(inode, page_address(page), bytes,
					  &lxh.hash_pos, &lxh.id_pos,
					  false, true);
		if (ret <= 0)
			break;

		if (copy_to_user((void __user *)lxh.buf_ptr,
				 page_address(page), ret)) {
			ret = -EFAULT;
			break;
		}

		lxh.buf_ptr += ret;
		lxh.buf_bytes -= ret;
		total += ret;
		ret = 0;
	}

out:
	if (page)
		__free_page(page);

	if (ret == 0 && (__put_user(lxh.hash_pos, &ulxr->hash_pos) ||
			 __put_user(lxh.id_pos, &ulxr->id_pos)))
		ret = -EFAULT;

	return ret ?: total;
}

/*
 * Return the inode numbers of inodes which might contain the given
 * named xattr.  This will only find scoutfs xattrs with the index tag
 * but we don't check that the callers xattr name contains the tag and
 * search for it regardless.
 */
static long scoutfs_ioc_search_xattrs(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_search_xattrs __user *usx = (void __user *)arg;
	struct scoutfs_ioctl_search_xattrs sx;
	struct scoutfs_xattr_prefix_tags tgs;
	struct scoutfs_srch_rb_root sroot;
	struct scoutfs_srch_rb_node *snode;
	u64 __user *uinos;
	struct rb_node *node;
	char *name = NULL;
	bool done = false;
	u64 prev_ino = 0;
	u64 total = 0;
	int ret;

	if (!(file->f_mode & FMODE_READ)) {
		ret = -EBADF;
		goto out;
	}

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	if (copy_from_user(&sx, usx, sizeof(sx))) {
		ret = -EFAULT;
		goto out;
	}
	uinos = (u64 __user *)sx.inodes_ptr;

	if (sx.name_bytes > SCOUTFS_XATTR_MAX_NAME_LEN) {
		ret = -EINVAL;
		goto out;
	}

	if (sx.nr_inodes == 0 || sx.last_ino < sx.next_ino) {
		ret = 0;
		goto out;
	}

	name = kmalloc(sx.name_bytes, GFP_KERNEL);
	if (!name) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(name, (void __user *)sx.name_ptr, sx.name_bytes)) {
		ret = -EFAULT;
		goto out;
	}

	if (scoutfs_xattr_parse_tags(name, sx.name_bytes, &tgs) < 0 ||
	    !tgs.srch) {
		ret = -EINVAL;
		goto out;
	}

	ret = scoutfs_srch_search_xattrs(sb, &sroot,
					 scoutfs_hash64(name, sx.name_bytes),
					 sx.next_ino, sx.last_ino, &done);
	if (ret < 0)
		goto out;

	prev_ino = 0;
	scoutfs_srch_foreach_rb_node(snode, node, &sroot) {
		if (prev_ino == snode->ino)
			continue;

		if (put_user(snode->ino, uinos + total)) {
			ret = -EFAULT;
			break;
		}
		prev_ino = snode->ino;

		if (++total == sx.nr_inodes)
			break;
	}

	sx.output_flags = 0;
	if (done && total == sroot.nr)
		sx.output_flags |= SCOUTFS_SEARCH_XATTRS_OFLAG_END;

	if (put_user(sx.output_flags, &usx->output_flags))
		ret = -EFAULT;
	else
		ret = 0;

	scoutfs_srch_destroy_rb_root(&sroot);

out:
	kfree(name);
	return ret ?: total;
}

static long scoutfs_ioc_statfs_more(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super;
	struct scoutfs_ioctl_statfs_more sfm;
	int ret;

	super = kzalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	if (!super)
		return -ENOMEM;

	ret = scoutfs_read_super(sb, super);
	if (ret)
		goto out;

	sfm.fsid = le64_to_cpu(super->hdr.fsid);
	sfm.rid = sbi->rid;
	sfm.total_meta_blocks = le64_to_cpu(super->total_meta_blocks);
	sfm.total_data_blocks = le64_to_cpu(super->total_data_blocks);
	sfm.reserved_meta_blocks = scoutfs_server_reserved_meta_blocks(sb);

	ret = scoutfs_client_get_last_seq(sb, &sfm.committed_seq);
	if (ret)
		goto out;

	if (copy_to_user((void __user *)arg, &sfm, sizeof(sfm)))
		ret = -EFAULT;
	else
		ret = 0;
out:
	kfree(super);
	return ret;
}

struct copy_alloc_detail_args {
	struct scoutfs_ioctl_alloc_detail_entry __user *uade;
	u64 nr;
	u64 copied;
};

static int copy_alloc_detail_to_user(struct super_block *sb, void *arg,
				     int owner, u64 id, bool meta, bool avail,
				     u64 blocks)
{
	struct copy_alloc_detail_args *args = arg;
	struct scoutfs_ioctl_alloc_detail_entry ade;

	if (args->copied == args->nr)
		return -EOVERFLOW;

	ade.blocks = blocks;
	ade.id = id;
	ade.meta = !!meta;
	ade.avail = !!avail;

	if (copy_to_user(&args->uade[args->copied], &ade, sizeof(ade)))
		return -EFAULT;

	args->copied++;
	return 0;
}

static long scoutfs_ioc_alloc_detail(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_alloc_detail __user *uad = (void __user *)arg;
	struct scoutfs_ioctl_alloc_detail ad;
	struct copy_alloc_detail_args args;

	if (copy_from_user(&ad, uad, sizeof(ad)))
		return -EFAULT;

	args.uade = (struct scoutfs_ioctl_alloc_detail_entry __user *)
			(uintptr_t)ad.entries_ptr;
	args.nr = ad.entries_nr;
	args.copied = 0;

	return scoutfs_alloc_foreach(sb, copy_alloc_detail_to_user, &args) ?:
	       args.copied;
}

static long scoutfs_ioc_move_blocks(struct file *file, unsigned long arg)
{
	struct inode *to = file_inode(file);
	struct super_block *sb = to->i_sb;
	struct scoutfs_ioctl_move_blocks __user *umb = (void __user *)arg;
	struct scoutfs_ioctl_move_blocks mb;
	struct file *from_file;
	struct inode *from;
	int ret;

	if (copy_from_user(&mb, umb, sizeof(mb)))
		return -EFAULT;

	if (mb.len == 0)
		return 0;

	if ((u64_region_wraps(mb.from_off, mb.len)) ||
	    (u64_region_wraps(mb.to_off, mb.len)))
		return -EOVERFLOW;

	from_file = fget(mb.from_fd);
	if (!from_file)
		return -EBADF;
	from = file_inode(from_file);

	if (from == to) {
		ret = -EINVAL;
		goto out;
	}

	if (from->i_sb != sb) {
		ret = -EXDEV;
		goto out;
	}

	if (mb.flags & SCOUTFS_IOC_MB_UNKNOWN) {
		ret = -EINVAL;
		goto out;
	}

	ret = mnt_want_write_file(file);
	if (ret < 0)
		goto out;

	ret = scoutfs_data_move_blocks(from, mb.from_off, mb.len,
				       to, mb.to_off, !!(mb.flags & SCOUTFS_IOC_MB_STAGE),
				       mb.data_version);
	mnt_drop_write_file(file);
out:
	fput(from_file);

	return ret;
}

static long scoutfs_ioc_resize_devices(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_resize_devices __user *urd = (void __user *)arg;
	struct scoutfs_ioctl_resize_devices rd;
	struct scoutfs_net_resize_devices nrd;
	int ret;

	if (!(file->f_mode & FMODE_READ)) {
		ret = -EBADF;
		goto out;
	}

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	if (copy_from_user(&rd, urd, sizeof(rd))) {
		ret = -EFAULT;
		goto out;
	}

	nrd.new_total_meta_blocks = cpu_to_le64(rd.new_total_meta_blocks);
	nrd.new_total_data_blocks = cpu_to_le64(rd.new_total_data_blocks);

	ret = scoutfs_client_resize_devices(sb, &nrd);
out:
	return ret;
}

struct read_xattr_total_iter_cb_args {
	struct scoutfs_ioctl_xattr_total *xt;
	unsigned int copied;
	unsigned int total;
};

/*
 * This is called under an RCU read lock so it can't copy to userspace.
 */
static int read_xattr_total_iter_cb(struct scoutfs_key *key, void *val, unsigned int val_len,
				    void *cb_arg)
{
	struct read_xattr_total_iter_cb_args *cba = cb_arg;
	struct scoutfs_xattr_totl_val *tval = val;
	struct scoutfs_ioctl_xattr_total *xt = &cba->xt[cba->copied];

	xt->name[0] = le64_to_cpu(key->skxt_a);
	xt->name[1] = le64_to_cpu(key->skxt_b);
	xt->name[2] = le64_to_cpu(key->skxt_c);
	xt->total = le64_to_cpu(tval->total);
	xt->count = le64_to_cpu(tval->count);

	if (++cba->copied < cba->total)
		return -EAGAIN;
	else
		return 0;
}

/*
 * Starting from the caller's pos_name, copy the names, totals, and
 * counts for the .totl. tagged xattrs in the system sorted by their
 * name until the user's buffer is full.  This only sees xattrs that
 * have been committed.  It doesn't use locking to force commits and
 * block writers so it can be a little bit out of date with respect to
 * dirty xattrs in memory across the system.
 */
static long scoutfs_ioc_read_xattr_totals(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_read_xattr_totals __user *urxt = (void __user *)arg;
	struct scoutfs_ioctl_read_xattr_totals rxt;
	struct scoutfs_ioctl_xattr_total __user *uxt;
	struct read_xattr_total_iter_cb_args cba = {NULL, };
	struct scoutfs_key range_start;
	struct scoutfs_key range_end;
	struct scoutfs_key key;
	unsigned int copied = 0;
	unsigned int total;
	unsigned int ready;
	int ret;

	if (!(file->f_mode & FMODE_READ)) {
		ret = -EBADF;
		goto out;
	}

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	cba.xt = (void *)__get_free_page(GFP_KERNEL);
	if (!cba.xt) {
		ret = -ENOMEM;
		goto out;
	}
	cba.total = PAGE_SIZE / sizeof(struct scoutfs_ioctl_xattr_total);

	if (copy_from_user(&rxt, urxt, sizeof(rxt))) {
		ret = -EFAULT;
		goto out;
	}
	uxt = (void __user *)rxt.totals_ptr;

	if ((rxt.totals_ptr & (sizeof(__u64) - 1)) ||
	    (rxt.totals_bytes < sizeof(struct scoutfs_ioctl_xattr_total))) {
		ret = -EINVAL;
		goto out;
	}

	total = div_u64(min_t(u64, rxt.totals_bytes, INT_MAX),
			sizeof(struct scoutfs_ioctl_xattr_total));

	scoutfs_totl_set_range(&range_start, &range_end);
	scoutfs_xattr_init_totl_key(&key, rxt.pos_name);

	while (copied < total) {
		cba.copied = 0;
		ret = scoutfs_wkic_iterate(sb, &key, &range_end, &range_start, &range_end,
					   read_xattr_total_iter_cb, &cba);
		if (ret < 0)
			goto out;

		if (cba.copied == 0)
			break;

		ready = min(total - copied, cba.copied);

		if (copy_to_user(&uxt[copied], cba.xt, ready * sizeof(cba.xt[0]))) {
			ret = -EFAULT;
			goto out;
		}

		scoutfs_xattr_init_totl_key(&key, cba.xt[ready - 1].name);
		scoutfs_key_inc(&key);
		copied += ready;
	}

	ret = 0;
out:
	if (cba.xt)
		free_page((long)cba.xt);

	return ret ?: copied;
}

static long scoutfs_ioc_get_allocated_inos(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_get_allocated_inos __user *ugai = (void __user *)arg;
	struct scoutfs_ioctl_get_allocated_inos gai;
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_key key;
	struct scoutfs_key end;
	struct page *page = NULL;
	u64 __user *uinos;
	u64 bytes;
	u64 *ino;
	u64 *ino_end;
	int entries = 0;
	int nr;
	int ret;
	int complete = 0;

	if (!(file->f_mode & FMODE_READ)) {
		ret = -EBADF;
		goto out;
	}

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	if (copy_from_user(&gai, ugai, sizeof(gai))) {
		ret = -EFAULT;
		goto out;
	}

	if ((gai.inos_ptr & (sizeof(__u64) - 1)) || (gai.inos_bytes < sizeof(__u64))) {
		ret = -EINVAL;
		goto out;
	}

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	ino_end = page_address(page) + PAGE_SIZE;

	scoutfs_inode_init_key(&key, gai.start_ino);
	scoutfs_inode_init_key(&end, gai.start_ino | SCOUTFS_LOCK_INODE_GROUP_MASK);
	uinos = (void __user *)gai.inos_ptr;
	bytes = gai.inos_bytes;
	nr = 0;

	for (;;) {

		ret = scoutfs_lock_ino(sb, SCOUTFS_LOCK_READ, 0, gai.start_ino, &lock);
		if (ret < 0)
			goto out;

		ino = page_address(page);
		while (ino < ino_end) {

			ret = scoutfs_item_next(sb, &key, &end, NULL, 0, lock);
			if (ret < 0) {
				if (ret == -ENOENT) {
					ret = 0;
					complete = 1;
				}
				break;
			}

			if (key.sk_zone != SCOUTFS_FS_ZONE) {
				ret = 0;
				complete = 1;
				break;
			}

			/* all fs items are owned by allocated inodes, and _first is always ino */
			*ino = le64_to_cpu(key._sk_first);
			scoutfs_inode_init_key(&key, *ino + 1);

			ino++;
			entries++;
			nr++;

			bytes -= sizeof(*uinos);
			if (bytes < sizeof(*uinos)) {
				complete = 1;
				break;
			}

			if (nr == INT_MAX) {
				complete = 1;
				break;
			}
		}

		scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);

		if (ret < 0)
			break;

		ino = page_address(page);
		if (copy_to_user(uinos, ino, entries * sizeof(*uinos))) {
			ret = -EFAULT;
			goto out;
		}

		uinos += entries;
		entries = 0;

		if (complete)
			break;
	}
out:
	if (page)
		__free_page(page);
	return ret ?: nr;
}

/*
 * Copy entries that point to an inode to the user's buffer.  We copy to
 * userspace from copies of the entries that are acquired under a lock
 * so that we don't fault while holding cluster locks.  It also gives us
 * a chance to limit the amount of work under each lock hold.
 */
static long scoutfs_ioc_get_referring_entries(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_get_referring_entries gre;
	struct scoutfs_link_backref_entry *bref = NULL;
	struct scoutfs_link_backref_entry *bref_tmp;
	struct scoutfs_ioctl_dirent __user *uent;
	struct scoutfs_ioctl_dirent ent;
	LIST_HEAD(list);
	u64 copied;
	int name_len;
	int bytes;
	long nr;
	int ret;

	if (!capable(CAP_DAC_READ_SEARCH))
		return -EPERM;

	if (copy_from_user(&gre, (void __user *)arg, sizeof(gre)))
		return -EFAULT;

	uent = (void __user *)(unsigned long)gre.entries_ptr;
	copied = 0;
	nr = 0;

	/* use entry as cursor between calls */
	ent.dir_ino = gre.dir_ino;
	ent.dir_pos = gre.dir_pos;

	for (;;) {
		ret = scoutfs_dir_add_next_linkrefs(sb, gre.ino, ent.dir_ino, ent.dir_pos, 1024,
						    &list);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			goto out;
		}

		/* _add_next adds each entry to the head, _reverse for key order */
		list_for_each_entry_safe_reverse(bref, bref_tmp, &list, head) {
			list_del_init(&bref->head);

			name_len = bref->name_len;
			bytes = ALIGN(offsetof(struct scoutfs_ioctl_dirent, name[name_len + 1]),
				      16);
			if (copied + bytes > gre.entries_bytes) {
				ret = -EINVAL;
				goto out;
			}

			ent.dir_ino = bref->dir_ino;
			ent.dir_pos = bref->dir_pos;
			ent.ino = gre.ino;
			ent.entry_bytes = bytes;
			ent.flags = bref->last ? SCOUTFS_IOCTL_DIRENT_FLAG_LAST : 0;
			ent.d_type = bref->d_type;
			ent.name_len = name_len;

			if (copy_to_user(uent, &ent, sizeof(struct scoutfs_ioctl_dirent)) ||
			    copy_to_user(&uent->name[0], bref->dent.name, name_len) ||
			    put_user('\0', &uent->name[name_len])) {
				ret = -EFAULT;
				goto out;
			}

			kfree(bref);
			bref = NULL;

			uent = (void __user *)uent + bytes;
			copied += bytes;
			nr++;

			if (nr == LONG_MAX || (ent.flags & SCOUTFS_IOCTL_DIRENT_FLAG_LAST)) {
				ret = 0;
				goto out;
			}
		}

		/* advance cursor pos from last copied entry */
		if (++ent.dir_pos == 0) {
			if (++ent.dir_ino == 0) {
				ret = 0;
				goto out;
			}
		}
	}

	ret = 0;
out:
	kfree(bref);
	list_for_each_entry_safe(bref, bref_tmp, &list, head) {
		list_del_init(&bref->head);
		kfree(bref);
	}

	return nr ?: ret;
}

static long scoutfs_ioc_get_attr_x(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct scoutfs_ioctl_inode_attr_x __user *uiax = (void __user *)arg;
	struct scoutfs_ioctl_inode_attr_x *iax = NULL;
	int ret;

	iax = kmalloc(sizeof(struct scoutfs_ioctl_inode_attr_x), GFP_KERNEL);
	if (!iax) {
		ret = -ENOMEM;
		goto out;
	}

	ret = get_user(iax->x_mask, &uiax->x_mask) ?:
	      get_user(iax->x_flags, &uiax->x_flags);
	if (ret < 0)
		goto out;

	ret = scoutfs_get_attr_x(inode, iax);
	if (ret < 0)
		goto out;

	/* only copy results after dropping cluster locks (could fault) */
	if (ret > 0 && copy_to_user(uiax, iax, ret) != 0)
		ret = -EFAULT;
	else
		ret = 0;
out:
	kfree(iax);
	return ret;
}

static long scoutfs_ioc_set_attr_x(struct file *file, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct scoutfs_ioctl_inode_attr_x __user *uiax = (void __user *)arg;
	struct scoutfs_ioctl_inode_attr_x *iax = NULL;
	int ret;

	iax = kmalloc(sizeof(struct scoutfs_ioctl_inode_attr_x), GFP_KERNEL);
	if (!iax) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(iax, uiax, sizeof(struct scoutfs_ioctl_inode_attr_x))) {
		ret = -EFAULT;
		goto out;
	}

	ret = mnt_want_write_file(file);
	if (ret < 0)
		goto out;

	ret = scoutfs_set_attr_x(inode, iax);

	mnt_drop_write_file(file);
out:
	kfree(iax);
	return ret;
}

static long scoutfs_ioc_get_quota_rules(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_get_quota_rules __user *ugqr = (void __user *)arg;
	struct scoutfs_ioctl_get_quota_rules gqr;
	struct scoutfs_ioctl_quota_rule __user *uirules;
	struct scoutfs_ioctl_quota_rule *irules;
	struct page *page = NULL;
	int copied = 0;
	int nr;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&gqr, ugqr, sizeof(gqr)))
		return -EFAULT;

	if (gqr.rules_nr == 0)
		return 0;

	uirules = (void __user *)gqr.rules_ptr;
	/* limit rules copied per call */
	gqr.rules_nr = min_t(u64, gqr.rules_nr, INT_MAX);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	irules = page_address(page);

	while (copied < gqr.rules_nr) {
		nr = min_t(u64, gqr.rules_nr - copied,
				PAGE_SIZE / sizeof(struct scoutfs_ioctl_quota_rule));
		ret = scoutfs_quota_get_rules(sb, gqr.iterator, page_address(page), nr);
		if (ret <= 0)
			goto out;

		if (copy_to_user(&uirules[copied], irules, ret * sizeof(irules[0]))) {
			ret = -EFAULT;
			goto out;
		}

		copied += ret;
	}

	ret = 0;
out:
	if (page)
		__free_page(page);

	if (ret == 0 && copy_to_user(ugqr->iterator, gqr.iterator, sizeof(gqr.iterator)))
		ret = -EFAULT;

	return ret ?: copied;
}

static long scoutfs_ioc_mod_quota_rule(struct file *file, unsigned long arg, bool is_add)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_quota_rule __user *uirule = (void __user *)arg;
	struct scoutfs_ioctl_quota_rule irule;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&irule, uirule, sizeof(irule)))
		return -EFAULT;

	return scoutfs_quota_mod_rule(sb, is_add, &irule);
}

struct read_index_buf {
	int nr;
	int size;
	struct scoutfs_ioctl_xattr_index_entry ents[0];
};

#define READ_INDEX_BUF_MAX_ENTS \
	((PAGE_SIZE - sizeof(struct read_index_buf)) / \
		sizeof(struct scoutfs_ioctl_xattr_index_entry))

/*
 * This doesn't filter out duplicates, the caller filters them out to
 * catch duplicates between iteration calls.
 */
static int read_index_cb(struct scoutfs_key *key, void *val, unsigned int val_len, void *cb_arg)
{
	struct read_index_buf *rib = cb_arg;
	struct scoutfs_ioctl_xattr_index_entry *ent = &rib->ents[rib->nr];
	u64 xid;

	if (val_len != 0)
		return -EIO;

	/* discard the xid, they're not exposed to ioctl callers */
	scoutfs_xattr_get_indx_key(key, &ent->major, &ent->minor, &ent->ino, &xid);

	if (++rib->nr == rib->size)
		return rib->nr;

	return -EAGAIN;
}

static long scoutfs_ioc_read_xattr_index(struct file *file, unsigned long arg)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct scoutfs_ioctl_read_xattr_index __user *urxi = (void __user *)arg;
	struct scoutfs_ioctl_xattr_index_entry __user *uents;
	struct scoutfs_ioctl_xattr_index_entry *ent;
	struct scoutfs_ioctl_xattr_index_entry prev;
	struct scoutfs_ioctl_read_xattr_index rxi;
	struct read_index_buf *rib;
	struct page *page = NULL;
	struct scoutfs_key first;
	struct scoutfs_key last;
	struct scoutfs_key start;
	struct scoutfs_key end;
	int copied = 0;
	int ret;
	int i;

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	if (copy_from_user(&rxi, urxi, sizeof(rxi))) {
		ret = -EFAULT;
		goto out;
	}
	uents = (void __user *)rxi.entries_ptr;
	rxi.entries_nr = min_t(u64, rxi.entries_nr, INT_MAX);

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	rib = page_address(page);

	scoutfs_xattr_init_indx_key(&first, rxi.first.major, rxi.first.minor, rxi.first.ino, 0);
	scoutfs_xattr_init_indx_key(&last, rxi.last.major, rxi.last.minor, rxi.last.ino, U64_MAX);
	scoutfs_xattr_indx_get_range(&start, &end);

	if (scoutfs_key_compare(&first, &last) > 0) {
		ret = -EINVAL;
		goto out;
	}

	/* 0 ino doesn't exist, can't ever match entry to return */
	memset(&prev, 0, sizeof(prev));

	while (copied < rxi.entries_nr) {
		rib->nr = 0;
		rib->size = min_t(u64, rxi.entries_nr - copied, READ_INDEX_BUF_MAX_ENTS);
		ret = scoutfs_wkic_iterate(sb, &first, &last, &start, &end,
					   read_index_cb, rib);
		if (ret < 0)
			goto out;
		if (rib->nr == 0)
			break;

		/*
		 * Copy entries to userspace, skipping duplicate entries
		 * that can result from multiple xattrs indexing an
		 * inode at the same position and which can span
		 * multiple cache iterations.  (Comparing in order of
		 * most likely to change to fail fast.)
		 */
		for (i = 0, ent = rib->ents; i < rib->nr; i++, ent++) {
			if (ent->ino == prev.ino && ent->minor == prev.minor &&
			    ent->major == prev.major)
				continue;

			if (copy_to_user(&uents[copied], ent, sizeof(*ent))) {
				ret = -EFAULT;
				goto out;
			}

			prev = *ent;
			copied++;
		}

		scoutfs_xattr_init_indx_key(&first, prev.major, prev.minor, prev.ino, U64_MAX);
		scoutfs_key_inc(&first);
	}

	ret = copied;
out:
	if (page)
		__free_page(page);

	return ret;
}

long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SCOUTFS_IOC_WALK_INODES:
		return scoutfs_ioc_walk_inodes(file, arg);
	case SCOUTFS_IOC_INO_PATH:
		return scoutfs_ioc_ino_path(file, arg);
	case SCOUTFS_IOC_RELEASE:
		return scoutfs_ioc_release(file, arg);
	case SCOUTFS_IOC_STAGE:
		return scoutfs_ioc_stage(file, arg);
	case SCOUTFS_IOC_STAT_MORE:
		return scoutfs_ioc_stat_more(file, arg);
	case SCOUTFS_IOC_DATA_WAITING:
		return scoutfs_ioc_data_waiting(file, arg);
	case SCOUTFS_IOC_SETATTR_MORE:
		return scoutfs_ioc_setattr_more(file, arg);
	case SCOUTFS_IOC_LISTXATTR_HIDDEN:
		return scoutfs_ioc_listxattr_hidden(file, arg);
	case SCOUTFS_IOC_SEARCH_XATTRS:
		return scoutfs_ioc_search_xattrs(file, arg);
	case SCOUTFS_IOC_STATFS_MORE:
		return scoutfs_ioc_statfs_more(file, arg);
	case SCOUTFS_IOC_DATA_WAIT_ERR:
		return scoutfs_ioc_data_wait_err(file, arg);
	case SCOUTFS_IOC_ALLOC_DETAIL:
		return scoutfs_ioc_alloc_detail(file, arg);
	case SCOUTFS_IOC_MOVE_BLOCKS:
		return scoutfs_ioc_move_blocks(file, arg);
	case SCOUTFS_IOC_RESIZE_DEVICES:
		return scoutfs_ioc_resize_devices(file, arg);
	case SCOUTFS_IOC_READ_XATTR_TOTALS:
		return scoutfs_ioc_read_xattr_totals(file, arg);
	case SCOUTFS_IOC_GET_ALLOCATED_INOS:
		return scoutfs_ioc_get_allocated_inos(file, arg);
	case SCOUTFS_IOC_GET_REFERRING_ENTRIES:
		return scoutfs_ioc_get_referring_entries(file, arg);
	case SCOUTFS_IOC_GET_ATTR_X:
		return scoutfs_ioc_get_attr_x(file, arg);
	case SCOUTFS_IOC_SET_ATTR_X:
		return scoutfs_ioc_set_attr_x(file, arg);
	case SCOUTFS_IOC_GET_QUOTA_RULES:
		return scoutfs_ioc_get_quota_rules(file, arg);
	case SCOUTFS_IOC_ADD_QUOTA_RULE:
		return scoutfs_ioc_mod_quota_rule(file, arg, true);
	case SCOUTFS_IOC_DEL_QUOTA_RULE:
		return scoutfs_ioc_mod_quota_rule(file, arg, false);
	case SCOUTFS_IOC_READ_XATTR_INDEX:
		return scoutfs_ioc_read_xattr_index(file, arg);
	}

	return -ENOTTY;
}
