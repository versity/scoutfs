/*
 * Copyright (C) 2015 Versity Software, Inc.  All rights reserved.
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
#include <linux/random.h>
#include <linux/xattr.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/list_sort.h>
#include <linux/workqueue.h>
#include <linux/buffer_head.h>

#include "format.h"
#include "super.h"
#include "key.h"
#include "inode.h"
#include "dir.h"
#include "data.h"
#include "scoutfs_trace.h"
#include "xattr.h"
#include "trans.h"
#include "msg.h"
#include "item.h"
#include "client.h"
#include "cmp.h"
#include "omap.h"
#include "forest.h"
#include "btree.h"
#include "acl.h"

/*
 * XXX
 *  - worry about i_ino trunctation, not sure if we do anything
 *  - use inode item value lengths for forward/back compat
 */

/*
 * XXX before committing:
 *  - describe all this better
 *  - describe data locking size problems
 */

struct inode_allocator {
	spinlock_t lock;
	u64 ino;
	u64 nr;
};

struct inode_sb_info {
	struct super_block *sb;
	bool stopped;

	spinlock_t writeback_lock;
	struct list_head writeback_list;
	struct inode_allocator dir_ino_alloc;
	struct inode_allocator ino_alloc;

	struct delayed_work orphan_scan_dwork;

	struct workqueue_struct *iput_workq;
	struct work_struct iput_work;
	spinlock_t iput_lock;
	struct list_head iput_list;
};

#define DECLARE_INODE_SB_INFO(sb, name) \
	struct inode_sb_info *name = SCOUTFS_SB(sb)->inode_sb_info

static struct kmem_cache *scoutfs_inode_cachep;

/*
 * This is called once before all the allocations and frees of a inode
 * object within a slab.  It's for inode fields that don't need to be
 * initialized for a given instance of an inode.
 */
static void scoutfs_inode_ctor(void *obj)
{
	struct scoutfs_inode_info *si = obj;

	init_rwsem(&si->extent_sem);
	mutex_init(&si->item_mutex);
	seqlock_init(&si->seqlock);
	si->staging = false;
	scoutfs_per_task_init(&si->pt_data_lock);
	atomic64_set(&si->data_waitq.changed, 0);
	init_waitqueue_head(&si->data_waitq.waitq);
	init_rwsem(&si->xattr_rwsem);
	INIT_LIST_HEAD(&si->writeback_entry);
	scoutfs_lock_init_coverage(&si->ino_lock_cov);
	INIT_LIST_HEAD(&si->iput_head);
	si->iput_count = 0;
	si->iput_flags = 0;

	inode_init_once(&si->inode);
}

struct inode *scoutfs_alloc_inode(struct super_block *sb)
{
	struct scoutfs_inode_info *si;

	si = kmem_cache_alloc(scoutfs_inode_cachep, GFP_NOFS);
	if (!si)
		return NULL;

	return &si->inode;
}

static void scoutfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	trace_scoutfs_i_callback(inode);
	kmem_cache_free(scoutfs_inode_cachep, SCOUTFS_I(inode));
}

void scoutfs_destroy_inode(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	DECLARE_INODE_SB_INFO(inode->i_sb, inf);

	spin_lock(&inf->writeback_lock);
	if (!list_empty(&si->writeback_entry))
		list_del_init(&si->writeback_entry);
	spin_unlock(&inf->writeback_lock);

	scoutfs_lock_del_coverage(inode->i_sb, &si->ino_lock_cov);

	call_rcu(&inode->i_rcu, scoutfs_i_callback);
}

static const struct inode_operations scoutfs_file_iops = {
	.getattr	= scoutfs_getattr,
	.setattr	= scoutfs_setattr,
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
#endif
	.listxattr	= scoutfs_listxattr,
	.get_acl	= scoutfs_get_acl,
	.fiemap		= scoutfs_data_fiemap,
};

static const struct inode_operations scoutfs_special_iops = {
	.getattr	= scoutfs_getattr,
	.setattr	= scoutfs_setattr,
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
#endif
	.listxattr	= scoutfs_listxattr,
	.get_acl	= scoutfs_get_acl,
};

/*
 * Called once new inode allocation or inode reading has initialized
 * enough of the inode for us to set the ops based on the mode.
 */
static void set_inode_ops(struct inode *inode)
{
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_mapping->a_ops = &scoutfs_file_aops;
		inode->i_op = &scoutfs_file_iops;
		inode->i_fop = &scoutfs_file_fops;
		break;
	case S_IFDIR:
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
		inode->i_op = &scoutfs_dir_iops.ops;
		inode->i_flags |= S_IOPS_WRAPPER;
#else
		inode->i_op = &scoutfs_dir_iops;
#endif
		inode->i_fop = &scoutfs_dir_fops;
		break;
	case S_IFLNK:
		inode->i_op = &scoutfs_symlink_iops;
		break;
	default:
		inode->i_op = &scoutfs_special_iops;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;
	}

	/* ephemeral data items avoid kmap for pointers to page contents */
	mapping_set_gfp_mask(inode->i_mapping, GFP_USER);
}

static unsigned int item_index_arr_ind(u8 type)
{
	switch (type) {
		case SCOUTFS_INODE_INDEX_META_SEQ_TYPE: return 0; break;
		case SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE: return 1; break;
		/* should never get here, we control callers, not untrusted data */
		default: BUG(); break;
	}
}

static void set_item_major(struct scoutfs_inode_info *si, u8 type, __le64 maj)
{
	unsigned int ind = item_index_arr_ind(type);

	si->item_majors[ind] = le64_to_cpu(maj);
}

static u64 get_item_major(struct scoutfs_inode_info *si, u8 type)
{
	unsigned int ind = item_index_arr_ind(type);

	return si->item_majors[ind];
}

static u64 get_item_minor(struct scoutfs_inode_info *si, u8 type)
{
	unsigned int ind = item_index_arr_ind(type);

	return si->item_minors[ind];
}

/*
 * The caller has ensured that the fields in the incoming scoutfs inode
 * reflect both the inode item and the inode index items.  This happens
 * when reading, refreshing, or updating the inodes.  We set the inode
 * info fields to match so that next time we try to update the inode we
 * can tell which fields have changed.
 */
static void set_item_info(struct scoutfs_inode_info *si,
			  struct scoutfs_inode *sinode)
{
	BUG_ON(!mutex_is_locked(&si->item_mutex));

	memset(si->item_majors, 0, sizeof(si->item_majors));
	memset(si->item_minors, 0, sizeof(si->item_minors));

	si->have_item = true;
	set_item_major(si, SCOUTFS_INODE_INDEX_META_SEQ_TYPE, sinode->meta_seq);
	set_item_major(si, SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE, sinode->data_seq);
}

static void load_inode(struct inode *inode, struct scoutfs_inode *cinode, int inode_bytes)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	i_size_write(inode, le64_to_cpu(cinode->size));
	inode_set_iversion_queried(inode, le64_to_cpu(cinode->version));
	set_nlink(inode, le32_to_cpu(cinode->nlink));
	i_uid_write(inode, le32_to_cpu(cinode->uid));
	i_gid_write(inode, le32_to_cpu(cinode->gid));
	inode->i_mode = le32_to_cpu(cinode->mode);
	inode->i_rdev = le32_to_cpu(cinode->rdev);
	inode->i_atime.tv_sec = le64_to_cpu(cinode->atime.sec);
	inode->i_atime.tv_nsec = le32_to_cpu(cinode->atime.nsec);
	inode->i_mtime.tv_sec = le64_to_cpu(cinode->mtime.sec);
	inode->i_mtime.tv_nsec = le32_to_cpu(cinode->mtime.nsec);
	inode->i_ctime.tv_sec = le64_to_cpu(cinode->ctime.sec);
	inode->i_ctime.tv_nsec = le32_to_cpu(cinode->ctime.nsec);

	si->meta_seq = le64_to_cpu(cinode->meta_seq);
	si->data_seq = le64_to_cpu(cinode->data_seq);
	si->data_version = le64_to_cpu(cinode->data_version);
	si->online_blocks = le64_to_cpu(cinode->online_blocks);
	si->offline_blocks = le64_to_cpu(cinode->offline_blocks);
	si->next_readdir_pos = le64_to_cpu(cinode->next_readdir_pos);
	si->next_xattr_id = le64_to_cpu(cinode->next_xattr_id);
	si->flags = le32_to_cpu(cinode->flags);
	si->crtime.tv_sec = le64_to_cpu(cinode->crtime.sec);
	si->crtime.tv_nsec = le32_to_cpu(cinode->crtime.nsec);
	si->proj = le64_to_cpu(cinode->proj);

	/*
	 * i_blocks is initialized from online and offline and is then
	 * maintained as blocks come and go.
	 */
	inode->i_blocks = (si->online_blocks + si->offline_blocks)
				<< SCOUTFS_BLOCK_SM_SECTOR_SHIFT;

	set_item_info(si, cinode);
}

void scoutfs_inode_init_key(struct scoutfs_key *key, u64 ino)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.ski_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_INODE_TYPE,
	};
}

/*
 * Read an inode item into the caller's buffer and return the size that
 * we read.   Returns errors if the inode size is unsupported or doesn't
 * make sense for the format version.
 */
static int lookup_inode_item(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_inode *sinode, struct scoutfs_lock *lock)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret;

	ret = scoutfs_item_lookup_smaller_zero(sb, key, sinode, sizeof(struct scoutfs_inode), lock);
	if (ret >= 0 && !scoutfs_inode_valid_vers_bytes(sbi->fmt_vers, ret))
		return -EIO;

	return ret;
}

/*
 * Refresh the vfs inode fields if the lock indicates that the current
 * contents could be stale.
 *
 * This can be racing with many lock holders of an inode.  A bunch of
 * readers can be checking to refresh while one of them is refreshing.
 *
 * The vfs inode field updates can't be racing with valid readers of the
 * fields because they should have already had a locked refreshed inode
 * to be dereferencing its contents.
 */
int scoutfs_inode_refresh(struct inode *inode, struct scoutfs_lock *lock)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	struct scoutfs_inode sinode;
	const u64 refresh_gen = lock->refresh_gen;
	int ret;

	/*
	 * Lock refresh gens are supposed to strictly increase.  Inodes
	 * having a greater gen means memory corruption or
	 * lifetime/logic bugs that could stop the inode from refreshing
	 * and expose stale data.
	 */
	BUG_ON(atomic64_read(&si->last_refreshed) > refresh_gen);

	if (atomic64_read(&si->last_refreshed) == refresh_gen)
		return 0;

	scoutfs_inode_init_key(&key, scoutfs_ino(inode));

	mutex_lock(&si->item_mutex);
	if (atomic64_read(&si->last_refreshed) < refresh_gen) {
		ret = lookup_inode_item(sb, &key, &sinode, lock);
		if (ret > 0) {
			load_inode(inode, &sinode, ret);
			atomic64_set(&si->last_refreshed, refresh_gen);
			scoutfs_lock_add_coverage(sb, lock, &si->ino_lock_cov);
			ret = 0;
		}
	} else {
		ret = 0;
	}
	mutex_unlock(&si->item_mutex);

	return ret;
}

#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
int scoutfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		    struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
#else
int scoutfs_getattr(KC_VFS_NS_DEF
		    const struct path *path, struct kstat *stat,
		    u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
#endif
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret == 0) {
		generic_fillattr(KC_VFS_INIT_NS
				 inode, stat);
		scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	}
	return ret;
}

static int set_inode_size(struct inode *inode, struct scoutfs_lock *lock,
			  u64 new_size, bool truncate)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	SCOUTFS_DECLARE_PER_TASK_ENTRY(pt_ent);
	LIST_HEAD(ind_locks);
	int ret;

	if (!S_ISREG(inode->i_mode))
		return 0;

	ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, true, false);
	if (ret)
		return ret;

	scoutfs_per_task_add(&si->pt_data_lock, &pt_ent, lock);
	ret = block_truncate_page(inode->i_mapping, new_size, scoutfs_get_block_write);
	scoutfs_per_task_del(&si->pt_data_lock, &pt_ent);
	if (ret < 0)
		goto unlock;
	scoutfs_inode_queue_writeback(inode);

	if (new_size != i_size_read(inode))
		scoutfs_inode_inc_data_version(inode);

	truncate_setsize(inode, new_size);
	inode->i_ctime = inode->i_mtime = current_time(inode);
	if (truncate)
		si->flags |= SCOUTFS_INO_FLAG_TRUNCATE;
	scoutfs_inode_set_data_seq(inode);
	inode_inc_iversion(inode);
	scoutfs_update_inode_item(inode, lock, &ind_locks);

unlock:
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);

	return ret;
}

static int clear_truncate_flag(struct inode *inode, struct scoutfs_lock *lock)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	LIST_HEAD(ind_locks);
	int ret;

	ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, false, false);
	if (ret)
		return ret;

	si->flags &= ~SCOUTFS_INO_FLAG_TRUNCATE;
	scoutfs_update_inode_item(inode, lock, &ind_locks);

	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);

	return ret;
}

int scoutfs_complete_truncate(struct inode *inode, struct scoutfs_lock *lock)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	u64 start;
	int ret, err;

	trace_scoutfs_complete_truncate(inode, si->flags);

	if (!(si->flags & SCOUTFS_INO_FLAG_TRUNCATE))
		return 0;

	start = (i_size_read(inode) + SCOUTFS_BLOCK_SM_SIZE - 1) >>
		SCOUTFS_BLOCK_SM_SHIFT;
	ret = scoutfs_data_truncate_items(inode->i_sb, inode,
					  scoutfs_ino(inode), &start, ~0ULL,
					  false, lock, false);
	err = clear_truncate_flag(inode, lock);

	return ret ? ret : err;
}

/*
 * If we're changing the file size than the contents of the file are
 * changing and we increment the data_version.  This would prevent
 * staging because the data_version is per-inode today, not per-extent.
 * So if there are any offline extents within the new size then we need
 * to stage them before we truncate.  And this is called with the
 * i_mutex held which would prevent staging so we release it and
 * re-acquire it.  Ideally we'd fix this so that we can acquire the lock
 * instead of the caller.
 */
int scoutfs_setattr(KC_VFS_NS_DEF
		    struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	DECLARE_DATA_WAIT(dw);
	LIST_HEAD(ind_locks);
	bool truncate = false;
	u64 attr_size;
	int ret;

	trace_scoutfs_setattr(dentry, attr);

retry:
	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		return ret;
	ret = setattr_prepare(KC_VFS_INIT_NS
			      dentry, attr);
	if (ret)
		goto out;

	ret = scoutfs_inode_check_retention(inode);
	if (ret < 0)
		goto out;

	attr_size = (attr->ia_valid & ATTR_SIZE) ? attr->ia_size :
		i_size_read(inode);

	if (S_ISREG(inode->i_mode) && attr->ia_valid & ATTR_SIZE) {
		/*
		 * Complete any truncates that may have failed while
		 * in progress
		 */
		ret = scoutfs_complete_truncate(inode, lock);
		if (ret)
			goto out;

		/* data_version is per inode, all must be online */
		if (attr_size > 0 && attr_size != i_size_read(inode)) {
			ret = scoutfs_data_wait_check(inode, 0, attr_size,
						SEF_OFFLINE,
						SCOUTFS_IOC_DWO_CHANGE_SIZE,
						&dw, lock);
			if (ret < 0)
				goto out;
			if (scoutfs_data_wait_found(&dw)) {
				scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);

				/* XXX callee locks instead? */
				inode_unlock(inode);
				ret = scoutfs_data_wait(inode, &dw);
				inode_lock(inode);

				if (ret == 0)
					goto retry;
				goto out;
			}
		}

		/* truncating to current size truncates extents past size */
		truncate = i_size_read(inode) >= attr_size;

		ret = set_inode_size(inode, lock, attr_size, truncate);
		if (ret)
			goto out;

		if (truncate) {
			ret = scoutfs_complete_truncate(inode, lock);
			if (ret)
				goto out;
		}
	}

	ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, false, false);
	if (ret)
		goto out;

	ret = scoutfs_acl_chmod_locked(inode, attr, lock, &ind_locks);
	if (ret < 0)
		goto release;

	setattr_copy(KC_VFS_INIT_NS
		     inode, attr);
	inode_inc_iversion(inode);
	scoutfs_update_inode_item(inode, lock, &ind_locks);

release:
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
out:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	return ret;
}

/*
 * Set a given seq to the current trans seq if it differs.  The caller
 * holds locks and a transaction which prevents the transaction from
 * committing and refreshing the seq.
 */
static void set_trans_seq(struct inode *inode, u64 *seq)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (*seq != sbi->trans_seq) {
		write_seqlock(&si->seqlock);
		*seq = sbi->trans_seq;
		write_sequnlock(&si->seqlock);
	}
}

void scoutfs_inode_set_meta_seq(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	set_trans_seq(inode, &si->meta_seq);
}

void scoutfs_inode_set_data_seq(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	set_trans_seq(inode, &si->data_seq);
}

void scoutfs_inode_inc_data_version(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	write_seqlock(&si->seqlock);
	si->data_version++;
	write_sequnlock(&si->seqlock);
}

void scoutfs_inode_set_data_version(struct inode *inode, u64 data_version)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	write_seqlock(&si->seqlock);
	si->data_version = data_version;
	write_sequnlock(&si->seqlock);
}

void scoutfs_inode_add_onoff(struct inode *inode, s64 on, s64 off)
{
	struct scoutfs_inode_info *si;

	if (inode && (on || off)) {
		si = SCOUTFS_I(inode);
		write_seqlock(&si->seqlock);

		/* inode and extents out of sync, bad callers */
		if (((s64)si->online_blocks + on < 0) ||
		    ((s64)si->offline_blocks + off < 0)) {
			scoutfs_corruption(inode->i_sb, SC_INODE_BLOCK_COUNTS,
				corrupt_inode_block_counts,
				"ino %llu size %llu online %llu + %lld offline %llu + %lld",
				scoutfs_ino(inode), i_size_read(inode),
				si->online_blocks, on, si->offline_blocks, off);
		}

		si->online_blocks += on;
		si->offline_blocks += off;
		/* XXX not sure if this is right */
		inode->i_blocks += (on + off) * SCOUTFS_BLOCK_SM_SECTORS;

		trace_scoutfs_online_offline_blocks(inode, on, off,
						    si->online_blocks,
						    si->offline_blocks);

		write_sequnlock(&si->seqlock);
	}

	/* any time offline extents decreased we try and wake waiters */
	if (inode && off < 0)
		scoutfs_data_wait_changed(inode);
}

static u64 read_seqlock_u64(struct inode *inode, u64 *val)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	unsigned seq;
	u64 v;

	do {
		seq = read_seqbegin(&si->seqlock);
		v = *val;
	} while (read_seqretry(&si->seqlock, seq));

	return v;
}

u64 scoutfs_inode_meta_seq(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	return read_seqlock_u64(inode, &si->meta_seq);
}

u64 scoutfs_inode_data_seq(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	return read_seqlock_u64(inode, &si->data_seq);
}

u64 scoutfs_inode_data_version(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	return read_seqlock_u64(inode, &si->data_version);
}

void scoutfs_inode_get_onoff(struct inode *inode, s64 *on, s64 *off)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	unsigned seq;

	do {
		seq = read_seqbegin(&si->seqlock);
		*on = SCOUTFS_I(inode)->online_blocks;
		*off = SCOUTFS_I(inode)->offline_blocks;
	} while (read_seqretry(&si->seqlock, seq));
}

/*
 * Get our private scoutfs inode flags, not the vfs i_flags.
 */
u32 scoutfs_inode_get_flags(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	unsigned seq;
	u32 flags;

	do {
		seq = read_seqbegin(&si->seqlock);
		flags = si->flags;
	} while (read_seqretry(&si->seqlock, seq));

	return flags;
}

void scoutfs_inode_set_flags(struct inode *inode, u32 and, u32 or)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	write_seqlock(&si->seqlock);
	si->flags = (si->flags & and) | or;
	write_sequnlock(&si->seqlock);
}

u64 scoutfs_inode_get_proj(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	unsigned seq;
	u64 proj;

	do {
		seq = read_seqbegin(&si->seqlock);
		proj = si->proj;
	} while (read_seqretry(&si->seqlock, seq));

	return proj;
}

void scoutfs_inode_set_proj(struct inode *inode, u64 proj)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	write_seqlock(&si->seqlock);
	si->proj = proj;
	write_sequnlock(&si->seqlock);
}

static int scoutfs_iget_test(struct inode *inode, void *arg)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	u64 *ino = arg;

	return si->ino == *ino;
}

static int scoutfs_iget_set(struct inode *inode, void *arg)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	u64 *ino = arg;

	inode->i_ino = *ino;
	si->ino = *ino;

	return 0;
}

/*
 * There's a risk of a deadlock between lock invalidation and eviction.
 * Invalidation blocks locks while looking up inodes.  Eviction blocks
 * inode lookups while trying to get a lock.
 *
 * We have an inode lookup variant which will never block waiting for an
 * inode.   This is more aggressive than base ilookup5_nowait() which
 * will, you know, wait for inodes that are being freed.   We have our
 * test function hide those inodes from find_inode so that it won't wait
 * on them.
 *
 * These semantics are sufficiently weird that we use a big giant scary
 * looking function name to deter use.
 */
static int ilookup_test_nonewfree(struct inode *inode, void *arg)
{
	return scoutfs_iget_test(inode, arg) &&
	       !(inode->i_state & (I_NEW | I_WILL_FREE | I_FREEING));
}
struct inode *scoutfs_ilookup_nowait_nonewfree(struct super_block *sb, u64 ino)
{
	return ilookup5_nowait(sb, ino, ilookup_test_nonewfree, &ino);
}

/*
 * Final iput can delete an unused inode's items which can take multiple
 * locked transactions.  iget (which can call iput in error cases) and
 * iput must not be called with locks or transactions held.
 */
struct inode *scoutfs_iget(struct super_block *sb, u64 ino, int lkf, int igf)
{
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_inode_info *si;
	struct inode *inode = NULL;
	int ret;

	/* wait for vfs inode (I_FREEING in particular) before acquiring cluster lock */
	inode = iget5_locked(sb, ino, scoutfs_iget_test, scoutfs_iget_set, &ino);
	if (!inode) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_ino(sb, SCOUTFS_LOCK_READ, lkf, ino, &lock);
	if (ret < 0)
		goto out;

	if (inode->i_state & I_NEW) {
		/* XXX ensure refresh, instead clear in drop_inode? */
		si = SCOUTFS_I(inode);
		atomic64_set(&si->last_refreshed, 0);
		inode_set_iversion_queried(inode, 0);
	}

	ret = scoutfs_inode_refresh(inode, lock);
	if (ret < 0)
		goto out;

	/* check nlink both for new and after refreshing */
	if ((igf & SCOUTFS_IGF_LINKED) && inode->i_nlink == 0) {
		ret = -ENOENT;
		goto out;
	}

	if (inode->i_state & I_NEW) {
		ret = scoutfs_omap_set(sb, ino);
		if (ret < 0)
			goto out;

		set_inode_ops(inode);
		unlock_new_inode(inode);
	}

	ret = 0;
out:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);

	if (ret < 0) {
		if (inode) {
			if (inode->i_state & I_NEW)
				iget_failed(inode);
			else
				iput(inode);
		}
		inode = ERR_PTR(ret);
	}

	return inode;
}

static void store_inode(struct scoutfs_inode *cinode, struct inode *inode, int inode_bytes)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	u64 online_blocks;
	u64 offline_blocks;

	scoutfs_inode_get_onoff(inode, &online_blocks, &offline_blocks);

	cinode->size = cpu_to_le64(i_size_read(inode));
	cinode->version = cpu_to_le64(inode_peek_iversion(inode));
	cinode->nlink = cpu_to_le32(inode->i_nlink);
	cinode->uid = cpu_to_le32(i_uid_read(inode));
	cinode->gid = cpu_to_le32(i_gid_read(inode));
	cinode->mode = cpu_to_le32(inode->i_mode);
	cinode->rdev = cpu_to_le32(inode->i_rdev);
	cinode->atime.sec = cpu_to_le64(inode->i_atime.tv_sec);
	cinode->atime.nsec = cpu_to_le32(inode->i_atime.tv_nsec);
	memset(cinode->atime.__pad, 0, sizeof(cinode->atime.__pad));
	cinode->ctime.sec = cpu_to_le64(inode->i_ctime.tv_sec);
	cinode->ctime.nsec = cpu_to_le32(inode->i_ctime.tv_nsec);
	memset(cinode->ctime.__pad, 0, sizeof(cinode->ctime.__pad));
	cinode->mtime.sec = cpu_to_le64(inode->i_mtime.tv_sec);
	cinode->mtime.nsec = cpu_to_le32(inode->i_mtime.tv_nsec);
	memset(cinode->mtime.__pad, 0, sizeof(cinode->mtime.__pad));

	cinode->meta_seq = cpu_to_le64(scoutfs_inode_meta_seq(inode));
	cinode->data_seq = cpu_to_le64(scoutfs_inode_data_seq(inode));
	cinode->data_version = cpu_to_le64(scoutfs_inode_data_version(inode));
	cinode->online_blocks = cpu_to_le64(online_blocks);
	cinode->offline_blocks = cpu_to_le64(offline_blocks);
	cinode->next_readdir_pos = cpu_to_le64(si->next_readdir_pos);
	cinode->next_xattr_id = cpu_to_le64(si->next_xattr_id);
	cinode->flags = cpu_to_le32(si->flags);
	cinode->crtime.sec = cpu_to_le64(si->crtime.tv_sec);
	cinode->crtime.nsec = cpu_to_le32(si->crtime.tv_nsec);
	memset(cinode->crtime.__pad, 0, sizeof(cinode->crtime.__pad));
	cinode->proj = cpu_to_le64(si->proj);
}

/*
 * Create a pinned dirty inode item so that we can later update the
 * inode item without risking failure.  We often wouldn't want to have
 * to unwind inode modifcations (perhaps by shared vfs code!) if our
 * item update failed.  This is our chance to return errors for enospc
 * for lack of space for new logged dirty inode items.
 *
 * This dirty inode item will be found by lookups in the interim so we
 * have to update it now with the current inode contents.
 *
 * Callers don't delete these dirty items on errors.  They're still
 * valid and will be merged with the current item eventually.
 *
 * The caller has to prevent sync between dirtying and updating the
 * inodes.
 *
 * XXX this will have to do something about variable length inodes
 */
int scoutfs_dirty_inode_item(struct inode *inode, struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_inode sinode;
	struct scoutfs_key key;
	int inode_bytes;
	int ret;

	inode_bytes = scoutfs_inode_vers_bytes(sbi->fmt_vers);
	store_inode(&sinode, inode, inode_bytes);

	scoutfs_inode_init_key(&key, scoutfs_ino(inode));

	ret = scoutfs_item_update(sb, &key, &sinode, inode_bytes, lock);
	if (!ret)
		trace_scoutfs_dirty_inode(inode);
	return ret;
}

struct index_lock {
	struct list_head head;
	struct scoutfs_lock *lock;
	u8 type;
	u64 major;
	u32 minor;
	u64 ino;
};

static bool will_del_index(struct scoutfs_inode_info *si,
			   u8 type, u64 major, u32 minor)
{
	return si && si->have_item &&
	       (get_item_major(si, type) != major || get_item_minor(si, type) != minor);
}

static bool will_ins_index(struct scoutfs_inode_info *si,
			   u8 type, u64 major, u32 minor)
{
	return !si || !si->have_item ||
	       (get_item_major(si, type) != major || get_item_minor(si, type) != minor);
}

static bool inode_has_index(umode_t mode, u8 type)
{
	switch(type) {
		case SCOUTFS_INODE_INDEX_META_SEQ_TYPE:
			return true;
		case SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE:
			return S_ISREG(mode);
		default:
			return WARN_ON_ONCE(false);
	}
}

static int cmp_index_lock(void *priv, KC_LIST_CMP_CONST struct list_head *A, KC_LIST_CMP_CONST struct list_head *B)
{
	KC_LIST_CMP_CONST struct index_lock *a = list_entry(A, KC_LIST_CMP_CONST struct index_lock, head);
	KC_LIST_CMP_CONST struct index_lock *b = list_entry(B, KC_LIST_CMP_CONST struct index_lock, head);

	return ((int)a->type - (int)b->type) ?:
	       scoutfs_cmp_u64s(a->major, b->major) ?:
	       scoutfs_cmp_u64s(a->minor, b->minor) ?:
	       scoutfs_cmp_u64s(a->ino, b->ino);
}

static void clamp_inode_index(u8 type, u64 *major, u32 *minor, u64 *ino)
{
	struct scoutfs_key start;

	scoutfs_lock_get_index_item_range(type, *major, *ino, &start, NULL);

	*major = le64_to_cpu(start.skii_major);
	*minor = 0;
	*ino = le64_to_cpu(start.skii_ino);
}

/*
 * Find the lock that covers the given index item.  Returns NULL if
 * there isn't a lock that covers the item.  We know that the list is
 * sorted at this point so we can stop once our search value is less
 * than a list entry.
 */
static struct scoutfs_lock *find_index_lock(struct list_head *lock_list,
					    u8 type, u64 major, u32 minor,
					    u64 ino)
{
	struct index_lock *ind_lock;
	struct index_lock needle;
	int cmp;

	clamp_inode_index(type, &major, &minor, &ino);
	needle.type = type;
	needle.major = major;
	needle.minor = minor;
	needle.ino = ino;

	list_for_each_entry(ind_lock, lock_list, head) {
		cmp = cmp_index_lock(NULL, &needle.head, &ind_lock->head);
		if (cmp == 0)
			return ind_lock->lock;
		if (cmp < 0)
			break;
	}

	return NULL;
}

void scoutfs_inode_init_index_key(struct scoutfs_key *key, u8 type, u64 major,
				  u32 minor, u64 ino)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_INODE_INDEX_ZONE,
		.sk_type = type,
		.skii_major = cpu_to_le64(major),
		.skii_ino = cpu_to_le64(ino),
	};
}

/*
 * The inode info reflects the current inode index items.  Create or delete
 * index items to bring the index in line with the caller's item.  The list
 * should contain locks that cover any item modifications that are made.
 */
static int update_index_items(struct super_block *sb,
			      struct scoutfs_inode_info *si, u64 ino, u8 type,
			      u64 major, u32 minor,
			      struct list_head *lock_list,
			      struct scoutfs_lock *primary)
{
	struct scoutfs_lock *ins_lock;
	struct scoutfs_lock *del_lock;
	struct scoutfs_key ins;
	struct scoutfs_key del;
	int ret;
	int err;

	if (!will_ins_index(si, type, major, minor))
		return 0;

	trace_scoutfs_create_index_item(sb, type, major, minor, ino);

	scoutfs_inode_init_index_key(&ins, type, major, minor, ino);

	ins_lock = find_index_lock(lock_list, type, major, minor, ino);
	ret = scoutfs_item_create_force(sb, &ins, NULL, 0, ins_lock, primary);
	if (ret || !will_del_index(si, type, major, minor))
		return ret;

	trace_scoutfs_delete_index_item(sb, type, get_item_major(si, type),
					get_item_minor(si, type), ino);

	scoutfs_inode_init_index_key(&del, type, get_item_major(si, type),
				     get_item_minor(si, type), ino);

	del_lock = find_index_lock(lock_list, type, get_item_major(si, type),
				   get_item_minor(si, type), ino);
	ret = scoutfs_item_delete_force(sb, &del, del_lock, primary);
	if (ret) {
		err = scoutfs_item_delete(sb, &ins, ins_lock);
		BUG_ON(err);
	}

	return ret;
}

static int update_indices(struct super_block *sb,
			  struct scoutfs_inode_info *si, u64 ino, umode_t mode,
			  struct scoutfs_inode *sinode,
			  struct list_head *lock_list,
			  struct scoutfs_lock *primary)
{
	struct index_update {
		u8 type;
		u64 major;
		u32 minor;
	} *upd, upds[] = {
		{ SCOUTFS_INODE_INDEX_META_SEQ_TYPE,
			le64_to_cpu(sinode->meta_seq), 0 },
		{ SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE,
			le64_to_cpu(sinode->data_seq), 0 },
	};
	int ret;
	int i;

	for (i = 0, upd = upds; i < ARRAY_SIZE(upds); i++, upd++) {
		if (!inode_has_index(mode, upd->type))
			continue;

		ret = update_index_items(sb, si, ino, upd->type, upd->major,
					 upd->minor, lock_list, primary);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Every time we modify the inode in memory we copy it to its inode
 * item.  This lets us write out items without having to track down
 * dirty vfs inodes.
 *
 * The caller makes sure that the item is dirty and pinned so they don't
 * have to deal with errors and unwinding after they've modified the vfs
 * inode and get here.
 *
 * Index items that track inode fields are updated here as we update the
 * inode item.  The caller must have acquired locks on all the index
 * items that might change.
 */
void scoutfs_update_inode_item(struct inode *inode, struct scoutfs_lock *lock,
			       struct list_head *lock_list)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_inode sinode;
	struct scoutfs_key key;
	int inode_bytes;
	int ret;
	int err;

	mutex_lock(&si->item_mutex);

	/* set the meta version once per trans for any inode updates */
	scoutfs_inode_set_meta_seq(inode);

	inode_bytes = scoutfs_inode_vers_bytes(sbi->fmt_vers);

	/* only race with other inode field stores once */
	store_inode(&sinode, inode, inode_bytes);

	ret = update_indices(sb, si, ino, inode->i_mode, &sinode, lock_list, lock);
	BUG_ON(ret);

	scoutfs_inode_init_key(&key, ino);

	err = scoutfs_item_update(sb, &key, &sinode, inode_bytes, lock);
	if (err) {
		scoutfs_err(sb, "inode %llu update err %d", ino, err);
		BUG_ON(err);
	}

	set_item_info(si, &sinode);
	trace_scoutfs_update_inode(inode);

	mutex_unlock(&si->item_mutex);
}

/*
 * We map the item to coarse locks here.  This reduces the number of
 * locks we track and means that when we later try to find the lock that
 * covers an item we can deal with the item update changing a little
 * while still being covered.  It does mean we have to share some logic
 * with lock naming.
 */
static int add_index_lock(struct list_head *list, u64 ino, u8 type, u64 major,
			  u32 minor)
{
	struct index_lock *ind_lock;

	clamp_inode_index(type, &major, &minor, &ino);

	list_for_each_entry(ind_lock, list, head) {
		if (ind_lock->type == type && ind_lock->major == major &&
		    ind_lock->minor == minor && ind_lock->ino == ino) {
			return 0;
		}
	}

	ind_lock = kzalloc(sizeof(struct index_lock), GFP_NOFS);
	if (!ind_lock)
		return -ENOMEM;

	ind_lock->type = type;
	ind_lock->major = major;
	ind_lock->minor = minor;
	ind_lock->ino = ino;
	list_add(&ind_lock->head, list);

	return 0;
}

static int prepare_index_items(struct scoutfs_inode_info *si,
			       struct list_head *list, u64 ino, umode_t mode,
			       u8 type, u64 major, u32 minor)
{
	int ret;

	if (will_ins_index(si, type, major, minor)) {
		ret = add_index_lock(list, ino, type, major, minor);
		if (ret)
			return ret;
	}

	if (will_del_index(si, type, major, minor)) {
		ret = add_index_lock(list, ino, type, get_item_major(si, type),
				     get_item_minor(si, type));
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Return the data seq that we expect to see in the updated inode.  The
 * caller tells us if they know they're going to update it.  If the
 * inode doesn't exist it'll also get the current data_seq.
 */
static u64 upd_data_seq(struct scoutfs_sb_info *sbi,
			struct scoutfs_inode_info *si, bool set_data_seq)
{
	if (!si || !si->have_item || set_data_seq)
		return sbi->trans_seq;

	return get_item_major(si, SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE);
}

/*
 * Prepare locks that will cover the inode index items that will be
 * modified when this inode's item is updated during the upcoming
 * transaction.
 *
 * To lock the index items that will be created we need to predict the
 * new indexed values.  We assume that the meta seq will always be set
 * to the current seq.  This will usually be a nop in a running
 * transaction.  The caller tells us what the size will be and whether
 * data_seq will also be set to the current transaction.
 */
static int prepare_indices(struct super_block *sb, struct list_head *list,
			   struct scoutfs_inode_info *si, u64 ino,
			   umode_t mode, bool set_data_seq)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct index_update {
		u8 type;
		u64 major;
		u32 minor;
	} *upd, upds[] = {
		{ SCOUTFS_INODE_INDEX_META_SEQ_TYPE, sbi->trans_seq, 0},
		{ SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE,
			upd_data_seq(sbi, si, set_data_seq), 0},
	};
	int ret;
	int i;

	for (i = 0, upd = upds; i < ARRAY_SIZE(upds); i++, upd++) {
		if (!inode_has_index(mode, upd->type))
			continue;

		ret = prepare_index_items(si, list, ino, mode,
					  upd->type, upd->major, upd->minor);
		if (ret)
			break;
	}

	return ret;
}

int scoutfs_inode_index_prepare(struct super_block *sb, struct list_head *list,
			        struct inode *inode, bool set_data_seq)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	return prepare_indices(sb, list, si, scoutfs_ino(inode),
			       inode->i_mode, set_data_seq);
}

/*
 * This is used to initially create the index items for a newly created
 * inode.  We don't have a populated vfs inode yet.  The existing
 * indexed values don't matter because it's 'have_item' is false.  It
 * will try to create all the appropriate index items.
 */
int scoutfs_inode_index_prepare_ino(struct super_block *sb,
				    struct list_head *list, u64 ino,
				    umode_t mode)
{
	return prepare_indices(sb, list, NULL, ino, mode, true);
}

/*
 * Prepare the locks needed to delete all the index items associated
 * with the inode.  We know the items have to exist and can skip straight
 * to adding locks for each of them.
 */
static int prepare_index_deletion(struct super_block *sb,
				  struct list_head *list, u64 ino,
				  umode_t mode, struct scoutfs_inode *sinode)
{
	struct index_item {
		u8 type;
		u64 major;
		u32 minor;
	} *ind, inds[] = {
		{ SCOUTFS_INODE_INDEX_META_SEQ_TYPE,
			le64_to_cpu(sinode->meta_seq), 0 },
		{ SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE,
			le64_to_cpu(sinode->data_seq), 0 },
	};
	int ret;
	int i;

	for (i = 0, ind = inds; i < ARRAY_SIZE(inds); i++, ind++) {
		if (!inode_has_index(mode, ind->type))
			continue;

		ret = add_index_lock(list, ino, ind->type,  ind->major,
				     ind->minor);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Sample the transaction sequence before we start checking it to see if
 * indexed meta seq and data seq items will change.
 */
int scoutfs_inode_index_start(struct super_block *sb, u64 *seq)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	/* XXX this feels racey in a bad way :) */
	*seq = sbi->trans_seq;
	return 0;
}

/*
 * Acquire the prepared index locks and hold the transaction.  If the
 * sequence number changes as we enter the transaction then we need to
 * retry so that we can use the new seq to prepare locks.
 *
 * Returns > 0 if the seq changed and the locks should be retried.
 */
int scoutfs_inode_index_try_lock_hold(struct super_block *sb,
				      struct list_head *list, u64 seq, bool allocing)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct index_lock *ind_lock;
	int ret = 0;

	list_sort(NULL, list, cmp_index_lock);

	list_for_each_entry(ind_lock, list, head) {
		ret = scoutfs_lock_inode_index(sb, SCOUTFS_LOCK_WRITE_ONLY,
					       ind_lock->type, ind_lock->major,
					       ind_lock->ino, &ind_lock->lock);
		if (ret)
			goto out;
	}

	ret = scoutfs_hold_trans(sb, allocing);
	if (ret == 0 && seq != sbi->trans_seq) {
		scoutfs_release_trans(sb);
		ret = 1;
	}

out:
	if (ret)
		scoutfs_inode_index_unlock(sb, list);

	return ret;
}

int scoutfs_inode_index_lock_hold(struct inode *inode, struct list_head *list,
				  bool set_data_seq, bool allocing)
{
	struct super_block *sb = inode->i_sb;
	int ret;
	u64 seq;

	do {
		ret = scoutfs_inode_index_start(sb, &seq) ?:
		      scoutfs_inode_index_prepare(sb, list, inode,
						  set_data_seq) ?:
		      scoutfs_inode_index_try_lock_hold(sb, list, seq, allocing);
	} while (ret > 0);

	return ret;
}

/*
 * Unlocks and frees all the locks on the list.
 */
void scoutfs_inode_index_unlock(struct super_block *sb, struct list_head *list)
{
	struct index_lock *ind_lock;
	struct index_lock *tmp;

	list_for_each_entry_safe(ind_lock, tmp, list, head) {
		scoutfs_unlock(sb, ind_lock->lock, SCOUTFS_LOCK_WRITE_ONLY);
		list_del_init(&ind_lock->head);
		kfree(ind_lock);
	}
}

/* this is called on final inode cleanup so enoent is fine */
static int remove_index(struct super_block *sb, u64 ino, u8 type, u64 major,
			u32 minor, struct list_head *ind_locks, struct scoutfs_lock *primary)
{
	struct scoutfs_key key;
	struct scoutfs_lock *lock;
	int ret;

	scoutfs_inode_init_index_key(&key, type, major, minor, ino);

	lock = find_index_lock(ind_locks, type, major, minor, ino);
	ret = scoutfs_item_delete_force(sb, &key, lock, primary);
	if (ret == -ENOENT)
		ret = 0;
	return ret;
}

/*
 * Remove all the inode's index items.  The caller has ensured that
 * there are no more active users of the inode.  This can be racing with
 * users of the inode index items.  Once we can use them we'll get CW
 * locks around the index items to invalidate remote caches.  Racing
 * users of the index items already have to deal with the possibility
 * that the inodes returned by the index queries can go out of sync by
 * the time they get to it, including being deleted.
 */
static int remove_index_items(struct super_block *sb, u64 ino,
			      struct scoutfs_inode *sinode,
			      struct list_head *ind_locks,
			      struct scoutfs_lock *primary)
{
	umode_t mode = le32_to_cpu(sinode->mode);
	int ret;

	ret = remove_index(sb, ino, SCOUTFS_INODE_INDEX_META_SEQ_TYPE,
			   le64_to_cpu(sinode->meta_seq), 0, ind_locks, primary);
	if (ret == 0 && S_ISREG(mode))
		ret = remove_index(sb, ino, SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE,
				   le64_to_cpu(sinode->data_seq), 0, ind_locks, primary);
	return ret;
}

/*
 * Return an allocated and unused inode number.  Returns -ENOSPC if
 * we're out of inode.
 *
 * Each parent directory has its own pool of free inode numbers.  Items
 * are sorted by their inode numbers as they're stored in segments.
 * This will tend to group together files that are created in a
 * directory at the same time in segments.  Concurrent creation across
 * different directories will be stored in their own regions.
 *
 * Inode numbers are never reclaimed.  If the inode is evicted or we're
 * unmounted the pending inode numbers will be lost.  Asking for a
 * relatively small number from the server each time will tend to
 * minimize that loss while still being large enough for typical
 * directory file counts.
 */
int scoutfs_alloc_ino(struct super_block *sb, bool is_dir, u64 *ino_ret)
{
	DECLARE_INODE_SB_INFO(sb, inf);
	struct inode_allocator *ia;
	u64 ino;
	u64 nr;
	int ret;

	ia = is_dir ? &inf->dir_ino_alloc : &inf->ino_alloc;

	spin_lock(&ia->lock);

	if (ia->nr == 0) {
		spin_unlock(&ia->lock);
		ret = scoutfs_client_alloc_inodes(sb,
					SCOUTFS_LOCK_INODE_GROUP_NR * 10,
					&ino, &nr);
		if (ret < 0)
			goto out;
		spin_lock(&ia->lock);
		if (ia->nr == 0) {
			ia->ino = ino;
			ia->nr = nr;
		}
	}

	*ino_ret = ia->ino++;
	ia->nr--;

	spin_unlock(&ia->lock);
	ret = 0;
out:
	trace_scoutfs_alloc_ino(sb, ret, *ino_ret, ia->ino, ia->nr);
	return ret;
}

/*
 * Allocate and initialize a new inode.  The caller is responsible for
 * creating links to it and updating it.  @dir can be null.
 *
 * This is called with locks and a transaction because it creates the
 * inode item.   We can't call iput on the new inode on error.   We
 * return the inode to the caller *including on error* for them to put
 * once they've released the transaction.
 */
int scoutfs_new_inode(struct super_block *sb, struct inode *dir, umode_t mode, dev_t rdev,
		      u64 ino, struct scoutfs_lock *lock, struct inode **inode_ret)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_inode_info *si;
	struct scoutfs_inode sinode;
	struct scoutfs_key key;
	struct inode *inode;
	int inode_bytes;
	int ret;

	inode = new_inode(sb);
	if (!inode) {
		ret = -ENOMEM;
		goto out;
	}

	si = SCOUTFS_I(inode);
	si->ino = ino;
	si->data_version = 0;
	si->online_blocks = 0;
	si->offline_blocks = 0;
	si->next_readdir_pos = SCOUTFS_DIRENT_FIRST_POS;
	si->next_xattr_id = 0;
	si->proj = 0;
	si->have_item = false;
	atomic64_set(&si->last_refreshed, lock->refresh_gen);
	scoutfs_lock_add_coverage(sb, lock, &si->ino_lock_cov);
	si->flags = 0;

	scoutfs_inode_set_meta_seq(inode);
	scoutfs_inode_set_data_seq(inode);

	inode->i_ino = ino; /* XXX overflow */
	inode_init_owner(KC_VFS_INIT_NS
			 inode, dir, mode);
	inode_set_bytes(inode, 0);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_rdev = rdev;
	set_inode_ops(inode);

	inode_bytes = scoutfs_inode_vers_bytes(sbi->fmt_vers);

	store_inode(&sinode, inode, inode_bytes);
	scoutfs_inode_init_key(&key, scoutfs_ino(inode));

	ret = scoutfs_omap_set(sb, ino);
	if (ret < 0)
		goto out;

	ret = scoutfs_item_create(sb, &key, &sinode, inode_bytes, lock);
	if (ret < 0)
		scoutfs_omap_clear(sb, ino);
out:
	*inode_ret = inode;

	return ret;
}

static void init_orphan_key(struct scoutfs_key *key, u64 ino)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_ORPHAN_ZONE,
		.sko_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_ORPHAN_TYPE,
	};
}

/*
 * Create an orphan item.  The orphan items are maintained in their own
 * zone under a write only lock while the caller has the inode protected
 * by a write lock.
 */
int scoutfs_inode_orphan_create(struct super_block *sb, u64 ino, struct scoutfs_lock *lock,
				struct scoutfs_lock *primary)
{
	struct scoutfs_key key;

	init_orphan_key(&key, ino);

	return scoutfs_item_create_force(sb, &key, NULL, 0, lock, primary);
}

int scoutfs_inode_orphan_delete(struct super_block *sb, u64 ino, struct scoutfs_lock *lock,
				struct scoutfs_lock *primary)
{
	struct scoutfs_key key;

	init_orphan_key(&key, ino);

	return scoutfs_item_delete_force(sb, &key, lock, primary);
}

/*
 * Remove all the items associated with a given inode.  This is only
 * called once nlink has dropped to zero and nothing has the inode open
 * so we don't have to worry about dirents referencing the inode or link
 * backrefs.  Dropping nlink to 0 also created an orphan item.  That
 * orphan item will continue triggering attempts to finish previous
 * partial deletion until all deletion is complete and the orphan item
 * is removed.
 */
static int delete_inode_items(struct super_block *sb, u64 ino,
			      struct scoutfs_inode *sinode, u64 *start,
			      struct scoutfs_lock *lock, struct scoutfs_lock *orph_lock)
{
	struct scoutfs_key key;
	LIST_HEAD(ind_locks);
	bool release = false;
	umode_t mode;
	u64 ind_seq;
	u64 size;
	int ret;

	scoutfs_inode_init_key(&key, ino);

	mode = le32_to_cpu(sinode->mode);
	size = le64_to_cpu(sinode->size);
	trace_scoutfs_delete_inode(sb, ino, mode, size);

	/* remove data items in their own transactions */
	if (S_ISREG(mode)) {
		ret = scoutfs_data_truncate_items(sb, NULL, ino, start, ~0ULL,
						  false, lock, true);
		if (ret)
			goto out;
	}

	ret = scoutfs_xattr_drop(sb, ino, lock);
	if (ret)
		goto out;

	/* then delete the small known number of remaining inode items */
retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      prepare_index_deletion(sb, &ind_locks, ino, mode, sinode) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq, false);
	if (ret > 0)
		goto retry;
	if (ret)
		goto out;

	release = true;

	ret = remove_index_items(sb, ino, sinode, &ind_locks, lock);
	if (ret)
		goto out;

	if (S_ISLNK(mode)) {
		ret = scoutfs_symlink_drop(sb, ino, lock, size);
		if (ret)
			goto out;
	}

	/* make sure inode item and orphan are deleted together */
	ret = scoutfs_item_dirty(sb, &key, lock);
	if (ret < 0)
		goto out;

	ret = scoutfs_inode_orphan_delete(sb, ino, orph_lock, lock);
	if (ret < 0)
		goto out;

	ret = scoutfs_item_delete(sb, &key, lock);
	BUG_ON(ret != 0); /* dirtying should have guaranteed success */

	scoutfs_forest_dec_inode_count(sb);

out:
	if (release)
		scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);

	return ret;
}

struct inode_deletion_lock_data {
	wait_queue_head_t waitq;
	atomic64_t seq;
	struct scoutfs_open_ino_map map;
	unsigned long trying[DIV_ROUND_UP(SCOUTFS_OPEN_INO_MAP_BITS, BITS_PER_LONG)];
};

/*
 * Get a lock data struct that has the current omap from this hold of
 * the lock.  The lock data is saved on the lock so it can be used
 * multiple times until the lock is refreshed.  Only one task will send
 * an omap request at a time, and errors are only returned by each task
 * as it gets a response to its send.
 */
static int get_current_lock_data(struct super_block *sb, struct scoutfs_lock *lock,
				 struct inode_deletion_lock_data **ldata_ret, u64 group_nr)
{
	struct inode_deletion_lock_data *ldata;
	u64 seq;
	int ret;

	/* we're storing omap maps in locks, they need to cover the same number of inodes */
	BUILD_BUG_ON(SCOUTFS_OPEN_INO_MAP_BITS != SCOUTFS_LOCK_INODE_GROUP_NR);

	/* allocate a new lock data struct as needed */
	while ((ldata = cmpxchg(&lock->inode_deletion_data, NULL, NULL)) == NULL) {
		ldata = kzalloc(sizeof(struct inode_deletion_lock_data), GFP_NOFS);
		if (!ldata) {
			ret = -ENOMEM;
			goto out;
		}

		atomic64_set(&ldata->seq, lock->write_seq - 1); /* ensure refresh */
		init_waitqueue_head(&ldata->waitq);

		/* the lock kfrees the inode_deletion_data pointer along with the lock */
		if (cmpxchg(&lock->inode_deletion_data, NULL, ldata) == NULL)
			break;
		else
			kfree(ldata);
	}

	/* make sure that the lock's data is current */
	while ((seq = atomic64_read(&ldata->seq)) != lock->write_seq) {
		if (seq != U64_MAX && atomic64_cmpxchg(&ldata->seq, seq, U64_MAX) == seq) {
			/* ask the server for current omap */
			ret = scoutfs_client_open_ino_map(sb, group_nr, &ldata->map);
			if (ret == 0)
				atomic64_set(&ldata->seq, lock->write_seq);
			else
				atomic64_set(&ldata->seq, lock->write_seq - 1);
			wake_up(&ldata->waitq);
			if (ret < 0)
				goto out;
		} else {
			/* wait for someone else who's sent a request */
			wait_event(ldata->waitq, atomic64_read(&ldata->seq) != U64_MAX);
		}
	}

	ret = 0;
out:
	if (ret < 0)
		ldata = NULL;
	*ldata_ret = ldata;
	return ret;
}

/*
 * Try to delete all the items for an unused inode number.  This is the
 * relatively slow path that uses cluster locks, network requests, and
 * IO to ensure correctness.  Callers should try hard to avoid calling
 * when there's no work to do.
 *
 * Inode references are added under cluster locks.  In-memory vfs cache
 * references are added under read cluster locks and are visible in omap
 * bitmaps.  Directory entry references are added under write cluster
 * locks and are visible in the inode's nlink.  Orphan items exist
 * whenever nlink == 0 and are maintained under write cluster locks.
 * Directory entries can be added to an inode with nlink == 0 to
 * instantiate tmpfile inodes into the name space.  Cached inodes will
 * not be created for inodes with an nlink of 0.
 *
 * Combining all this we know that it's safe to delete an inode's items
 * when we hold an exclusive write cluster lock, the inode has nlink ==
 * 0, and an omap request protected by the lock doesn't have the inode's
 * bit set.
 *
 * This is called by orphan scanning and vfs inode cache eviction after
 * they've checked that the inode could really be deleted.  We serialize
 * on a bit in the lock data so that we only have one deletion attempt
 * per inode under this mount's cluster lock.
 */
static int try_delete_inode_items(struct super_block *sb, u64 ino)
{
	struct inode_deletion_lock_data *ldata;
	struct scoutfs_lock *orph_lock;
	struct scoutfs_lock *lock;
	struct scoutfs_inode sinode;
	struct scoutfs_key key;
	bool clear_trying = false;
	bool more = false;
	u64 group_nr;
	u64 start = 0;
	int bit_nr;
	int ret;

again:
	ldata = NULL;
	orph_lock = NULL;
	lock = NULL;

	ret = scoutfs_lock_ino(sb, SCOUTFS_LOCK_WRITE, 0, ino, &lock);
	if (ret < 0)
		goto out;

	scoutfs_omap_calc_group_nrs(ino, &group_nr, &bit_nr);

	ret = get_current_lock_data(sb, lock, &ldata, group_nr);
	if (ret < 0)
		goto out;

	/* only one local attempt per inode at a time */
	if (!more && test_and_set_bit(bit_nr, ldata->trying)) {
		ret = 0;
		goto out;
	}
	clear_trying = true;
	more = false;

	/* can't delete if it's cached in local or remote mounts */
	if (scoutfs_omap_test(sb, ino) || test_bit_le(bit_nr, ldata->map.bits)) {
		ret = 0;
		goto out;
	}

	scoutfs_inode_init_key(&key, ino);
	ret = lookup_inode_item(sb, &key, &sinode, lock);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	if (le32_to_cpu(sinode.nlink) > 0) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_lock_orphan(sb, SCOUTFS_LOCK_WRITE_ONLY, 0, ino, &orph_lock);
	if (ret < 0)
		goto out;

	ret = delete_inode_items(sb, ino, &sinode, &start, lock, orph_lock);

	if (ret == -EINPROGRESS) {
		more = true;
		clear_trying = false;
	} else {
		more = false;
	}

out:
	if (clear_trying)
		clear_bit(bit_nr, ldata->trying);

	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, orph_lock, SCOUTFS_LOCK_WRITE_ONLY);

	if (more)
		goto again;

	return ret;
}

/*
 * As we evicted an inode we need to decide to try and delete its items
 * or not, which is expensive.  We only try when we have lock coverage
 * and the inode has been unlinked.  This catches the common case of
 * regular deletion so deletion will be performed in the final unlink
 * task.  It also catches open-unlink or o_tmpfile that aren't cached on
 * other nodes.
 *
 * Inodes being evicted outside of lock coverage, by referenced dentries
 * or inodes that survived the attempt to drop them as their lock was
 * invalidated, will not try to delete.  This means that cross-mount
 * open/unlink will almost certainly fall back to the orphan scanner to
 * perform final deletion.
 */
void scoutfs_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	const u64 ino = scoutfs_ino(inode);

	trace_scoutfs_evict_inode(sb, ino, inode->i_nlink, is_bad_inode(inode));

	if (!is_bad_inode(inode)) {
		truncate_inode_pages_final(&inode->i_data);

		/* clear before trying to delete tests */
		scoutfs_omap_clear(sb, ino);

		if (scoutfs_lock_is_covered(sb, &si->ino_lock_cov) && inode->i_nlink == 0)
			try_delete_inode_items(sb, scoutfs_ino(inode));
	}

	clear_inode(inode);
}

/*
 * We want to remove inodes from the cache as their count goes to 0 if
 * they're no longer covered by a cluster lock or if while locked they
 * were unlinked.
 *
 * We don't want unused cached inodes to linger outside of cluster
 * locking so that they don't prevent final inode deletion on other
 * nodes.  We don't have specific per-inode or per-dentry locks which
 * would otherwise remove the stale caches as they're invalidated.
 * Stale cached inodes provide little value because they're going to be
 * refreshed the next time they're locked.  Populating the item cache
 * and loading the inode item is a lot more expensive than initializing
 * and inserting a newly allocated vfs inode.
 */
int scoutfs_drop_inode(struct inode *inode)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	const bool covered = scoutfs_lock_is_covered(sb, &si->ino_lock_cov);

	trace_scoutfs_drop_inode(sb, scoutfs_ino(inode), inode->i_nlink, inode_unhashed(inode),
				 covered);

	return !covered || generic_drop_inode(inode);
}


/*
 * These iput workers can be concurrent amongst cpus.  This lets us get
 * some concurrency when these async final iputs end up performing very
 * expensive inode deletion.  Typically they're dropping linked inodes
 * that lost lock coverage and the iput will evict without deleting.
 *
 * Keep in mind that the dputs in d_prune can ascend into parents and
 * end up performing the final iput->evict deletion on other inodes.
 */
static void iput_worker(struct work_struct *work)
{
	struct inode_sb_info *inf = container_of(work, struct inode_sb_info, iput_work);
	struct scoutfs_inode_info *si;
	struct inode *inode;
	unsigned long count;
	unsigned long flags;

	spin_lock(&inf->iput_lock);
	while ((si = list_first_entry_or_null(&inf->iput_list, struct scoutfs_inode_info,
					      iput_head))) {
		list_del_init(&si->iput_head);
		count = si->iput_count;
		flags = si->iput_flags;
		si->iput_count = 0;
		si->iput_flags = 0;
		spin_unlock(&inf->iput_lock);

		inode = &si->inode;

		/* can't touch during unmount, dcache destroys w/o locks */
		if ((flags & SI_IPUT_FLAG_PRUNE) && !inf->stopped)
			d_prune_aliases(inode);

		while (count-- > 0)
			iput(inode);

		/* can't touch inode after final iput */

		spin_lock(&inf->iput_lock);
	}
	spin_unlock(&inf->iput_lock);
}

/*
 * Final iput can get into evict and perform final inode deletion which
 * can delete a lot of items spanning multiple cluster locks and
 * transactions.  It should be understood as a heavy high level
 * operation, more like file writing and less like dropping a refcount.
 *
 * Unfortunately we also have incentives to use igrab/iput from internal
 * contexts that have no business doing that work, like lock
 * invalidation or dirty inode writeback during transaction commit.
 *
 * In those cases we can kick iput off to background work context.
 * Nothing stops multiple puts of an inode before the work runs so we
 * can track multiple puts in flight.
 */
void scoutfs_inode_queue_iput(struct inode *inode, unsigned long flags)
{
	DECLARE_INODE_SB_INFO(inode->i_sb, inf);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	bool should_queue;

	spin_lock(&inf->iput_lock);
	si->iput_count++;
	si->iput_flags |= flags;
	if ((should_queue = list_empty(&si->iput_head)))
		list_add_tail(&si->iput_head, &inf->iput_list);
	spin_unlock(&inf->iput_lock);

	if (should_queue)
		queue_work(inf->iput_workq, &inf->iput_work);
}

/*
 * All mounts are performing this work concurrently.  We introduce
 * significant jitter between them to try and keep them from all
 * bunching up and working on the same inodes.  We always try to delay
 * for at least one jiffy if precision tricks us into calculating no
 * delay.
 */
void scoutfs_inode_schedule_orphan_dwork(struct super_block *sb)
{
	DECLARE_INODE_SB_INFO(sb, inf);
	struct scoutfs_mount_options opts;
	unsigned long low;
	unsigned long high;
	unsigned long delay;

	if (!inf->stopped) {
		scoutfs_options_read(sb, &opts);

		low = (opts.orphan_scan_delay_ms * 80) / 100;
		high = (opts.orphan_scan_delay_ms * 120) / 100;
		delay = msecs_to_jiffies(low + prandom_u32_max(high - low)) ?: 1;

		mod_delayed_work(system_wq, &inf->orphan_scan_dwork, delay);
	}
}

/*
 * Find and delete inodes whose only remaining reference is the
 * persistent orphan item that was created as they were unlinked.
 *
 * Orphan items are maintained for inodes that have an nlink of 0.
 * Typically this is from unlink, but tmpfiles are created with orphans.
 * They're deleted as the final cached inode is evicted and the inode
 * items are destroyed.
 *
 * This work runs in all mounts in the background looking for those
 * orphaned inodes that weren't fully deleted.
 *
 * First, we search for items in the current persistent fs root.  We'll
 * only find orphan items that made it to the fs root after being merged
 * from a mount's log btree.  This naturally avoids orphan items that
 * exist while inodes have been unlinked but are still cached, including
 * tmpfile inodes that are actively used during normal operations.
 * Scanning the read-only persistent fs root uses cached blocks and
 * avoids the lock contention we'd cause if we tried to use the
 * consistent item cache.  The downside is that it adds a bit of
 * latency.
 *
 * Once we find candidate orphan items we first check our local omap for
 * a locally cached inode.  Then we ask the server for the open map
 * containing the inode.  Only if we don't see any cached users do we do
 * the expensive work of acquiring locks to try and delete the items.
 */
static void inode_orphan_scan_worker(struct work_struct *work)
{
	struct inode_sb_info *inf = container_of(work, struct inode_sb_info,
						 orphan_scan_dwork.work);
	struct super_block *sb = inf->sb;
	struct scoutfs_open_ino_map omap;
	struct scoutfs_net_roots roots;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key last;
	struct scoutfs_key key;
	u64 group_nr;
	int bit_nr;
	u64 ino;
	int ret;

	scoutfs_inc_counter(sb, orphan_scan);

	init_orphan_key(&last, U64_MAX);
	omap.args.group_nr = cpu_to_le64(U64_MAX);

	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	for (ino = SCOUTFS_ROOT_INO + 1; ino != 0; ino++) {
		if (inf->stopped) {
			ret = 0;
			goto out;
		}

		/* find the next orphan item */
		init_orphan_key(&key, ino);
		ret = scoutfs_btree_next(sb, &roots.fs_root, &key, &iref);
		if (ret < 0) {
			if (ret == -ENOENT)
				break;
			goto out;
		}

		key = *iref.key;
		scoutfs_btree_put_iref(&iref);

		if (scoutfs_key_compare(&key, &last) > 0)
			break;

		scoutfs_inc_counter(sb, orphan_scan_item);
		ino = le64_to_cpu(key.sko_ino);

		/* locally cached inodes will try to delete as they evict */
		if (scoutfs_omap_test(sb, ino)) {
			scoutfs_inc_counter(sb, orphan_scan_cached);
			continue;
		}

		/* get an omap that covers the orphaned ino */
		scoutfs_omap_calc_group_nrs(ino, &group_nr, &bit_nr);

		if (le64_to_cpu(omap.args.group_nr) != group_nr) {
			ret = scoutfs_client_open_ino_map(sb, group_nr, &omap);
			if (ret < 0)
				goto out;
		}

		/* remote cached inodes will also try to delete */
		if (test_bit_le(bit_nr, omap.bits)) {
			scoutfs_inc_counter(sb, orphan_scan_omap_set);
			continue;
		}

		/* seemingly orphaned and unused, get locks and check for sure */
		scoutfs_inc_counter(sb, orphan_scan_attempts);
		ret = try_delete_inode_items(sb, ino);
	}

	ret = 0;

out:
	if (ret < 0)
		scoutfs_inc_counter(sb, orphan_scan_error);

	scoutfs_inode_schedule_orphan_dwork(sb);
}

/*
 * Track an inode that could have dirty pages.  Used to kick off
 * writeback on all dirty pages during transaction commit without tying
 * ourselves in knots trying to call through the high level vfs sync
 * methods.
 *
 * File data block allocations tend to advance through free space so we
 * add the inode to the end of the list to roughly encourage sequential
 * IO.
 *
 * This is called by writers who hold the inode and transaction.  The
 * inode is removed from the list by evict->destroy if it's unlinked
 * during the transaction or by committing the transaction.  Pruning the
 * icache won't try to evict the inode as long as it has dirty buffers.
 */
void scoutfs_inode_queue_writeback(struct inode *inode)
{
	DECLARE_INODE_SB_INFO(inode->i_sb, inf);
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);

	if (list_empty(&si->writeback_entry)) {
		spin_lock(&inf->writeback_lock);
		if (list_empty(&si->writeback_entry))
			list_add_tail(&si->writeback_entry, &inf->writeback_list);
		spin_unlock(&inf->writeback_lock);
	}
}

/*
 * Walk our dirty inodes and either start dirty page writeback or wait
 * for writeback to complete.
 *
 * This is called by transaction committing so other writers are
 * excluded.  We're still very careful to iterate over the tree while it
 * and the inodes could be changing.
 *
 * Because writes are excluded we know that there's no remaining dirty
 * pages once waiting returns successfully.
 *
 * XXX not sure what to do about retrying io errors.
 */
int scoutfs_inode_walk_writeback(struct super_block *sb, bool write)
{
	DECLARE_INODE_SB_INFO(sb, inf);
	struct scoutfs_inode_info *si;
	struct scoutfs_inode_info *tmp;
	struct inode *inode;
	int ret;

	spin_lock(&inf->writeback_lock);

	list_for_each_entry_safe(si, tmp, &inf->writeback_list, writeback_entry) {
		inode = igrab(&si->inode);
		if (!inode)
			continue;

		spin_unlock(&inf->writeback_lock);

		if (write)
			ret = filemap_fdatawrite(inode->i_mapping);
		else
			ret = filemap_fdatawait(inode->i_mapping);
		trace_scoutfs_inode_walk_writeback(sb, scoutfs_ino(inode),
						   write, ret);
		if (ret) {
			scoutfs_inode_queue_iput(inode, 0);
			goto out;
		}

		spin_lock(&inf->writeback_lock);

		/* restore tmp after reacquiring lock */
		if (WARN_ON_ONCE(list_empty(&si->writeback_entry)))
			tmp = list_first_entry(&inf->writeback_list, struct scoutfs_inode_info,
					       writeback_entry);
		else
			tmp = list_next_entry(si, writeback_entry);

		if (!write)
			list_del_init(&si->writeback_entry);

		scoutfs_inode_queue_iput(inode, 0);
	}

	spin_unlock(&inf->writeback_lock);
out:

	return ret;
}

/*
 * Return an error if the inode has the retention flag set and can not
 * be modified.  This mimics the errno returned by the vfs whan an
 * inode's immutable flag is set.  The flag won't be set on older format
 * versions so we don't check the mounted format version here.
 */
int scoutfs_inode_check_retention(struct inode *inode)
{
	return (scoutfs_inode_get_flags(inode) & SCOUTFS_INO_FLAG_RETENTION) ? -EPERM : 0;
}

int scoutfs_inode_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct inode_sb_info *inf;

	inf = kzalloc(sizeof(struct inode_sb_info), GFP_KERNEL);
	if (!inf)
		return -ENOMEM;

	inf->sb = sb;
	spin_lock_init(&inf->writeback_lock);
	INIT_LIST_HEAD(&inf->writeback_list);
	spin_lock_init(&inf->dir_ino_alloc.lock);
	spin_lock_init(&inf->ino_alloc.lock);
	INIT_DELAYED_WORK(&inf->orphan_scan_dwork, inode_orphan_scan_worker);
	INIT_WORK(&inf->iput_work, iput_worker);
	spin_lock_init(&inf->iput_lock);
	INIT_LIST_HEAD(&inf->iput_list);

	/* re-entrant, worker locks with itself and queueing */
	inf->iput_workq = alloc_workqueue("scoutfs_inode_iput", WQ_UNBOUND, 0);
	if (!inf->iput_workq) {
		kfree(inf);
		return -ENOMEM;
	}

	sbi->inode_sb_info = inf;

	return 0;
}

/*
 * Our inode subsystem is setup pretty early but orphan scanning uses
 * many other subsystems like networking and the server.  We only kick
 * it off once everything is ready.
 */
void scoutfs_inode_start(struct super_block *sb)
{
	scoutfs_inode_schedule_orphan_dwork(sb);
}

/*
 * Orphan scanning can instantiate inodes.  We shut it down before
 * calling into the vfs to tear down dentries and inodes during unmount.
 */
void scoutfs_inode_orphan_stop(struct super_block *sb)
{
	DECLARE_INODE_SB_INFO(sb, inf);

	if (inf) {
		inf->stopped = true;
		cancel_delayed_work_sync(&inf->orphan_scan_dwork);
	}
}

void scoutfs_inode_flush_iput(struct super_block *sb)
{
	DECLARE_INODE_SB_INFO(sb, inf);

	if (inf)
		flush_workqueue(inf->iput_workq);
}

void scoutfs_inode_destroy(struct super_block *sb)
{
	struct inode_sb_info *inf = SCOUTFS_SB(sb)->inode_sb_info;

	if (inf) {
		if (inf->iput_workq)
			destroy_workqueue(inf->iput_workq);
		kfree(inf);
	}
}

void scoutfs_inode_exit(void)
{
	if (scoutfs_inode_cachep) {
		rcu_barrier();
		kmem_cache_destroy(scoutfs_inode_cachep);
		scoutfs_inode_cachep = NULL;
	}
}

int scoutfs_inode_init(void)
{
	scoutfs_inode_cachep = kmem_cache_create("scoutfs_inode_info",
					sizeof(struct scoutfs_inode_info), 0,
					SLAB_RECLAIM_ACCOUNT,
					scoutfs_inode_ctor);
	if (!scoutfs_inode_cachep)
		return -ENOMEM;

	return 0;
}
