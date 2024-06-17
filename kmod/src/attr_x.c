/*
 * Copyright (C) 2024 Versity Software, Inc.  All rights reserved.
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

#include "format.h"
#include "super.h"
#include "inode.h"
#include "ioctl.h"
#include "lock.h"
#include "trans.h"
#include "attr_x.h"

static int validate_attr_x_input(struct super_block *sb, struct scoutfs_ioctl_inode_attr_x *iax)
{
	int ret;

	if ((iax->x_mask & SCOUTFS_IOC_IAX__UNKNOWN) ||
	    (iax->x_flags & SCOUTFS_IOC_IAX_F__UNKNOWN))
		return -EINVAL;

	if ((iax->x_mask & SCOUTFS_IOC_IAX_RETENTION) &&
	    (ret = scoutfs_fmt_vers_unsupported(sb, SCOUTFS_FORMAT_VERSION_FEAT_RETENTION)))
		    return ret;

	return 0;
}

/*
 * If the mask indicates interest in the given attr then set the field
 * to the caller's value and return the new size if it didn't already
 * include the attr field.
 */
#define fill_attr(size, iax, bit, field, val)							\
({												\
	__typeof__(iax) _iax = (iax);								\
	__typeof__(size) _size = (size);							\
												\
	if (_iax->x_mask & (bit)) {								\
		_iax->field = (val);								\
		_size = max(_size, offsetof(struct scoutfs_ioctl_inode_attr_x, field) +		\
				   sizeof_field(struct scoutfs_ioctl_inode_attr_x, field));	\
	}											\
												\
	_size;											\
})

/*
 * Returns -errno on error, or >= number of bytes filled by the
 * response.  0 can be returned if no attributes are requested in the
 * input x_mask.
 */
int scoutfs_get_attr_x(struct inode *inode, struct scoutfs_ioctl_inode_attr_x *iax)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct scoutfs_lock *lock = NULL;
	size_t size = 0;
	u64 offline;
	u64 online;
	u64 bits;
	int ret;

	if (iax->x_mask == 0) {
		ret = 0;
		goto out;
	}

	ret = validate_attr_x_input(sb, iax);
	if (ret < 0)
		goto out;

	inode_lock(inode);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto unlock;

	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_META_SEQ,
			 meta_seq, scoutfs_inode_meta_seq(inode));
	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_DATA_SEQ,
			 data_seq, scoutfs_inode_data_seq(inode));
	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_DATA_VERSION,
			 data_version, scoutfs_inode_data_version(inode));
	if (iax->x_mask & (SCOUTFS_IOC_IAX_ONLINE_BLOCKS | SCOUTFS_IOC_IAX_OFFLINE_BLOCKS)) {
		scoutfs_inode_get_onoff(inode, &online, &offline);
		size = fill_attr(size, iax, SCOUTFS_IOC_IAX_ONLINE_BLOCKS,
				 online_blocks, online);
		size = fill_attr(size, iax, SCOUTFS_IOC_IAX_OFFLINE_BLOCKS,
				 offline_blocks, offline);
	}
	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_CTIME, ctime_sec, inode->i_ctime.tv_sec);
	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_CTIME, ctime_nsec, inode->i_ctime.tv_nsec);
	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_CRTIME, crtime_sec, si->crtime.tv_sec);
	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_CRTIME, crtime_nsec, si->crtime.tv_nsec);
	size = fill_attr(size, iax, SCOUTFS_IOC_IAX_SIZE, size, i_size_read(inode));
	if (iax->x_mask & SCOUTFS_IOC_IAX__BITS) {
		bits = 0;
		if ((iax->x_mask & SCOUTFS_IOC_IAX_RETENTION) &&
		    (scoutfs_inode_get_flags(inode) & SCOUTFS_INO_FLAG_RETENTION))
			bits |= SCOUTFS_IOC_IAX_B_RETENTION;
		size = fill_attr(size, iax, SCOUTFS_IOC_IAX__BITS, bits, bits);
	}

	ret = size;
unlock:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	inode_unlock(inode);
out:
	return ret;
}

static bool valid_attr_changes(struct inode *inode, struct scoutfs_ioctl_inode_attr_x *iax)
{
	/* provided data_version must be non-zero */
	if ((iax->x_mask & SCOUTFS_IOC_IAX_DATA_VERSION) && (iax->data_version == 0))
		return false;

	/* can only set size or data version in new regular files */
	if (((iax->x_mask & SCOUTFS_IOC_IAX_SIZE) ||
	     (iax->x_mask & SCOUTFS_IOC_IAX_DATA_VERSION)) &&
	    (!S_ISREG(inode->i_mode) || scoutfs_inode_data_version(inode) != 0))
		return false;

	/* must provide non-zero data_version with non-zero size */
	if (((iax->x_mask & SCOUTFS_IOC_IAX_SIZE) && (iax->size > 0)) &&
	    (!(iax->x_mask & SCOUTFS_IOC_IAX_DATA_VERSION) || (iax->data_version == 0)))
		return false;

	/* must provide non-zero size when setting offline extents to that size */
	if ((iax->x_flags & SCOUTFS_IOC_IAX_F_SIZE_OFFLINE) &&
	    (!(iax->x_mask & SCOUTFS_IOC_IAX_SIZE) || (iax->size == 0)))
		return false;

	/* the retention bit only applies to regular files */
	if ((iax->x_mask & SCOUTFS_IOC_IAX_RETENTION) && !S_ISREG(inode->i_mode))
		return false;

	return true;
}

int scoutfs_set_attr_x(struct inode *inode, struct scoutfs_ioctl_inode_attr_x *iax)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct scoutfs_lock *lock = NULL;
	LIST_HEAD(ind_locks);
	bool set_data_seq;
	int ret;

	/* initially all setting is root only, could loosen with finer grained checks */
	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	if (iax->x_mask == 0) {
		ret = 0;
		goto out;
	}

	ret = validate_attr_x_input(sb, iax);
	if (ret < 0)
		goto out;

	inode_lock(inode);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE, SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret)
		goto unlock;

	/* check for errors before making any changes */
	if (!valid_attr_changes(inode, iax)) {
		ret = -EINVAL;
		goto unlock;
	}

	/* retention prevents modification unless also clearing retention */
	ret = scoutfs_inode_check_retention(inode);
	if (ret < 0 && !((iax->x_mask & SCOUTFS_IOC_IAX_RETENTION) &&
			 !(iax->bits & SCOUTFS_IOC_IAX_B_RETENTION)))
		goto unlock;

	/* setting only so we don't see 0 data seq with nonzero data_version */
	if ((iax->x_mask & SCOUTFS_IOC_IAX_DATA_VERSION) && (iax->data_version > 0))
		set_data_seq = true;
	else
		set_data_seq = false;

	ret = scoutfs_inode_index_lock_hold(inode, &ind_locks, set_data_seq, true);
	if (ret)
		goto unlock;

	ret = scoutfs_dirty_inode_item(inode, lock);
	if (ret < 0)
		goto release;

	/* creating offline extent first, it might fail */
	if (iax->x_flags & SCOUTFS_IOC_IAX_F_SIZE_OFFLINE) {
		ret = scoutfs_data_init_offline_extent(inode, iax->size, lock);
		if (ret)
			goto release;
	}

	/* make all changes once they're all checked and will succeed */
	if (iax->x_mask & SCOUTFS_IOC_IAX_DATA_VERSION)
		scoutfs_inode_set_data_version(inode, iax->data_version);
	if (iax->x_mask & SCOUTFS_IOC_IAX_SIZE)
		i_size_write(inode, iax->size);
	if (iax->x_mask & SCOUTFS_IOC_IAX_CTIME) {
		inode->i_ctime.tv_sec = iax->ctime_sec;
		inode->i_ctime.tv_nsec = iax->ctime_nsec;
	}
	if (iax->x_mask & SCOUTFS_IOC_IAX_CRTIME) {
		si->crtime.tv_sec = iax->crtime_sec;
		si->crtime.tv_nsec = iax->crtime_nsec;
	}
	if (iax->x_mask & SCOUTFS_IOC_IAX_RETENTION) {
		scoutfs_inode_set_flags(inode, ~SCOUTFS_INO_FLAG_RETENTION,
					(iax->bits & SCOUTFS_IOC_IAX_B_RETENTION) ?
					SCOUTFS_INO_FLAG_RETENTION : 0);
	}

	scoutfs_update_inode_item(inode, lock, &ind_locks);
	ret = 0;
release:
	scoutfs_release_trans(sb);
unlock:
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	inode_unlock(inode);
out:
	return ret;
}
