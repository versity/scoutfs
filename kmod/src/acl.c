/*
 * Copyright (C) 2022 Versity Software, Inc.  All rights reserved.
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
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

#include "format.h"
#include "super.h"
#include "scoutfs_trace.h"
#include "xattr.h"
#include "acl.h"
#include "inode.h"
#include "trans.h"

/*
 * POSIX draft ACLs are stored as full xattr items with the entries
 * encoded as the kernel's posix_acl_xattr_{header,entry} value structs.
 *
 * They're accessed and modified via user facing synthetic xattrs, iops
 * calls from the kernel, during inode mode changes, and during inode
 * creation.
 *
 * ACL access devolves into xattr access which is relatively expensive
 * so we maintain the cached native form in the vfs inode.  We drop the
 * cache in lock invalidation which means that cached acl access must
 * always be performed under cluster locking.
 */

static int acl_xattr_name_len(int type, char **name, size_t *name_len)
{
	int ret = 0;

	switch (type) {
	case ACL_TYPE_ACCESS:
		*name = XATTR_NAME_POSIX_ACL_ACCESS;
		if (name_len)
			*name_len = sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1;
		break;
	case ACL_TYPE_DEFAULT:
		*name = XATTR_NAME_POSIX_ACL_DEFAULT;
		if (name_len)
			*name_len = sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

struct posix_acl *scoutfs_get_acl_locked(struct inode *inode, int type, struct scoutfs_lock *lock)
{
	struct posix_acl *acl;
	char *value = NULL;
	char *name;
	int ret;

	if (!IS_POSIXACL(inode))
		return NULL;

	acl = get_cached_acl(inode, type);
	if (acl != ACL_NOT_CACHED)
		return acl;

	ret = acl_xattr_name_len(type, &name, NULL);
	if (ret < 0)
		return ERR_PTR(ret);

	ret = scoutfs_xattr_get_locked(inode, name, NULL, 0, lock);
	if (ret > 0) {
		value = kzalloc(ret, GFP_NOFS);
		if (!value)
			ret = -ENOMEM;
		else
			ret = scoutfs_xattr_get_locked(inode, name, value, ret, lock);
	}
	if (ret > 0) {
		acl = posix_acl_from_xattr(&init_user_ns, value, ret);
	} else if (ret == -ENODATA || ret == 0) {
		acl = NULL;
	} else {
		acl = ERR_PTR(ret);
	}

	/* can set null negative cache */
	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	kfree(value);

	return acl;
}

struct posix_acl *scoutfs_get_acl(struct inode *inode, int type)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	struct posix_acl *acl;
	int ret;

	if (!IS_POSIXACL(inode))
		return NULL;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &lock);
	if (ret < 0) {
		acl = ERR_PTR(ret);
	} else {
		acl = scoutfs_get_acl_locked(inode, type, lock);
		scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	}

	return acl;
}

/*
 * The caller has acquired the locks and dirtied the inode, they'll
 * update the inode item if we return 0.
 */
int scoutfs_set_acl_locked(struct inode *inode, struct posix_acl *acl, int type,
			   struct scoutfs_lock *lock, struct list_head *ind_locks)
{
	static const struct scoutfs_xattr_prefix_tags tgs = {0,}; /* never scoutfs. prefix */
	bool set_mode = false;
	char *value = NULL;
	umode_t new_mode;
	size_t name_len;
	char *name;
	int size = 0;
	int ret;

	ret = acl_xattr_name_len(type, &name, &name_len);
	if (ret < 0)
		return ret;

	switch (type) {
	case ACL_TYPE_ACCESS:
		if (acl) {
			ret = posix_acl_update_mode(inode, &new_mode, &acl);
			if (ret < 0)
				goto out;
			set_mode = true;
		}
		break;
	case ACL_TYPE_DEFAULT:
		if (!S_ISDIR(inode->i_mode)) {
			ret = acl ? -EINVAL : 0;
			goto out;
		}
		break;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_NOFS);
		if (!value) {
			ret = -ENOMEM;
			goto out;
		}

		ret = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (ret < 0)
			goto out;
	}

	ret = scoutfs_xattr_set_locked(inode, name, name_len, value, size, 0, &tgs,
				       lock, NULL, ind_locks);
	if (ret == 0 && set_mode) {
		inode->i_mode = new_mode;
		if (!value) {
			/* can be setting an acl that only affects mode, didn't need xattr */
			inode_inc_iversion(inode);
			inode->i_ctime = current_time(inode);
		}
	}

out:
	if (!ret)
		set_cached_acl(inode, type, acl);

	kfree(value);

	return ret;
}

int scoutfs_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *lock = NULL;
	LIST_HEAD(ind_locks);
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE, SCOUTFS_LKF_REFRESH_INODE, inode, &lock) ?:
	      scoutfs_inode_index_lock_hold(inode, &ind_locks, false, true);
	if (ret == 0) {
		ret = scoutfs_dirty_inode_item(inode, lock) ?:
		      scoutfs_set_acl_locked(inode, acl, type, lock, &ind_locks);
		if (ret == 0)
			scoutfs_update_inode_item(inode, lock, &ind_locks);

		scoutfs_release_trans(sb);
		scoutfs_inode_index_unlock(sb, &ind_locks);
	}

	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
	return ret;
}
#ifdef KC_XATTR_STRUCT_XATTR_HANDLER
int scoutfs_acl_get_xattr(const struct xattr_handler *handler, struct dentry *dentry,
			  struct inode *inode, const char *name, void *value,
			  size_t size)
{
	int type = handler->flags;
#else
int scoutfs_acl_get_xattr(struct dentry *dentry, const char *name, void *value, size_t size,
			  int type)
{
#endif
	struct posix_acl *acl;
	int ret = 0;

	if (!IS_POSIXACL(dentry->d_inode))
		return -EOPNOTSUPP;

	acl = scoutfs_get_acl(dentry->d_inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;

	ret = posix_acl_to_xattr(&init_user_ns, acl, value, size);
	posix_acl_release(acl);

	return ret;
}

#ifdef KC_XATTR_STRUCT_XATTR_HANDLER
int scoutfs_acl_set_xattr(const struct xattr_handler *handler, struct dentry *dentry,
			  struct inode *inode, const char *name, const void *value,
			  size_t size, int flags)
{
	int type = handler->flags;
#else
int scoutfs_acl_set_xattr(struct dentry *dentry, const char *name, const void *value, size_t size,
			  int flags, int type)
{
#endif
	struct posix_acl *acl = NULL;
	int ret;

	if (!inode_owner_or_capable(dentry->d_inode))
		return -EPERM;

	if (!IS_POSIXACL(dentry->d_inode))
		return -EOPNOTSUPP;

	if (value) {
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);

		if (acl) {
			ret = kc_posix_acl_valid(&init_user_ns, acl);
			if (ret)
				goto out;
		}
	}

	ret = scoutfs_set_acl(dentry->d_inode, acl, type);
out:
	posix_acl_release(acl);

	return ret;
}

/*
 * Apply the parent's default acl to new inodes access acl and inherit
 * it as the default for new directories.  The caller holds locks and a
 * transaction.
 */
int scoutfs_init_acl_locked(struct inode *inode, struct inode *dir,
			    struct scoutfs_lock *lock, struct scoutfs_lock *dir_lock,
			    struct list_head *ind_locks)
{
	struct posix_acl *acl = NULL;
	int ret = 0;

	if (!S_ISLNK(inode->i_mode)) {
		if (IS_POSIXACL(dir)) {
			acl = scoutfs_get_acl_locked(dir, ACL_TYPE_DEFAULT, dir_lock);
			if (IS_ERR(acl))
				return PTR_ERR(acl);
		}

		if (!acl)
			inode->i_mode &= ~current_umask();
	}

	if (IS_POSIXACL(dir) && acl) {
		if (S_ISDIR(inode->i_mode)) {
			ret = scoutfs_set_acl_locked(inode, acl, ACL_TYPE_DEFAULT,
						     lock, ind_locks);
			if (ret)
				goto out;
		}
		ret = __posix_acl_create(&acl, GFP_NOFS, &inode->i_mode);
		if (ret < 0)
			return ret;
		if (ret > 0)
			ret = scoutfs_set_acl_locked(inode, acl, ACL_TYPE_ACCESS,
						     lock, ind_locks);
	} else {
		cache_no_acl(inode);
	}
out:
	posix_acl_release(acl);
	return ret;
}

/*
 * Update the access ACL based on a newly set mode.  If we return an
 * error then the xattr wasn't changed.
 *
 * Annoyingly, setattr_copy has logic that transforms the final set mode
 * that we want to use to update the acl.   But we don't want to modify
 * the other inode fields while discovering the resulting mode.  We're
 * relying on acl_chmod not caring about the transformation (currently
 * just clears sgid).  It would be better if we could get the resulting
 * mode to give to acl_chmod without modifying the other inode fields.
 *
 * The caller has the inode mutex, a cluster lock, transaction, and will
 * update the inode item if we return success.
 */
int scoutfs_acl_chmod_locked(struct inode *inode, struct iattr *attr,
			     struct scoutfs_lock *lock, struct list_head *ind_locks)
{
	struct posix_acl *acl;
	int ret = 0;

	if (!IS_POSIXACL(inode) || !(attr->ia_valid & ATTR_MODE))
		return 0;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;

	acl = scoutfs_get_acl_locked(inode, ACL_TYPE_ACCESS, lock);
	if (IS_ERR_OR_NULL(acl))
		return PTR_ERR(acl);

	ret = __posix_acl_chmod(&acl, GFP_KERNEL, attr->ia_mode);
	if (ret)
		return ret;

	ret = scoutfs_set_acl_locked(inode, acl, ACL_TYPE_ACCESS, lock, ind_locks);
	posix_acl_release(acl);
	return ret;
}
