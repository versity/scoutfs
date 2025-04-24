#ifndef _SCOUTFS_ACL_H_
#define _SCOUTFS_ACL_H_

#ifdef KC_GET_ACL_DENTRY
struct posix_acl *scoutfs_get_acl(KC_VFS_NS_DEF struct dentry *dentry, int type);
int scoutfs_set_acl(KC_VFS_NS_DEF struct dentry *dentry, struct posix_acl *acl, int type);
#else
struct posix_acl *scoutfs_get_acl(struct inode *inode, int type);
int scoutfs_set_acl(struct inode *inode, struct posix_acl *acl, int type);
#endif
struct posix_acl *scoutfs_get_acl_locked(struct inode *inode, int type, struct scoutfs_lock *lock);
int scoutfs_set_acl_locked(struct inode *inode, struct posix_acl *acl, int type,
			   struct scoutfs_lock *lock, struct list_head *ind_locks);
#ifdef KC_XATTR_STRUCT_XATTR_HANDLER
int scoutfs_acl_get_xattr(const struct xattr_handler *, struct dentry *dentry,
			  struct inode *inode, const char *name, void *value,
			  size_t size);
int scoutfs_acl_set_xattr(const struct xattr_handler *,
			  KC_VFS_NS_DEF
			  struct dentry *dentry,
			  struct inode *inode, const char *name, const void *value,
			  size_t size, int flags);
#else
int scoutfs_acl_get_xattr(struct dentry *dentry, const char *name, void *value, size_t size,
			  int type);
int scoutfs_acl_set_xattr(struct dentry *dentry, const char *name, const void *value, size_t size,
			  int flags, int type);
#endif
int scoutfs_acl_chmod_locked(struct inode *inode, struct iattr *attr,
			     struct scoutfs_lock *lock, struct list_head *ind_locks);
int scoutfs_init_acl_locked(struct inode *inode, struct inode *dir,
			    struct scoutfs_lock *lock, struct scoutfs_lock *dir_lock,
			    struct list_head *ind_locks);
#endif
