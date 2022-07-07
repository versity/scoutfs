#ifndef _SCOUTFS_XATTR_H_
#define _SCOUTFS_XATTR_H_

ssize_t scoutfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
			 size_t size);
int scoutfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags);
int scoutfs_removexattr(struct dentry *dentry, const char *name);
ssize_t scoutfs_listxattr(struct dentry *dentry, char *buffer, size_t size);
ssize_t scoutfs_list_xattrs(struct inode *inode, char *buffer,
			    size_t size, __u32 *hash_pos, __u64 *id_pos,
			    bool e_range, bool show_hidden);

int scoutfs_xattr_drop(struct super_block *sb, u64 ino,
		       struct scoutfs_lock *lock);

struct scoutfs_xattr_prefix_tags {
	unsigned long hide:1,
		      srch:1,
		      totl:1,
		      worm:1;
};

int scoutfs_xattr_parse_tags(struct super_block *sb, const char *name,
			     unsigned int name_len, struct scoutfs_xattr_prefix_tags *tgs);

void scoutfs_xattr_init_totl_key(struct scoutfs_key *key, u64 *name);
int scoutfs_xattr_combine_totl(void *dst, int dst_len, void *src, int src_len);

#endif
