#ifndef _SCOUTFS_XATTR_H_
#define _SCOUTFS_XATTR_H_

struct scoutfs_xattr_prefix_tags {
	unsigned long hide:1,
		      indx:1,
		      srch:1,
		      totl:1;
};

extern const struct xattr_handler *scoutfs_xattr_handlers[];

u32 scoutfs_xattr_name_hash(const char *name, unsigned int name_len);
void scoutfs_xattr_init_key(struct scoutfs_key *key, u64 ino, u32 name_hash, u64 id);

int scoutfs_xattr_get_locked(struct inode *inode, const char *name, void *buffer, size_t size,
			     struct scoutfs_lock *lck);
int scoutfs_xattr_set_locked(struct inode *inode, const char *name, size_t name_len,
			     const void *value, size_t size, int flags,
			     const struct scoutfs_xattr_prefix_tags *tgs,
			     struct scoutfs_lock *lck, struct scoutfs_lock *totl_lock,
			     struct list_head *ind_locks);

ssize_t scoutfs_listxattr(struct dentry *dentry, char *buffer, size_t size);
ssize_t scoutfs_list_xattrs(struct inode *inode, char *buffer,
			    size_t size, __u32 *hash_pos, __u64 *id_pos,
			    bool e_range, bool show_hidden);
int scoutfs_xattr_drop(struct super_block *sb, u64 ino,
		       struct scoutfs_lock *lock);

int scoutfs_xattr_parse_tags(const char *name, unsigned int name_len,
			     struct scoutfs_xattr_prefix_tags *tgs);

void scoutfs_xattr_init_totl_key(struct scoutfs_key *key, u64 *name);
int scoutfs_xattr_combine_totl(void *dst, int dst_len, void *src, int src_len);

void scoutfs_xattr_indx_get_range(struct scoutfs_key *start, struct scoutfs_key *end);
void scoutfs_xattr_init_indx_key(struct scoutfs_key *key, u8 major, u64 minor, u64 ino, u64 xid);
void scoutfs_xattr_get_indx_key(struct scoutfs_key *key, u8 *major, u64 *minor, u64 *ino, u64 *xid);
void scoutfs_xattr_set_indx_key_xid(struct scoutfs_key *key, u64 xid);

#endif
