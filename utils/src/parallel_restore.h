#ifndef _SCOUTFS_PARALLEL_RESTORE_H_
#define _SCOUTFS_PARALLEL_RESTORE_H_

#include <errno.h>

struct scoutfs_parallel_restore_progress {
	struct scoutfs_btree_root fs_items;
	struct scoutfs_btree_root root_items;
	struct scoutfs_srch_file sfl;
	struct scoutfs_block_ref bloom_ref;
	__le64 inode_count;
	__le64 max_ino;
};

struct scoutfs_parallel_restore_slice {
	__le64 fsid;
	__le64 meta_start;
	__le64 meta_len;
};

struct scoutfs_parallel_restore_entry {
	u64 dir_ino;
	u64 pos;
	u64 ino;
	mode_t mode;
	char *name;
	unsigned int name_len;
};

struct scoutfs_parallel_restore_xattr {
	u64 ino;
	u64 pos;
	char *name;
	unsigned int name_len;
	void *value;
	unsigned int value_len;
};

struct scoutfs_parallel_restore_inode {
	/* all inodes */
	u64 ino;
	u64 meta_seq;
	u64 data_seq;
	u64 nr_xattrs;
	u32 uid;
	u32 gid;
	u32 mode;
	u32 rdev;
	u32 flags;
	u8 pad[4];
	struct timespec atime;
	struct timespec ctime;
	struct timespec mtime;
	struct timespec crtime;
	u64 proj;

	/* regular files */
	u64 data_version;
	u64 size;
	bool offline;

	/* only used for directories */
	u64 nr_subdirs;
	u64 total_entry_name_bytes;

	/* only used for symlnks */
	char *target;
	unsigned int target_len; /* not including null terminator */
};

struct scoutfs_parallel_restore_quota_rule {
	u64 limit;
	u8  prio;
	u8  op;
	u8  rule_flags;
	struct quota_rule_name {
		u64 val;
		u8  source;
		u8  flags;
	} names [3];
	char *value;
	unsigned int value_len;
};

typedef __typeof__(EINVAL) spr_err_t;

struct scoutfs_parallel_restore_writer;

spr_err_t scoutfs_parallel_restore_create_writer(struct scoutfs_parallel_restore_writer **wrip);
void scoutfs_parallel_restore_destroy_writer(struct scoutfs_parallel_restore_writer **wrip);

spr_err_t scoutfs_parallel_restore_init_slices(struct scoutfs_parallel_restore_writer *wri,
					       struct scoutfs_parallel_restore_slice *slices,
					       int nr);
spr_err_t scoutfs_parallel_restore_add_slice(struct scoutfs_parallel_restore_writer *wri,
					    struct scoutfs_parallel_restore_slice *slice);
spr_err_t scoutfs_parallel_restore_get_slice(struct scoutfs_parallel_restore_writer *wri,
					    struct scoutfs_parallel_restore_slice *slice);

spr_err_t scoutfs_parallel_restore_add_inode(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_inode *inode);
spr_err_t scoutfs_parallel_restore_add_entry(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_entry *entry);
spr_err_t scoutfs_parallel_restore_add_xattr(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_xattr *xattr);

spr_err_t scoutfs_parallel_restore_get_progress(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_parallel_restore_progress *prog);
spr_err_t scoutfs_parallel_restore_add_progress(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_parallel_restore_progress *prog);

spr_err_t scoutfs_parallel_restore_add_quota_rule(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_parallel_restore_quota_rule *rule);

spr_err_t scoutfs_parallel_restore_write_buf(struct scoutfs_parallel_restore_writer *wri,
					     void *buf, size_t len, off_t *off_ret,
					     size_t *count_ret);

spr_err_t scoutfs_parallel_restore_import_super(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_super_block *super, int fd);
spr_err_t scoutfs_parallel_restore_export_super(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_super_block *super);


#endif
