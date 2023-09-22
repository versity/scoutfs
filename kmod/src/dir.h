#ifndef _SCOUTFS_DIR_H_
#define _SCOUTFS_DIR_H_

#include "format.h"
#include "lock.h"

extern const struct file_operations scoutfs_dir_fops;
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
extern const struct inode_operations_wrapper scoutfs_dir_iops;
#else
extern const struct inode_operations scoutfs_dir_iops;
#endif
extern const struct inode_operations scoutfs_symlink_iops;

extern const struct dentry_operations scoutfs_dentry_ops;

struct scoutfs_link_backref_entry {
	struct list_head head;
	u64 dir_ino;
	u64 dir_pos;
	u16 name_len;
	u8 d_type;
	bool last;
	struct scoutfs_dirent dent;
	/* the full name is allocated and stored in dent.name[] */
};

int scoutfs_dir_get_backref_path(struct super_block *sb, u64 ino, u64 dir_ino,
				 u64 dir_pos, struct list_head *list);
void scoutfs_dir_free_backref_path(struct super_block *sb,
				   struct list_head *list);

int scoutfs_dir_add_next_linkrefs(struct super_block *sb, u64 ino, u64 dir_ino, u64 dir_pos,
				  int count, struct list_head *list);

int scoutfs_symlink_drop(struct super_block *sb, u64 ino,
			 struct scoutfs_lock *lock, u64 i_size);

#endif
