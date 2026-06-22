#ifndef _SCOUTFS_FILE_H_
#define _SCOUTFS_FILE_H_

ssize_t scoutfs_file_read_iter(struct kiocb *, struct iov_iter *);
ssize_t scoutfs_file_write_iter(struct kiocb *, struct iov_iter *);
int scoutfs_permission(KC_VFS_NS_DEF
		       struct inode *inode, int mask);
loff_t scoutfs_file_llseek(struct file *file, loff_t offset, int whence);

#endif	/* _SCOUTFS_FILE_H_ */
