#ifndef _SCOUTFS_FILE_H_
#define _SCOUTFS_FILE_H_

ssize_t scoutfs_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos);
ssize_t scoutfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos);
int scoutfs_permission(struct inode *inode, int mask);
loff_t scoutfs_file_llseek(struct file *file, loff_t offset, int whence);
int scoutfs_open(struct inode *inode, struct file *file);
int scoutfs_release(struct inode *inode, struct file *file);

#endif	/* _SCOUTFS_FILE_H_ */
