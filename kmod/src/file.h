#ifndef _SCOUTFS_FILE_H_
#define _SCOUTFS_FILE_H_

#ifdef KC_LINUX_HAVE_FOP_AIO_READ
ssize_t scoutfs_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos);
ssize_t scoutfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos);
#else
ssize_t scoutfs_file_read_iter(struct kiocb *, struct iov_iter *);
ssize_t scoutfs_file_write_iter(struct kiocb *, struct iov_iter *);
#endif
int scoutfs_permission(struct inode *inode, int mask);
loff_t scoutfs_file_llseek(struct file *file, loff_t offset, int whence);

#endif	/* _SCOUTFS_FILE_H_ */
