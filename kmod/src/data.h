#ifndef _SCOUTFS_DATA_H_
#define _SCOUTFS_DATA_H_

struct scoutfs_lock;
struct scoutfs_ioctl_data_waiting_entry;

struct scoutfs_data_wait_root {
	spinlock_t lock;
	struct rb_root root;
};

#define DECLARE_DATA_WAIT_ROOT(sb, nm) \
	struct scoutfs_data_wait_root *nm = &SCOUTFS_SB(sb)->data_wait_root

struct scoutfs_data_waitq {
	atomic64_t changed;
	wait_queue_head_t waitq;
};

#define DECLARE_DATA_WAITQ(in, nm) \
	struct scoutfs_data_waitq *nm = &SCOUTFS_I(in)->data_waitq

/*
 * Tasks can wait for data extents.
 */
struct scoutfs_data_wait {
	struct rb_node node;
	u64 chg;
	u64 ino;
	u64 iblock;
	long err;
	u8 op;
};

#define DECLARE_DATA_WAIT(nm)						\
	struct scoutfs_data_wait nm = {					\
		.node.__rb_parent_color = (unsigned long)(&nm.node),	\
		.err = 0,						\
	}

extern const struct address_space_operations scoutfs_file_aops;
extern const struct file_operations scoutfs_file_fops;
struct scoutfs_alloc;
struct scoutfs_block_writer;

int scoutfs_get_block_write(struct inode *inode, sector_t iblock, struct buffer_head *bh,
			    int create);

int scoutfs_data_truncate_items(struct super_block *sb, struct inode *inode,
				u64 ino, u64 iblock, u64 last, unsigned txn_limit,
				bool offline, struct scoutfs_lock *lock);
int scoutfs_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
			u64 start, u64 len);
long scoutfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len);
int scoutfs_data_init_offline_extent(struct inode *inode, u64 size,
				     struct scoutfs_lock *lock);
int scoutfs_data_move_blocks(struct inode *from, u64 from_off,
			     u64 byte_len, struct inode *to, u64 to_off, bool to_stage,
			     u64 data_version);

int scoutfs_data_wait_check(struct inode *inode, loff_t pos, loff_t len,
			    u8 sef, u8 op, struct scoutfs_data_wait *ow,
			    struct scoutfs_lock *lock);
int scoutfs_data_wait_check_iov(struct inode *inode, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos, u8 sef,
				u8 op, struct scoutfs_data_wait *ow,
				struct scoutfs_lock *lock);
int scoutfs_data_wait_check_iter(struct inode *inode, loff_t pos, struct iov_iter *iter,
				 u8 sef, u8 op, struct scoutfs_data_wait *ow,
				 struct scoutfs_lock *lock);
bool scoutfs_data_wait_found(struct scoutfs_data_wait *ow);
int scoutfs_data_wait(struct inode *inode,
			      struct scoutfs_data_wait *ow);
void scoutfs_data_wait_changed(struct inode *inode);
long scoutfs_data_wait_err(struct inode *inode, u64 sblock, u64 eblock, u64 op,
			   long err);
int scoutfs_data_waiting(struct super_block *sb, u64 ino, u64 iblock,
			 struct scoutfs_ioctl_data_waiting_entry *dwe,
			 unsigned int nr);

void scoutfs_data_init_btrees(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_log_trees *lt);
void scoutfs_data_get_btrees(struct super_block *sb,
			     struct scoutfs_log_trees *lt);
int scoutfs_data_prepare_commit(struct super_block *sb);
bool scoutfs_data_alloc_should_refill(struct super_block *sb, u64 blocks);

int scoutfs_data_setup(struct super_block *sb);
void scoutfs_data_destroy(struct super_block *sb);

#endif
