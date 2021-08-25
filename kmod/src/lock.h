#ifndef _SCOUTFS_LOCK_H_
#define _SCOUTFS_LOCK_H_

#include "key.h"
#include "tseq.h"

#define SCOUTFS_LKF_REFRESH_INODE	0x01 /* update stale inode from item */
#define SCOUTFS_LKF_NONBLOCK		0x02 /* only use already held locks */
#define SCOUTFS_LKF_INTERRUPTIBLE	0x04 /* pending signals return -ERESTARTSYS */
#define SCOUTFS_LKF_INVALID		(~((SCOUTFS_LKF_INTERRUPTIBLE << 1) - 1))

#define SCOUTFS_LOCK_NR_MODES		SCOUTFS_LOCK_INVALID

struct scoutfs_omap_lock;

/*
 * A few fields (start, end, refresh_gen, write_seq, granted_mode)
 * are referenced by code outside lock.c.
 */
struct scoutfs_lock {
	struct super_block *sb;
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct rb_node node;
	struct rb_node range_node;
	u64 refresh_gen;
	u64 write_seq;
	u64 dirty_trans_seq;
	struct list_head lru_head;
	wait_queue_head_t waitq;
	unsigned long request_pending:1,
		      invalidate_pending:1;

	struct list_head inv_head;  /* entry in linfo's list of locks with invalidations */
	struct list_head inv_list;  /* list of lock's invalidation requests */
	struct list_head shrink_head;

	spinlock_t cov_list_lock;
	struct list_head cov_list;

	enum scoutfs_lock_mode mode;
	unsigned int waiters[SCOUTFS_LOCK_NR_MODES];
	unsigned int users[SCOUTFS_LOCK_NR_MODES];

	struct scoutfs_tseq_entry tseq_entry;

	/* the forest tracks which log tree last saw bloom bit updates */
	atomic64_t forest_bloom_nr;

	/* open ino mapping has a valid map for a held write lock */
	spinlock_t omap_spinlock;
	struct scoutfs_omap_lock_data *omap_data;
};

struct scoutfs_lock_coverage {
	spinlock_t cov_lock;
	struct scoutfs_lock *lock;
	struct list_head head;
};

int scoutfs_lock_grant_response(struct super_block *sb,
				struct scoutfs_net_lock *nl);
int scoutfs_lock_invalidate_request(struct super_block *sb, u64 net_id,
				    struct scoutfs_net_lock *nl);
int scoutfs_lock_recover_request(struct super_block *sb, u64 net_id,
				 struct scoutfs_key *key);

int scoutfs_lock_inode(struct super_block *sb, enum scoutfs_lock_mode mode, int flags,
		       struct inode *inode, struct scoutfs_lock **ret_lock);
int scoutfs_lock_ino(struct super_block *sb, enum scoutfs_lock_mode mode, int flags, u64 ino,
		     struct scoutfs_lock **ret_lock);
void scoutfs_lock_get_index_item_range(u8 type, u64 major, u64 ino,
				       struct scoutfs_key *start,
				       struct scoutfs_key *end);
int scoutfs_lock_inode_index(struct super_block *sb, enum scoutfs_lock_mode mode,
			     u8 type, u64 major, u64 ino,
			     struct scoutfs_lock **ret_lock);
int scoutfs_lock_inodes(struct super_block *sb, enum scoutfs_lock_mode mode, int flags,
			struct inode *a, struct scoutfs_lock **a_lock,
			struct inode *b, struct scoutfs_lock **b_lock,
			struct inode *c, struct scoutfs_lock **c_lock,
			struct inode *d, struct scoutfs_lock **D_lock);
int scoutfs_lock_rename(struct super_block *sb, enum scoutfs_lock_mode mode, int flags,
			struct scoutfs_lock **lock);
int scoutfs_lock_orphan(struct super_block *sb, enum scoutfs_lock_mode mode, int flags,
		        u64 ino, struct scoutfs_lock **lock);
void scoutfs_unlock(struct super_block *sb, struct scoutfs_lock *lock,
		    enum scoutfs_lock_mode mode);

void scoutfs_lock_init_coverage(struct scoutfs_lock_coverage *cov);
void scoutfs_lock_add_coverage(struct super_block *sb,
			       struct scoutfs_lock *lock,
			       struct scoutfs_lock_coverage *cov);
bool scoutfs_lock_is_covered(struct super_block *sb,
			     struct scoutfs_lock_coverage *cov);
void scoutfs_lock_del_coverage(struct super_block *sb,
			       struct scoutfs_lock_coverage *cov);
bool scoutfs_lock_protected(struct scoutfs_lock *lock, struct scoutfs_key *key,
			    enum scoutfs_lock_mode mode);

void scoutfs_free_unused_locks(struct super_block *sb);

int scoutfs_lock_setup(struct super_block *sb);
void scoutfs_lock_unmount_begin(struct super_block *sb);
void scoutfs_lock_flush_invalidate(struct super_block *sb);
void scoutfs_lock_shutdown(struct super_block *sb);
void scoutfs_lock_destroy(struct super_block *sb);

#endif
