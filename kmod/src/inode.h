#ifndef _SCOUTFS_INODE_H_
#define _SCOUTFS_INODE_H_

#include "key.h"
#include "lock.h"
#include "per_task.h"
#include "format.h"
#include "data.h"

struct scoutfs_lock;

#define SCOUTFS_INODE_NR_INDICES 2

struct scoutfs_inode_info {
	/* read or initialized for each inode instance */
	u64 ino;
	u64 next_readdir_pos;
	u64 next_xattr_id;
	u64 meta_seq;
	u64 data_seq;
	u64 data_version;
	u64 online_blocks;
	u64 offline_blocks;
	u32 flags;
	struct timespec crtime;

	/*
	 * Protects per-inode extent items, most particularly readers
	 * who want to serialize writers without holding i_mutex. (only
	 * used in data.c, it's the only place that understands file
	 * extent items)
	 */
	struct rw_semaphore extent_sem;

	/*
	 * The in-memory item info caches the current index item values
	 * so that we can decide to update them with comparisons instead
	 * of by maintaining state that tracks the inode differing from
	 * the item.  The "item_" prefix is a bit clumsy :/.
	 */
	struct mutex item_mutex;
	bool have_item;
	u64 item_majors[SCOUTFS_INODE_NR_INDICES];
	u32 item_minors[SCOUTFS_INODE_NR_INDICES];

	/* updated at on each new lock acquisition */
	atomic64_t last_refreshed;

	/* initialized once for slab object */
	seqcount_t seqcount;
	bool staging;			/* holder of i_mutex is staging */
	struct scoutfs_per_task pt_data_lock;
	struct scoutfs_data_waitq data_waitq;
	struct rw_semaphore xattr_rwsem;
	struct list_head writeback_entry;

	struct scoutfs_lock_coverage ino_lock_cov;

	/* drop if i_count hits 0, allows drop while invalidate holds coverage */
	bool drop_invalidated;
	struct llist_node iput_llnode;
	atomic_t iput_count;

	struct inode inode;
};

struct scoutfs_inode_payload_wrapper {
	struct scoutfs_inode sinode;
	u64 overflow_detection;
};

static inline struct scoutfs_inode_info *SCOUTFS_I(struct inode *inode)
{
	return container_of(inode, struct scoutfs_inode_info, inode);
}

static inline u64 scoutfs_ino(struct inode *inode)
{
	return SCOUTFS_I(inode)->ino;
}

struct inode *scoutfs_alloc_inode(struct super_block *sb);
void scoutfs_destroy_inode(struct inode *inode);
int scoutfs_drop_inode(struct inode *inode);
void scoutfs_evict_inode(struct inode *inode);
void scoutfs_inode_queue_iput(struct inode *inode);

#define SCOUTFS_IGF_LINKED (1 << 0) /* enoent if nlink == 0 */
struct inode *scoutfs_iget(struct super_block *sb, u64 ino, int lkf, int igf);
struct inode *scoutfs_ilookup(struct super_block *sb, u64 ino);

void scoutfs_inode_init_key(struct scoutfs_key *key, u64 ino);
void scoutfs_inode_init_index_key(struct scoutfs_key *key, u8 type, u64 major,
				  u32 minor, u64 ino);
int scoutfs_inode_index_start(struct super_block *sb, u64 *seq);
int scoutfs_inode_index_prepare(struct super_block *sb, struct list_head *list,
			        struct inode *inode, bool set_data_seq);
int scoutfs_inode_index_prepare_ino(struct super_block *sb,
				    struct list_head *list, u64 ino,
				    umode_t mode);
int scoutfs_inode_index_try_lock_hold(struct super_block *sb,
				      struct list_head *list, u64 seq, bool allocing);
int scoutfs_inode_index_lock_hold(struct inode *inode, struct list_head *list,
				  bool set_data_seq, bool allocing);
void scoutfs_inode_index_unlock(struct super_block *sb, struct list_head *list);

int scoutfs_dirty_inode_item(struct inode *inode, struct scoutfs_lock *lock);
void scoutfs_update_inode_item(struct inode *inode, struct scoutfs_lock *lock,
			       struct list_head *ind_locks);

int scoutfs_alloc_ino(struct super_block *sb, bool is_dir, u64 *ino_ret);
struct inode *scoutfs_new_inode(struct super_block *sb, struct inode *dir,
				umode_t mode, dev_t rdev, u64 ino,
				struct scoutfs_lock *lock);

void scoutfs_inode_set_meta_seq(struct inode *inode);
void scoutfs_inode_set_data_seq(struct inode *inode);
void scoutfs_inode_inc_data_version(struct inode *inode);
void scoutfs_inode_set_data_version(struct inode *inode, u64 data_version);
void scoutfs_inode_add_onoff(struct inode *inode, s64 on, s64 off);
u64 scoutfs_inode_meta_seq(struct inode *inode);
u64 scoutfs_inode_data_seq(struct inode *inode);
u64 scoutfs_inode_data_version(struct inode *inode);
void scoutfs_inode_get_onoff(struct inode *inode, s64 *on, s64 *off);
int scoutfs_complete_truncate(struct inode *inode, struct scoutfs_lock *lock);

int scoutfs_inode_refresh(struct inode *inode, struct scoutfs_lock *lock);
int scoutfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		    struct kstat *stat);
int scoutfs_setattr(struct dentry *dentry, struct iattr *attr);

int scoutfs_inode_orphan_create(struct super_block *sb, u64 ino, struct scoutfs_lock *lock);
int scoutfs_inode_orphan_delete(struct super_block *sb, u64 ino, struct scoutfs_lock *lock);

void scoutfs_inode_queue_writeback(struct inode *inode);
int scoutfs_inode_walk_writeback(struct super_block *sb, bool write);

void scoutfs_inode_exit(void);
int scoutfs_inode_init(void);

int scoutfs_inode_setup(struct super_block *sb);
void scoutfs_inode_start(struct super_block *sb);
void scoutfs_inode_orphan_stop(struct super_block *sb);
void scoutfs_inode_flush_iput(struct super_block *sb);
void scoutfs_inode_destroy(struct super_block *sb);

#endif
