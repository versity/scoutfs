#ifndef _SCOUTFS_SUPER_H_
#define _SCOUTFS_SUPER_H_

#include <linux/fs.h>
#include <linux/rbtree.h>

#include "format.h"
#include "options.h"
#include "data.h"
#include "sysfs.h"

struct scoutfs_counters;
struct scoutfs_triggers;
struct manifest;
struct data_info;
struct trans_info;
struct lock_info;
struct lock_server_info;
struct client_info;
struct server_info;
struct inode_sb_info;
struct btree_info;
struct sysfs_info;
struct options_sb_info;
struct net_info;
struct block_info;
struct forest_info;
struct srch_info;
struct recov_info;
struct omap_info;
struct volopt_info;
struct fence_info;
struct wkic_info;
struct squota_info;

struct scoutfs_sb_info {
	struct super_block *sb;

	/* assigned once at the start of each mount, read-only */
	u64 fsid;
	u64 rid;
	u64 fmt_vers;

	struct block_device *meta_bdev;
#ifdef KC_BDEV_FILE_OPEN_BY_PATH
	struct file *meta_bdev_file;
#endif

	spinlock_t next_ino_lock;

	struct options_info *options_info;
	struct data_info *data_info;
	struct inode_sb_info *inode_sb_info;
	struct btree_info *btree_info;
	struct net_info *net_info;
	struct quorum_info *quorum_info;
	struct block_info *block_info;
	struct forest_info *forest_info;
	struct srch_info *srch_info;
	struct omap_info *omap_info;
	struct volopt_info *volopt_info;
	struct item_cache_info *item_cache_info;
	struct wkic_info *wkic_info;
	struct squota_info *squota_info;
	struct fence_info *fence_info;

	/* tracks tasks waiting for data extents */
	struct scoutfs_data_wait_root data_wait_root;

	/* set as transaction opens with trans holders excluded */
	u64 trans_seq;

	struct trans_info *trans_info;
	struct lock_info *lock_info;
	struct lock_server_info *lock_server_info;
	struct client_info *client_info;
	struct server_info *server_info;
	struct recov_info *recov_info;
	struct sysfs_info *sfsinfo;

	struct scoutfs_counters *counters;
	struct scoutfs_triggers *triggers;

	struct dentry *debug_root;

	bool forced_unmount;
	bool unmounting;

	unsigned long corruption_messages_once[SC_NR_LONGS];
};

static inline struct scoutfs_sb_info *SCOUTFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline bool SCOUTFS_HAS_SBI(struct super_block *sb)
{
	return (sb != NULL) && (SCOUTFS_SB(sb) != NULL);
}

static inline bool SCOUTFS_IS_META_BDEV(struct scoutfs_super_block *super_block)
{
	return !!(le64_to_cpu(super_block->flags) & SCOUTFS_FLAG_IS_META_BDEV);
}

#ifdef KC_HAVE_BLK_MODE_T
#define SCOUTFS_META_BDEV_MODE (BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_EXCL)
#else
#define SCOUTFS_META_BDEV_MODE (FMODE_READ | FMODE_WRITE | FMODE_EXCL)
#endif

static inline bool scoutfs_forcing_unmount(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	return sbi->forced_unmount;
}

/*
 * True if we're shutting down the system and can be used as a coarse
 * indicator that we can avoid doing some work that no longer makes
 * sense.
 */
static inline bool scoutfs_unmounting(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	smp_rmb();
	return !sbi || sbi->unmounting;
}

/*
 * A small string embedded in messages that's used to identify a
 * specific mount.  It's the three most significant bytes of the fsid
 * and the rid.  That gives us a strong chance of avoiding collisions
 * with typical numbers of mounts.  We give it a bit of structure to
 * make it searchable and to be able to identify format changes, should
 * we need to.  The fsid will be 0 until the super has been read and the
 * fsid discovered.
 */
#define SCSBF		"f.%.06x.r.%.06x"
#define SCSB_SHIFT	(64 - (8 * 3))
#define SCSB_LEFR_ARGS(fsid, rid)					    \
	(int)(le64_to_cpu(fsid) >> SCSB_SHIFT),				    \
	(int)(le64_to_cpu(rid) >> SCSB_SHIFT)
#define SCSB_ARGS(sb)							    \
	(int)(SCOUTFS_SB(sb)->fsid >> SCSB_SHIFT),			    \
	(int)(SCOUTFS_SB(sb)->rid >> SCSB_SHIFT)
#define SCSB_TRACE_FIELDS	\
	__field(__u64, fsid)	\
	__field(__u64, rid)
#define SCSB_TRACE_ASSIGN(sb)						\
	__entry->fsid = SCOUTFS_HAS_SBI(sb) ?				\
		        SCOUTFS_SB(sb)->fsid : 0;			\
	__entry->rid = SCOUTFS_HAS_SBI(sb) ?				\
		       SCOUTFS_SB(sb)->rid : 0;
#define SCSB_TRACE_ARGS				\
	(int)(__entry->fsid >> SCSB_SHIFT),	\
	(int)(__entry->rid >> SCSB_SHIFT)

int scoutfs_read_super(struct super_block *sb,
		       struct scoutfs_super_block *super_res);
int scoutfs_write_super(struct super_block *sb,
		        struct scoutfs_super_block *super);

/* to keep this out of the ioctl.h public interface definition */
long scoutfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/*
 * Returns 0 when supported, non-zero -errno when unsupported.
 */
static inline int scoutfs_fmt_vers_unsupported(struct super_block *sb, u64 vers)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (sbi && (sbi->fmt_vers < vers))
		return -EOPNOTSUPP;
	else
		return 0;
}

#endif
