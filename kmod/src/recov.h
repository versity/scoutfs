#ifndef _SCOUTFS_RECOV_H_
#define _SCOUTFS_RECOV_H_

enum {
	SCOUTFS_RECOV_GREETING	= ( 1 <<  0),
	SCOUTFS_RECOV_LOCKS	= ( 1 <<  1),

	SCOUTFS_RECOV_INVALID	= (~0 <<  2),
	SCOUTFS_RECOV_ALL	= (~SCOUTFS_RECOV_INVALID),
};

int scoutfs_recov_prepare(struct super_block *sb, u64 rid, int which);
int scoutfs_recov_begin(struct super_block *sb, void (*timeout_fn)(struct super_block *),
			unsigned int timeout_ms);
int scoutfs_recov_finish(struct super_block *sb, u64 rid, int which);
bool scoutfs_recov_is_pending(struct super_block *sb, u64 rid, int which);
u64 scoutfs_recov_next_pending(struct super_block *sb, int which);
void scoutfs_recov_shutdown(struct super_block *sb);

int scoutfs_recov_setup(struct super_block *sb);
void scoutfs_recov_destroy(struct super_block *sb);

#endif
