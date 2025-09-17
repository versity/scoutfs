#ifndef _SCOUTFS_FENCE_H_
#define _SCOUTFS_FENCE_H_

enum {
	SCOUTFS_FENCE_CLIENT_RECOVERY,
	SCOUTFS_FENCE_CLIENT_RECONNECT,
	SCOUTFS_FENCE_QUORUM_BLOCK_LEADER,
};

int scoutfs_fence_start(struct super_block *sb, u64 rid, union scoutfs_inet_addr *addr, int reason);
int scoutfs_fence_next(struct super_block *sb, u64 *rid, int *reason, bool *error);
int scoutfs_fence_reason_pending(struct super_block *sb, int reason);
int scoutfs_fence_free(struct super_block *sb, u64 rid);
int scoutfs_fence_wait_fenced(struct super_block *sb, long timeout_jiffies);

int scoutfs_fence_setup(struct super_block *sb);
void scoutfs_fence_stop(struct super_block *sb);
void scoutfs_fence_destroy(struct super_block *sb);

#endif
