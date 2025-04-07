#ifndef _SCOUTFS_QUORUM_H_
#define _SCOUTFS_QUORUM_H_

int scoutfs_quorum_server_sin(struct super_block *sb, struct sockaddr_in *sin);

u8 scoutfs_quorum_votes_needed(struct super_block *sb);
void scoutfs_quorum_slot_sin(struct scoutfs_quorum_config *qconf, int i,
			     struct sockaddr_in *sin);

int scoutfs_quorum_fence_leaders(struct super_block *sb, struct scoutfs_quorum_config *qconf,
				 u64 term);

int scoutfs_quorum_setup(struct super_block *sb);
void scoutfs_quorum_shutdown(struct super_block *sb);
void scoutfs_quorum_destroy(struct super_block *sb);

#endif
