#ifndef _SCOUTFS_QUORUM_H_
#define _SCOUTFS_QUORUM_H_

int scoutfs_quorum_server_sin(struct super_block *sb, struct sockaddr_in *sin);
void scoutfs_quorum_server_shutdown(struct super_block *sb);

u8 scoutfs_quorum_votes_needed(struct super_block *sb);
void scoutfs_quorum_slot_sin(struct scoutfs_super_block *super, int i,
			     struct sockaddr_in *sin);

int scoutfs_quorum_setup(struct super_block *sb);
void scoutfs_quorum_shutdown(struct super_block *sb);
void scoutfs_quorum_destroy(struct super_block *sb);

#endif
