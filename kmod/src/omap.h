#ifndef _SCOUTFS_OMAP_H_
#define _SCOUTFS_OMAP_H_

int scoutfs_omap_set(struct super_block *sb, u64 ino);
bool scoutfs_omap_test(struct super_block *sb, u64 ino);
void scoutfs_omap_clear(struct super_block *sb, u64 ino);
int scoutfs_omap_client_handle_request(struct super_block *sb, u64 id,
				       struct scoutfs_open_ino_map_args *args);
void scoutfs_omap_calc_group_nrs(u64 ino, u64 *group_nr, int *bit_nr);

int scoutfs_omap_add_rid(struct super_block *sb, u64 rid);
int scoutfs_omap_remove_rid(struct super_block *sb, u64 rid);
int scoutfs_omap_finished_recovery(struct super_block *sb);
int scoutfs_omap_server_handle_request(struct super_block *sb, u64 rid, u64 id,
				       struct scoutfs_open_ino_map_args *args);
int scoutfs_omap_server_handle_response(struct super_block *sb, u64 rid,
					struct scoutfs_open_ino_map *resp_map);
void scoutfs_omap_server_shutdown(struct super_block *sb);

int scoutfs_omap_setup(struct super_block *sb);
void scoutfs_omap_destroy(struct super_block *sb);

#endif
