#ifndef	_SCOUTFS_OPTIONS_H_
#define	_SCOUTFS_OPTIONS_H_

#include <linux/fs.h>
#include <linux/in.h>
#include "format.h"

struct scoutfs_mount_options {
	u64 data_prealloc_blocks;
	bool data_prealloc_contig_only;
	unsigned int log_merge_wait_timeout_ms;
	char *metadev_path;
	unsigned int orphan_scan_delay_ms;
	int quorum_slot_nr;
	u64 quorum_heartbeat_timeout_ms;
};

void scoutfs_options_read(struct super_block *sb, struct scoutfs_mount_options *opts);
int scoutfs_options_show(struct seq_file *seq, struct dentry *root);

int scoutfs_options_early_setup(struct super_block *sb, char *options);
int scoutfs_options_setup(struct super_block *sb);
void scoutfs_options_stop(struct super_block *sb);
void scoutfs_options_destroy(struct super_block *sb);

#endif	/* _SCOUTFS_OPTIONS_H_ */
