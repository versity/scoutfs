#ifndef _SCOUTFS_RAW_H_
#define _SCOUTFS_RAW_H_

int scoutfs_raw_read_meta_seq(struct super_block *sb,
			      struct scoutfs_ioctl_raw_read_meta_seq *rms,
			      struct scoutfs_ioctl_meta_seq *last_ret);
int scoutfs_raw_read_inode_info(struct super_block *sb,
				struct scoutfs_ioctl_raw_read_inode_info *rii);

#endif
