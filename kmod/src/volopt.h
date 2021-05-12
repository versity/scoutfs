#ifndef _SCOUTFS_VOLOPT_H_
#define _SCOUTFS_VOLOPT_H_

int scoutfs_volopt_setup(struct super_block *sb);
void scoutfs_volopt_destroy(struct super_block *sb);

#endif
