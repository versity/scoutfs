#ifndef _SCOUTFS_UTILS_CHECK_SUPER_H_
#define _SCOUTFS_UTILS_CHECK_SUPER_H_

extern struct scoutfs_super_block *global_super;

int check_super_crc(bool repair);
int check_supers(int data_fd);
int super_commit(void);
int check_super_in_use(int meta_fd, bool repair, bool force);
void super_shutdown(void);

#endif
