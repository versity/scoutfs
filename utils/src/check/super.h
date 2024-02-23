#ifndef _SCOUTFS_UTILS_CHECK_SUPER_H_
#define _SCOUTFS_UTILS_CHECK_SUPER_H_

extern struct scoutfs_super_block *global_super;

int check_supers(void);
void super_shutdown(void);

#endif
