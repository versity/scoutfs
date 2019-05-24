#ifndef _PARSE_H_
#define _PARSE_H_

struct scoutfs_timespec;

int parse_u64(char *str, u64 *val_ret);
int parse_u32(char *str, u32 *val_ret);
int parse_timespec(char *str, struct scoutfs_timespec *ts);

#endif
