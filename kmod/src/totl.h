#ifndef _SCOUTFS_TOTL_H_
#define _SCOUTFS_TOTL_H_

#include "key.h"

struct scoutfs_totl_merging {
	u64 fs_seq;
	u64 fs_total;
	u64 fs_count;
	u64 fin_seq;
	u64 fin_total;
	s64 fin_count;
	u64 log_seq;
	u64 log_total;
	s64 log_count;
};

void scoutfs_totl_set_range(struct scoutfs_key *start, struct scoutfs_key *end);
void scoutfs_totl_merge_init(struct scoutfs_totl_merging *merg);
void scoutfs_totl_merge_contribute(struct scoutfs_totl_merging *merg,
				   u64 seq, u8 flags, void *val, int val_len, int fic);
void scoutfs_totl_merge_resolve(struct scoutfs_totl_merging *merg, __u64 *total, __u64 *count);

#endif
