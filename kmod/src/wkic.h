#ifndef _SCOUTFS_WKIC_H_
#define _SCOUTFS_WKIC_H_

#include "format.h"

typedef int (*wkic_iter_cb_t)(struct scoutfs_key *key, void *val, unsigned int val_len,
			      void *cb_arg);

int scoutfs_wkic_iterate(struct super_block *sb, struct scoutfs_key *key, struct scoutfs_key *last,
			 struct scoutfs_key *range_start, struct scoutfs_key *range_end,
			 wkic_iter_cb_t cb, void *cb_arg);
int scoutfs_wkic_iterate_stable(struct super_block *sb, struct scoutfs_key *key,
				struct scoutfs_key *last, struct scoutfs_key *range_start,
				struct scoutfs_key *range_end, wkic_iter_cb_t cb, void *cb_arg);

int scoutfs_wkic_setup(struct super_block *sb);
void scoutfs_wkic_destroy(struct super_block *sb);

#endif
