/*
 * Copyright (C) 2023 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/string.h>

#include "format.h"
#include "forest.h"
#include "totl.h"

void scoutfs_totl_set_range(struct scoutfs_key *start, struct scoutfs_key *end)
{
	scoutfs_key_set_zeros(start);
	start->sk_zone = SCOUTFS_XATTR_TOTL_ZONE;
	scoutfs_key_set_ones(end);
	end->sk_zone = SCOUTFS_XATTR_TOTL_ZONE;
}

void scoutfs_totl_merge_init(struct scoutfs_totl_merging *merg)
{
	memset(merg, 0, sizeof(struct scoutfs_totl_merging));
}

/*
 * bin the incoming merge inputs so that we can resolve delta items
 * properly. Finalized logs that are merge inputs are kept separately
 * from those that are not.
 */
void scoutfs_totl_merge_contribute(struct scoutfs_totl_merging *merg,
				   u64 seq, u8 flags, void *val, int val_len, int fic)
{
	struct scoutfs_xattr_totl_val *tval = val;

	if (fic & FIC_FS_ROOT) {
		merg->fs_seq = seq;
		merg->fs_total = le64_to_cpu(tval->total);
		merg->fs_count = le64_to_cpu(tval->count);
	} else if (fic & FIC_MERGE_INPUT) {
		merg->inp_seq = seq;
		merg->inp_total += le64_to_cpu(tval->total);
		merg->inp_count += le64_to_cpu(tval->count);
	} else {
		merg->log_seq = seq;
		merg->log_total += le64_to_cpu(tval->total);
		merg->log_count += le64_to_cpu(tval->count);
	}
}

/*
 * .totl. item merging has to be careful because the log btree merging
 * code can write partial results to the fs_root.  This means that a
 * reader can see both cases where merge input deltas should be applied
 * to the old fs items and where they have already been applied to the
 * partially merged fs items.
 *
 * Only finalized log trees that are inputs to the current merge cycle
 * are tracked in the inp_ bucket.  Finalized trees that aren't merge
 * inputs and active log trees are always applied unconditionally since
 * they cannot be in fs_root.
 *
 * These cases are differentiated with a combination of sequence numbers
 * in items and the count of contributing xattrs.  This lets us
 * recognize all cases, including when merge inputs were merged and
 * deleted the fs item.
 */
void scoutfs_totl_merge_resolve(struct scoutfs_totl_merging *merg, __u64 *total, __u64 *count)
{
	*total = 0;
	*count = 0;

	/* start with the fs item if we have it */
	if (merg->fs_seq != 0) {
		*total = merg->fs_total;
		*count = merg->fs_count;
	}

	/* apply merge input deltas if they're newer or creating */
	if (((merg->fs_seq != 0) && (merg->inp_seq > merg->fs_seq)) ||
	    ((merg->fs_seq == 0) && (merg->inp_count > 0))) {
		*total += merg->inp_total;
		*count += merg->inp_count;
	}

	/* always apply non-input finalized and active logs */
	if (merg->log_seq > 0) {
		*total += merg->log_total;
		*count += merg->log_count;
	}
}
