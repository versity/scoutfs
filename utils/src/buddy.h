#ifndef _BUDDY_H_
#define _BUDDY_H_

#include "format.h"

struct buddy_info {
	u8 height;
	u64 buddy_blocks;

	/* starting blkno in each level, including mirrors */
	u64 blknos[SCOUTFS_BUDDY_MAX_HEIGHT];
};

void buddy_init(struct buddy_info *binf, u64 total_blocks);

#endif
