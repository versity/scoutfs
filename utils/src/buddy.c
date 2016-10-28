#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "sparse.h"
#include "util.h"
#include "buddy.h"

/*
 * Figure out how many blocks the radix will need by starting with leaf
 * blocks and dividing by the slot fanout until we have one block.  cow
 * updates require two copies of every block.
 */
static u64 calc_blocks(struct buddy_info *binf, u64 bits)
{
	u64 blocks = DIV_ROUND_UP(bits, SCOUTFS_BUDDY_ORDER0_BITS);
	u64 tot = 0;
	int level = 0;
	int i;

	for (i = 0; i < SCOUTFS_BUDDY_MAX_HEIGHT; i++)
		binf->blknos[i] = SCOUTFS_BUDDY_BLKNO;

	for (;;) {
		for (i = level - 1; i >= 0; i--)
			binf->blknos[i] += (blocks * 2);
		tot += (blocks * 2);

		level++;
		if (blocks == 1)
			break;
		blocks = DIV_ROUND_UP(blocks, SCOUTFS_BUDDY_SLOTS);
	}

	binf->height = level;

	return tot;
}

/*
 * Figure out how many buddy blocks we'll need to allocate the rest of
 * the blocks in the device.  The first time through we find the size of
 * the radix needed to describe the whole device, but that doesn't take
 * the buddy block overhead into account.  We iterate getting a more
 * precise estimate each time.  This only takes a few rounds to
 * stabilize.
 */
void buddy_init(struct buddy_info *binf, u64 total_blocks)
{
	u64 blocks = SCOUTFS_BUDDY_BLKNO;
	u64 was;

	while(1) {
		was = blocks;
		blocks = calc_blocks(binf, total_blocks - blocks);
		if (blocks == was)
			break;
	}

	binf->buddy_blocks = blocks;
}
