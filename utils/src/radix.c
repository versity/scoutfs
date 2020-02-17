#include <stdbool.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "radix.h"

/* return the height of a tree needed to store the last bit */
u8 radix_height_from_last(u64 last)
{
	u64 bit = SCOUTFS_RADIX_BITS - 1;
	u64 mult = SCOUTFS_RADIX_BITS;
	int i;

	for (i = 1; i <= U8_MAX; i++) {
		if (bit >= last)
			return i;
		bit += (u64)(SCOUTFS_RADIX_REFS - 1) * mult;
		mult *= SCOUTFS_RADIX_REFS;
	}

	return U8_MAX;
}

u64 radix_full_subtree_total(int level)
{
	u64 total = SCOUTFS_RADIX_BITS;
	int i;

	for (i = 1; i <= level; i++)
		total *= SCOUTFS_RADIX_REFS;

	return total;
}

/*
 * Initialize a reference to a block at the given level.
 */
void radix_init_ref(struct scoutfs_radix_ref *ref, int level, bool full)
{
	u64 tot;

	if (full) {
		tot = radix_full_subtree_total(level);

		ref->blkno = cpu_to_le64(U64_MAX);
		ref->seq = cpu_to_le64(0);
		ref->sm_total = cpu_to_le64(tot);
		ref->lg_total = cpu_to_le64(tot);
	} else {
		ref->blkno = cpu_to_le64(0);
		ref->seq = cpu_to_le64(0);
		ref->sm_total = cpu_to_le64(0);
		ref->lg_total = cpu_to_le64(0);
	}
}

void radix_calc_level_inds(int *inds, u8 height, u64 bit)
{
	u32 ind;
	int i;

	ind = bit % SCOUTFS_RADIX_BITS;
	bit = bit / SCOUTFS_RADIX_BITS;
	inds[0] = ind;

	for (i = 1; i < height; i++) {
		ind = bit % SCOUTFS_RADIX_REFS;
		bit = bit / SCOUTFS_RADIX_REFS;
		inds[i] = ind;
	}
}

u64 radix_calc_leaf_bit(u64 bit)
{
	return bit - (bit % SCOUTFS_RADIX_BITS);
}

/*
 * The number of blocks needed to initialize a radix with left and right
 * paths.  The first time we find a level where the parent refs are at
 * different indices determines where the paths diverge at lower levels.
 * If the refs never diverge then the two paths traverse the same blocks
 * and we just need blocks for the height of the tree.
 */
int radix_blocks_needed(u64 a, u64 b)
{
	u8 height = radix_height_from_last(b);
	int *a_inds;
	int *b_inds;
	int i;

	a_inds = alloca(sizeof(a_inds[0] * height));
	b_inds = alloca(sizeof(b_inds[0] * height));

	radix_calc_level_inds(a_inds, height, a);
	radix_calc_level_inds(b_inds, height, b);

	for (i = height - 1; i > 0; i--) {
		if (a_inds[i] != b_inds[i]) {
			return (i * 2) + (height - i);
		}
	}

	return height;
}
