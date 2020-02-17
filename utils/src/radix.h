#ifndef _RADIX_H_
#define _RADIX_H_

#include <stdbool.h>

u8 radix_height_from_last(u64 last);
u64 radix_full_subtree_total(int level);
void radix_init_ref(struct scoutfs_radix_ref *ref, int level, bool full);
void radix_calc_level_inds(int *inds, u8 height, u64 bit);
u64 radix_calc_leaf_bit(u64 bit);
int radix_blocks_needed(u64 a, u64 b);

#endif
