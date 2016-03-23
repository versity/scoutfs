/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
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
#include "sparse.h"
#include "util.h"
#include "format.h"
#include "bloom.h"
#include "crc.h"
#include "bitops.h"

/* XXX garbage hack until we have siphash */
static u32 bloom_hash(struct scoutfs_key *key, __le32 salt)
{
	return crc32c(le32_to_cpu(salt), key, sizeof(struct scoutfs_key));
}

/*
 * Find the bits in the bloom filter for the given key.  The caller calculates
 * these once and uses them to test all the blocks.
 */
void scoutfs_calc_bloom_bits(struct scoutfs_bloom_bits *bits,
			     struct scoutfs_key *key, __le32 *salts)
{
	unsigned h_bits = 0;
	unsigned s = 0;
	u64 h = 0;
	int i;

	for (i = 0; i < SCOUTFS_BLOOM_BITS; i++) {
		if (h_bits < SCOUTFS_BLOOM_BIT_WIDTH) {
			h = (h << 32) | bloom_hash(key, salts[s++]);
			h += 32;
		}

		bits->nr[i] = h & SCOUTFS_BLOOM_BIT_MASK;
		h >>= SCOUTFS_BLOOM_BIT_WIDTH;
		h_bits -= SCOUTFS_BLOOM_BIT_WIDTH;
	}
}

/*
 * This interface is different than in the kernel because we don't
 * have a block IO interface here yet.  The caller gives us each
 * bloom block and we set each bit that falls in the block.
 */ 
void scoutfs_set_bloom_bits(struct scoutfs_bloom_block *blm, unsigned int nr,
			    struct scoutfs_bloom_bits *bits)
{
	int i;

	for (i = 0; i < SCOUTFS_BLOOM_BITS; i++) {
		if (nr == (bits->nr[i] / SCOUTFS_BLOOM_BITS_PER_BLOCK)) {
			set_bit_le(bits->nr[i] % SCOUTFS_BLOOM_BITS_PER_BLOCK,
				   blm->bits);
		}
	}
}
