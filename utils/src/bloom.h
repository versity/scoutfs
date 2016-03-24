#ifndef _BLOOM_H_
#define _BLOOM_H_

struct scoutfs_bloom_bits {
	u16 bit_off[SCOUTFS_BLOOM_BITS];
	u8 block[SCOUTFS_BLOOM_BITS];
};

void scoutfs_calc_bloom_bits(struct scoutfs_bloom_bits *bits,
			     struct scoutfs_key *key, __le32 *salts);
void scoutfs_set_bloom_bits(struct scoutfs_bloom_block *blm, unsigned int nr,
			    struct scoutfs_bloom_bits *bits);

#endif
