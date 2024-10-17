#ifndef _SCOUTFS_NAME_HASH_H_
#define _SCOUTFS_NAME_HASH_H_

#include "hash.h"

/*
 * Test a bit number as though an array of bytes is a large len-bit
 * big-endian value.  nr 0 is the LSB of the final byte, nr (len - 1) is
 * the MSB of the first byte.
 */
static int test_be_bytes_bit(int nr, const char *bytes, int len)
{
	return bytes[(len - 1 - nr) >> 3] & (1 << (nr & 7));
}

/*
 * Generate a 32bit "fingerprint" of the name by extracting 32 evenly
 * distributed bits from the name.  The intent is to have the sort order
 * of the fingerprints reflect the memcmp() sort order of the names
 * while mapping large names down to small fs keys.
 *
 * Names that are smaller than 32bits are biased towards the high bits
 * of the fingerprint so that most significant bits of the fingerprints
 * consistently reflect the initial characters of the names.
 */
static inline u32 dirent_name_fingerprint(const char *name, unsigned int name_len)
{
	int name_bits = name_len * 8;
	int skip = max(name_bits / 32, 1);
	u32 fp = 0;
	int f;
	int n;

	for (f = 31, n = name_bits - 1; f >= 0 && n >= 0; f--, n -= skip)
		fp |= !!test_be_bytes_bit(n, name, name_bits) << f;

	return fp;
}

static inline u64 dirent_name_hash(const char *name, unsigned int name_len)
{
       return scoutfs_hash32(name, name_len) |
              ((u64)dirent_name_fingerprint(name, name_len) << 32);
}

#endif
