#ifndef _BITOPS_H_
#define _BITOPS_H_

#include "sparse.h"

/*
 * Implement little endian bitmaps in terms of native longs.  __packed
 * is used to avoid unaligned accesses.  These are neither atomic nor
 * particularly efficient.
 */

#define BITS_PER_LONG (sizeof(long) * 8)
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BITOP_LE_SWIZZLE        0
#else
#define BITOP_LE_SWIZZLE        ((BITS_PER_LONG-1) & ~0x7)
#endif

static inline unsigned long get_nr_word(int nr, void *addr)
{
	unsigned long *longs = addr;
	unsigned long ind = nr / BITS_PER_LONG;
	unsigned long val;

	memcpy(&val, &longs[ind], sizeof(val));

	return val;
}

static inline void put_nr_word(int nr, void *addr, unsigned long val)
{
	unsigned long *longs = addr;
	unsigned long ind = nr / BITS_PER_LONG;

	memcpy(&longs[ind], &val, sizeof(val));
}

static inline unsigned long nr_mask(int nr)
{
	return 1UL << (nr % BITS_PER_LONG);
}

static inline int test_bit(int nr, void *addr)
{
	unsigned long val = get_nr_word(nr, addr);

	return !!(val & nr_mask(nr));
}

static inline void set_bit(int nr, void *addr)
{
	unsigned long val = get_nr_word(nr, addr);

	val |= nr_mask(nr);
	put_nr_word(nr, addr, val);
}

static inline void clear_bit(int nr, void *addr)
{
	unsigned long val = get_nr_word(nr, addr);

	val &= ~nr_mask(nr);
	put_nr_word(nr, addr, val);
}

static inline int test_bit_le(int nr, void *addr)
{
	return test_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

static inline int test_and_set_bit_le(int nr, void *addr)
{
	int ret;

	nr ^= BITOP_LE_SWIZZLE;
	ret = test_bit(nr, addr);
	set_bit(nr, addr);
	return ret;
}

static inline void set_bit_le(int nr, void *addr)
{
	set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

static inline void clear_bit_le(int nr, void *addr)
{
	clear_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}

static inline int test_and_clear_bit_le(int nr, void *addr)
{
	int ret;

	nr ^= BITOP_LE_SWIZZLE;
	ret = test_bit(nr, addr);
	clear_bit(nr, addr);
	return ret;
}

#endif
