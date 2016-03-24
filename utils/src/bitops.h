#ifndef _BITOPS_H_
#define _BITOPS_H_

#define BITS_PER_LONG (sizeof(long) * 8)
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BITOP_LE_SWIZZLE        0
#else
#define BITOP_LE_SWIZZLE        ((BITS_PER_LONG-1) & ~0x7)
#endif

static inline void set_bit_le(int nr, void *addr)
{
	unsigned long *longs = addr;

	nr ^= BITOP_LE_SWIZZLE;

	longs[nr / BITS_PER_LONG] |= 1UL << (nr & (BITS_PER_LONG - 1));
}

#endif
