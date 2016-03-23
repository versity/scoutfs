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
	u64 *dwords = addr;

	nr ^= BITOP_LE_SWIZZLE;

	dwords[nr / 64] |= 1 << (nr & 63);
}

#endif
