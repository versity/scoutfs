#define _GNU_SOURCE
#include <unistd.h>
#include <strings.h>

#include "sparse.h"
#include "util.h"
#include "bitmap.h"

/*
 * Just a quick simple native bitmap.
 */

void set_bit(unsigned long *bits, u64 nr)
{
	bits[nr / BITS_PER_LONG] |= 1UL << (nr & (BITS_PER_LONG - 1));
}

void clear_bit(unsigned long *bits, u64 nr)
{
	bits[nr / BITS_PER_LONG] &= ~(1UL << (nr & (BITS_PER_LONG - 1)));
}

u64 find_next_set_bit(unsigned long *map, u64 from, u64 total)
{
	unsigned long bits;
	u64 base;
	u64 nr;
	int bit;

	base = from & ~((unsigned long)BITS_PER_LONG - 1);
	map += from / BITS_PER_LONG;

	while (base < total) {
		bits = *map;

		while (bits) {
			bit = ffsl(bits) - 1;
			nr = base + bit;

			if (nr >= from)
				return min(nr, total);

			bits &= ~(1UL << bit);
		}

		base += BITS_PER_LONG;
		map++;
	}

	return total;
}

unsigned long *alloc_bits(u64 max)
{
	return calloc(DIV_ROUND_UP(max, BITS_PER_LONG), sizeof(unsigned long));
}

