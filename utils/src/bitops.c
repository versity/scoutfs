#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "sparse.h"
#include "util.h"
#include "bitops.h"

#if (__SIZEOF_LONG__  == 8)
typedef __le64 lelong;
#define lelong_to_cpu le64_to_cpu

#elif (__SIZEOF_LONG__  == 4)
typedef __le32 lelong;
#define lelong_to_cpu le32_to_cpu

#else
#error "no sizeof long define?"
#endif

/*
 * I'd have used ffsl(), but defining _GNU_SOURCE caused build errors
 * in glibc.  The gcc builtin has the added bonus of returning 0 for the
 * least significant bit instead of 1.
 */
#define ctzl __builtin_ctzl

int find_next_bit_le(void *addr, long size, int start)
{
	lelong * __packed longs = addr;
	unsigned long off = 0;
	unsigned long masked;

	/* skip past whole longs before start */
	if (start >= BITS_PER_LONG) {
		longs += start / BITS_PER_LONG;
		off = start & ~(BITS_PER_LONG - 1);
		start -= off;
	}

	/* mask off low bits if start isn't aligned */
	if (start) {
		masked = lelong_to_cpu(*longs) & ~((1 << (start)) - 1);
		if (masked)
			return min(ctzl(masked), size);

		off += BITS_PER_LONG;
		longs++;
	}

	/* then search remaining longs */
	while (off < size) {
		if (*longs)
			return min(off + ctzl(lelong_to_cpu(*longs)), size);
		longs++;
		off += BITS_PER_LONG;
	}

	return size;
}
