#define _GNU_SOURCE /* ffsll */
#include <string.h>

#include "lebitmap.h"

void set_le_bit(__le64 *bits, u64 nr)
{
	bits += nr / 64;

	*bits = cpu_to_le64(le64_to_cpu(*bits) | (1ULL << (nr & 63)));
}

void clear_le_bit(__le64 *bits, u64 nr)
{
	bits += nr / 64;

	*bits = cpu_to_le64(le64_to_cpu(*bits) & ~(1ULL << (nr & 63)));
}

int test_le_bit(__le64 *bits, u64 nr)
{
	bits += nr / 64;

	return !!(le64_to_cpu(*bits) & (1ULL << (nr & 63)));
}

/* returns -1 or nr */
s64 find_first_le_bit(__le64 *bits, s64 count)
{
	long nr;

	for (nr = 0; count > 0; bits++, nr += 64, count -= 64) {
		if (*bits)
			return nr + ffsll(le64_to_cpu(*bits)) - 1;
	}

	return -1;
}
