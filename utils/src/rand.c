#include <string.h>

#include "rand.h"
#include "sparse.h"
#include "util.h"

void pseudo_random_bytes(void *data, unsigned int len)
{
	unsigned long long tmp;
	unsigned long long *ll = data;
	unsigned int sz = sizeof(*ll);
	unsigned int unaligned;

	/* see if the initial buffer is unaligned */
	unaligned = min((unsigned long)data & (sz - 1), len);
	if (unaligned) {
		__builtin_ia32_rdrand64_step(&tmp);
		memcpy(data, &tmp, unaligned);
		data += unaligned;
		len -= unaligned;
	}

	for (ll = data; len >= sz; ll++, len -= sz)
		__builtin_ia32_rdrand64_step(ll);

	if (len) {
		__builtin_ia32_rdrand64_step(&tmp);
		memcpy(data, &tmp, len);
	}
}
