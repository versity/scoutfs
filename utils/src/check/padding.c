#include <string.h>
#include <stdbool.h>

#include "util.h"
#include "padding.h"

bool padding_is_zeros(const void *data, size_t sz)
{
	static char zeros[32] = {0,};
	const size_t batch = array_size(zeros);

	while (sz >= batch) {
		if (memcmp(data, zeros, batch))
			return false;
		data += batch;
		sz -= batch;
	}

	if (sz > 0 && memcmp(data, zeros, sz))
		return false;

	return true;
}
