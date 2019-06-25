#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

#include "sparse.h"
#include "util.h"
#include "format.h"

#include "parse.h"

int parse_u64(char *str, u64 *val_ret)
{
	unsigned long long ull;
	char *endptr = NULL;

	ull = strtoull(str, &endptr, 0);
	if (*endptr != '\0' ||
	    ((ull == LLONG_MIN || ull == LLONG_MAX) &&
	     errno == ERANGE)) {
		fprintf(stderr, "invalid 64bit value: '%s'\n", str);
		*val_ret = 0;
		return -EINVAL;
	}

	*val_ret = ull;

	return 0;
}

int parse_u32(char *str, u32 *val_ret)
{
	u64 val;
	int ret;

	ret = parse_u64(str, &val);
	if (ret)
		return ret;

	if (val > UINT_MAX)
		return -EINVAL;

	*val_ret = val;
	return 0;
}

int parse_timespec(char *str, struct timespec *ts)
{
	unsigned long long sec;
	unsigned int nsec;
	int ret;

	memset(ts, 0, sizeof(struct timespec));

	ret = sscanf(str, "%llu.%u", &sec, &nsec);
	if (ret != 2)  {
		fprintf(stderr, "invalid timespec string: '%s'\n", str);
		return -EINVAL;
	}

	if (nsec > 1000000000) {
		fprintf(stderr, "invalid timespec nsec value: '%s'\n", str);
		return -EINVAL;
	}

	ts->tv_sec = sec;
	ts->tv_nsec = nsec;

	return 0;
}
