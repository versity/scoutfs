#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

#include "sparse.h"
#include "util.h"
#include "format.h"

#include "parse.h"

/*
 * Convert size with multiplicative suffix to bytes.
 * e.g. "40M", "10G", "4T"
 *
 * These are powers-of-two prefixes - K means 1024 not 1000.
 *
 * One can go pretty far with variations but keeping relatively simple for
 * now: commas, decimals, and multichar suffixes not handled.
 */
int parse_human(char* str, u64 *val_ret)
{
	unsigned long long ull;
	char *endptr = NULL;
	int sh;
	int ret = 0;

	ull = strtoull(str, &endptr, 0);
	if (((ull == LLONG_MIN || ull == LLONG_MAX) &&
	     errno == ERANGE)) {
		fprintf(stderr, "invalid 64bit value: '%s'\n", str);
		*val_ret = 0;
		ret = -EINVAL;
		goto error;
	}

	switch (*endptr) {
	case 'K':
		sh = 10;
		break;
	case 'M':
		sh = 20;
		break;
	case 'G':
		sh = 30;
		break;
	case 'T':
		sh = 40;
		break;
	case 'P':
		sh = 50;
		break;
	case '\0':
		sh = 0;
		break;
	default:
		fprintf(stderr, "unknown suffix: '%s'\n", endptr);
		ret = -ERANGE;
		goto error;
	}

	if (ull > (SIZE_MAX >> sh)) {
		fprintf(stderr, "size too big: '%s'\n", str);
		ret = -ERANGE;
		goto error;
	}

	ull <<= sh;

	*val_ret = ull;

error:
	return ret;
}

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

int parse_s64(char *str, s64 *val_ret)
{
	long long ll;
	char *endptr = NULL;

	ll = strtoll(str, &endptr, 0);
	if (*endptr != '\0' ||
	    ((ll == LLONG_MIN || ll == LLONG_MAX) &&
	     errno == ERANGE)) {
		fprintf(stderr, "invalid 64bit value: '%s'\n", str);
		*val_ret = 0;
		return -EINVAL;
	}

	*val_ret = ll;

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
