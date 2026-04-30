/*
 * Test helper that calls SCOUTFS_IOC_INJECT_TOTL_DELTA to seed
 * arbitrary totl deltas.
 *
 * Copyright (C) 2026 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/types.h>

#include "ioctl.h"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <mountpoint> <a>.<b>.<c> <total> <count>\n",
		prog);
	exit(2);
}

static int parse_s64(const char *s, int64_t *out)
{
	char *end;
	int64_t v;

	errno = 0;
	v = strtoll(s, &end, 0);
	if (errno || *end != '\0' || end == s)
		return -1;
	*out = v;
	return 0;
}

/*
 * Parse "<a>.<b>.<c>" into abc[0..2] (skxt_a, skxt_b, skxt_c).  Each
 * component must be a non-empty unsigned base-0 integer.
 */
static int parse_dotted_name(const char *s, uint64_t abc[3])
{
	const char *p = s;
	char *end;
	int i;

	for (i = 0; i < 3; i++) {
		if (*p == '\0' || *p == '.')
			return -1;
		errno = 0;
		abc[i] = strtoull(p, &end, 0);
		if (errno || end == p)
			return -1;

		if (i < 2) {
			if (*end != '.')
				return -1;
			p = end + 1;
		} else {
			if (*end != '\0')
				return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct scoutfs_ioctl_inject_totl_delta itd = {{0,}};
	uint64_t abc[3];
	int64_t total, count;
	int fd;
	int ret;

	if (argc != 5)
		usage(argv[0]);

	if (parse_dotted_name(argv[2], abc) ||
	    parse_s64(argv[3], &total) ||
	    parse_s64(argv[4], &count)) {
		fprintf(stderr, "could not parse arguments\n");
		usage(argv[0]);
	}

	itd.name[0] = abc[0];
	itd.name[1] = abc[1];
	itd.name[2] = abc[2];
	itd.total = total;
	itd.count = count;

	fd = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", argv[1], strerror(errno));
		return 1;
	}

	ret = ioctl(fd, SCOUTFS_IOC_INJECT_TOTL_DELTA, &itd);
	if (ret < 0) {
		fprintf(stderr,
			"INJECT_TOTL_DELTA(%" PRIu64 ".%" PRIu64 ".%" PRIu64
			", total=%" PRId64 ", count=%" PRId64 "): %s\n",
			abc[0], abc[1], abc[2], total, count, strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
