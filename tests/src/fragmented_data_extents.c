/*
 * Copyright (C) 2021 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

/*
 * This creates fragmented data extents.
 *
 * A file is created that has alternating free and allocated extents.
 * This also results in the global allocator having the matching
 * fragmented free extent pattern.  While that file is being created,
 * occasionally an allocated extent is moved to another file.   This
 * results in a file that has fragmented extents at a given stride that
 * can be deleted to create free data extents with a given stride.
 *
 * We don't have hole punching so to do this quickly we use a goofy
 * combination of fallocate, truncate, and our move_blocks ioctl.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/types.h>
#include <assert.h>

#include "ioctl.h"

#define BLOCK_SIZE 4096

int main(int argc, char **argv)
{
	struct scoutfs_ioctl_move_blocks mb = {0,};
	unsigned long long freed_extents;
	unsigned long long move_stride;
	unsigned long long i;
	int alloc_fd;
	int trunc_fd;
	off_t off;
	int ret;

	if (argc != 5) {
		printf("%s <freed_extents> <move_stride> <alloc_file> <trunc_file>\n", argv[0]);
		return 1;
	}

	freed_extents = strtoull(argv[1], NULL, 0);
	move_stride = strtoull(argv[2], NULL, 0);

	alloc_fd = open(argv[3], O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (alloc_fd == -1) {
		fprintf(stderr, "error opening %s: %d (%s)\n", argv[3], errno, strerror(errno));
		exit(1);
	}

	trunc_fd = open(argv[4], O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (trunc_fd == -1) {
		fprintf(stderr, "error opening %s: %d (%s)\n", argv[4], errno, strerror(errno));
		exit(1);
	}

	for (i = 0, off = 0; i < freed_extents; i++, off += BLOCK_SIZE * 2) {

		ret = fallocate(alloc_fd, 0, off, BLOCK_SIZE * 2);
		if (ret < 0) {
			fprintf(stderr, "fallocate at off %llu error: %d (%s)\n",
				(unsigned long long)off, errno, strerror(errno));
			exit(1);
		}

		ret = ftruncate(alloc_fd, off + BLOCK_SIZE);
		if (ret < 0) {
			fprintf(stderr, "truncate to off %llu error: %d (%s)\n",
				(unsigned long long)off + BLOCK_SIZE, errno, strerror(errno));
			exit(1);
		}

		if ((i % move_stride) == 0) {
			mb.from_fd = alloc_fd;
			mb.from_off = off;
			mb.len = BLOCK_SIZE;
			mb.to_off = i * BLOCK_SIZE;

			ret = ioctl(trunc_fd, SCOUTFS_IOC_MOVE_BLOCKS, &mb);
			if (ret < 0) {
				fprintf(stderr, "move from off %llu error: %d (%s)\n",
					(unsigned long long)off,
					errno, strerror(errno));
			}
		}
	}

	if (alloc_fd > -1)
		close(alloc_fd);
	if (trunc_fd > -1)
		close(trunc_fd);

	return 0;
}
