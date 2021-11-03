/*
 * Exercise O_TMPFILE creation as well as staging from tmpfiles into
 * a released destination file.
 *
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

#define array_size(arr) (sizeof(arr) / sizeof(arr[0]))

/*
 * Write known data into 8 tmpfiles.
 * Make a new file X and release it
 * Move contents of 8 tmpfiles into X.
 */

struct sub_tmp_info {
	int fd;
	unsigned int offset;
	unsigned int length;
};

#define SZ	4096
char buf[SZ];

int main(int argc, char **argv)
{
	struct scoutfs_ioctl_release rel = {0};
	struct scoutfs_ioctl_move_blocks mb;
	struct scoutfs_ioctl_stat_more stm;
	struct sub_tmp_info sub_tmps[8];
	int tot_size = 0;
	char *dest_file;
	int dest_fd;
	char *mnt;
	int ret;
	int i;

	if (argc < 3) {
		printf("%s <mountpoint> <dest_file>\n", argv[0]);
		return 1;
	}

	mnt = argv[1];
	dest_file = argv[2];

	for (i = 0; i < array_size(sub_tmps); i++) {
		struct sub_tmp_info *sub_tmp = &sub_tmps[i];
		int remaining;

		sub_tmp->fd = open(mnt, O_RDWR | O_TMPFILE, S_IRUSR | S_IWUSR);
		if (sub_tmp->fd < 0) {
			perror("error");
			exit(1);
		}

		sub_tmp->offset = tot_size;

		/* First tmp file is 4MB */
		/* Each is 4k bigger than last */
		sub_tmp->length = (i + 1024) * sizeof(buf);

		remaining = sub_tmp->length;

		/* Each sub tmpfile written with 'A', 'B', etc. */
		memset(buf, 'A' + i, sizeof(buf));
		while (remaining) {
			int written;

			written = write(sub_tmp->fd, buf, sizeof(buf));
			assert(written == sizeof(buf));
			tot_size += sizeof(buf);
			remaining -= written;
		}
	}

	printf("total file size %d\n", tot_size);

	dest_fd = open(dest_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (dest_fd == -1) {
		perror("error");
		exit(1);
	}

	// make dest file big
	ret = posix_fallocate(dest_fd, 0, tot_size);
	if (ret) {
		perror("error");
		exit(1);
	}

	// get current data_version after fallocate's size extensions
	ret = ioctl(dest_fd, SCOUTFS_IOC_STAT_MORE, &stm);
	if (ret < 0) {
		perror("stat_more ioctl error");
		exit(1);
	}

	// release everything in dest file
	rel.offset = 0;
	rel.length = tot_size;
	rel.data_version = stm.data_version;

	ret = ioctl(dest_fd, SCOUTFS_IOC_RELEASE, &rel);
	if (ret < 0) {
		perror("error");
		exit(1);
	}

	// move contents into dest in reverse order
	for (i = array_size(sub_tmps) - 1; i >= 0 ; i--) {
		struct sub_tmp_info *sub_tmp = &sub_tmps[i];

		mb.from_fd = sub_tmp->fd;
		mb.from_off = 0;
		mb.len = sub_tmp->length;
		mb.to_off = sub_tmp->offset;
		mb.data_version = stm.data_version;
		mb.flags = SCOUTFS_IOC_MB_STAGE;

		ret = ioctl(dest_fd, SCOUTFS_IOC_MOVE_BLOCKS, &mb);
		if (ret < 0) {
			perror("error");
			exit(1);
		}

	}

	return 0;
}
