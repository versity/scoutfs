/*
 * Given a scoutfs mountpoint and an inode number, open the inode by
 * handle and print the contents to stdout.
 *
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <endian.h>
#include <linux/types.h>

#define FILEID_SCOUTFS			0x81
#define FILEID_SCOUTFS_WITH_PARENT	0x82

struct our_handle {
	struct file_handle handle;
	/*
	 * scoutfs file handle can be ino or ino/parent. The
	 * handle_type field of struct file_handle denotes which
	 * version is in use. We only use the ino variant here.
	 */
	__le64 scoutfs_ino;
};

#define SZ	4096
char buf[SZ];

int main(int argc, char **argv)
{
	int fd, mntfd, bytes;
	char *mnt;
	uint64_t ino;
	struct our_handle handle;

	if (argc < 3) {
		printf("%s <mountpoint> <inode #>\n", argv[0]);
		return 1;
	}

	mnt = argv[1];
	ino = strtoull(argv[2], NULL, 10);

	mntfd = open(mnt, O_RDONLY);
	if (mntfd == -1) {
		perror("while opening mountpoint");
		return 1;
	}

	handle.handle.handle_bytes = sizeof(struct our_handle);
	handle.handle.handle_type = FILEID_SCOUTFS;
	handle.scoutfs_ino = htole64(ino);

	fd = open_by_handle_at(mntfd, &handle.handle, O_RDONLY);
	if (fd == -1) {
		perror("while opening inode by handle");
		return 1;
	}

	while ((bytes = read(fd, buf, SZ)) > 0)
		write(STDOUT_FILENO, buf, bytes);

	close(fd);
	close(mntfd);
	return 0;
}
