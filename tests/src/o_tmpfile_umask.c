/*
 * Show the modes of files as we create them with O_TMPFILE and link
 * them into the namespace.
 *
 * Copyright (C) 2022 Versity Software, Inc.  All rights reserved.
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
#include <sys/stat.h>
#include <assert.h>
#include <limits.h>

static void linkat_tmpfile_modes(char *dir, char *lpath, mode_t mode)
{
	char proc_self[PATH_MAX];
	struct stat st;
	int ret;
	int fd;

	umask(mode);
	printf("umask 0%o\n", mode);

	fd = open(dir, O_RDWR | O_TMPFILE, 0777);
	if (fd < 0) {
		perror("open(O_TMPFILE)");
		exit(1);
	}

	ret = fstat(fd, &st);
	if (ret < 0) {
		perror("fstat");
		exit(1);
	}

	printf("fstat after open(0777): 0%o\n", st.st_mode);

	snprintf(proc_self, sizeof(proc_self), "/proc/self/fd/%d", fd);

	ret = linkat(AT_FDCWD, proc_self, AT_FDCWD, lpath, AT_SYMLINK_FOLLOW);
	if (ret < 0) {
		perror("linkat");
		exit(1);
	}

	close(fd);

	ret = stat(lpath, &st);
	if (ret < 0) {
		perror("fstat");
		exit(1);
	}

	printf("stat after linkat: 0%o\n", st.st_mode);

	ret = unlink(lpath);
	if (ret < 0) {
		perror("unlink");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	char *lpath;
	char *dir;

	if (argc < 3) {
		printf("%s <open_dir> <linkat_path>\n", argv[0]);
		return 1;
	}

	dir = argv[1];
	lpath = argv[2];

	linkat_tmpfile_modes(dir, lpath, 022);
	linkat_tmpfile_modes(dir, lpath, 077);

	return 0;
}
