/*
 * Copyright (C) 2023 Versity Software, Inc.  All rights reserved.
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

static void linkat_tmpfile(char *dir, char *lpath)
{
	char proc_self[PATH_MAX];
	int ret;
	int fd;

	fd = open(dir, O_RDWR | O_TMPFILE, 0777);
	if (fd < 0) {
		perror("open(O_TMPFILE)");
		exit(1);
	}

	snprintf(proc_self, sizeof(proc_self), "/proc/self/fd/%d", fd);

	ret = linkat(AT_FDCWD, proc_self, AT_FDCWD, lpath, AT_SYMLINK_FOLLOW);
	if (ret < 0) {
		perror("linkat");
		exit(1);
	}

	close(fd);
}

/*
 * Use O_TMPFILE and linkat to create a new visible file, used to test
 * the O_TMPFILE creation path by inspecting the created file.
 */
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

	linkat_tmpfile(dir, lpath);

	return 0;
}
