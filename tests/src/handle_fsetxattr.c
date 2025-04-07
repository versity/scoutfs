/*
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
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <endian.h>
#include <time.h>
#include <linux/types.h>
#include <sys/xattr.h>

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

#define DEFAULT_NAME "user.handle_fsetxattr"
#define DEFAULT_VALUE "value"

static void exit_usage(void)
{
	printf(" -h/-?         output this usage message and exit\n"
	       " -e            keep trying on enoent and estale, consider success an error\n"
	       " -i <num>      64bit inode number for handle open, can be multiple\n"
	       " -m <string>   scoutfs mount path string for ioctl fd\n"
	       " -n <string>   optional xattr name string, defaults to \""DEFAULT_NAME"\"\n"
	       " -s <num>      loop for num seconds, defaults to 0 for one iteration"
	       " -v <string>   optional xattr value string, defaults to \""DEFAULT_VALUE"\"\n");
	exit(1);
}

int main(int argc, char **argv)
{
	struct our_handle handle;
	struct timespec ts;
	bool enoent_success_err = false;
	uint64_t seconds = 0;
	char *value = NULL;
	char *name = NULL;
	char *mnt = NULL;
	int nr_inos = 0;
	uint64_t *inos;
	uint64_t i;
	int *fds;
	int mntfd;
	int fd;
	int ret;
	char c;
	int j;

	/* can't have more inos than args */
	inos = calloc(argc, sizeof(inos[0]));
	fds = calloc(argc, sizeof(fds[0]));
	if (!inos || !fds) {
		perror("calloc");
		exit(1);
	}
	for (i = 0; i < argc; i++)
		fds[i] = -1;

	while ((c = getopt(argc, argv, "+ei:m:n:s:v:")) != -1) {
		switch (c) {
			case 'e':
				enoent_success_err = true;
				break;
			case 'i':
				inos[nr_inos] = strtoll(optarg, NULL, 0);
				nr_inos++;
				break;
			case 'm':
				mnt = strdup(optarg);
				break;
			case 'n':
				name = strdup(optarg);
				break;
			case 's':
				seconds = strtoll(optarg, NULL, 0);
				break;
			case 'v':
				value = strdup(optarg);
				break;
			case '?':
				printf("unknown argument: %c\n", optind);
			case 'h':
				exit_usage();
		}
	}

	if (nr_inos == 0) {
		printf("specify non-zero inode number with -i\n");
		exit(1);
	}

	if (!mnt) {
		printf("specify scoutfs mount path for ioctl with -p\n");
		exit(1);
	}

	if (name == NULL)
		name = DEFAULT_NAME;
	if (value == NULL)
		value = DEFAULT_VALUE;

	mntfd = open(mnt, O_RDONLY);
	if (mntfd == -1) {
		perror("opening mountpoint");
		return 1;
	}

	clock_gettime(CLOCK_REALTIME, &ts);
	seconds += ts.tv_sec;

	for (i = 0; ; i++) {
		for (j = 0; j < nr_inos; j++) {
			fd = fds[j];

			if (fd < 0) {
				handle.handle.handle_bytes = sizeof(struct our_handle);
				handle.handle.handle_type = FILEID_SCOUTFS;
				handle.scoutfs_ino = htole64(inos[j]);

				fd = open_by_handle_at(mntfd, &handle.handle, O_RDWR);
				if (fd == -1) {
					if (!enoent_success_err || ( errno != ENOENT && errno != ESTALE )) {
						perror("open_by_handle_at");
						return 1;
					}
					continue;
				}
				fds[j] = fd;
			}

			ret = fsetxattr(fd, name, value, strlen(value), 0);
			if (ret < 0) {
				perror("fsetxattr");
				return 1;
			}
		}

		if ((i % 10) == 0) {
			clock_gettime(CLOCK_REALTIME, &ts);
			if (ts.tv_sec >= seconds)
				break;
		}
	}

	if (enoent_success_err) {
		bool able = false;
		for (i = 0; i < nr_inos; i++) {
			if (fds[i] >= 0) {
				printf("was able to open ino %"PRIu64"\n", inos[i]);
				able = true;
			}
		}
		if (able)
			exit(1);
	}

	/* not bothering to close or free */
	return 0;
}
