
/*
 * Copyright (C) 2025 Versity Software, Inc.  All rights reserved.
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "ioctl.h"

#define array_size(arr) (sizeof(arr) / sizeof(arr[0]))

#define FILEID_SCOUTFS			0x81
#define FILEID_SCOUTFS_WITH_PARENT	0x82

static uint64_t meta_seq = 0;
static bool sig_received = false;
static bool tracing_on = false;
static bool exit_on_current = false;
static bool exiting = false;
static uint64_t count = 0;

struct our_handle {
	struct file_handle handle;
	/*
	 * scoutfs file handle can be ino or ino/parent. The
	 * handle_type field of struct file_handle denotes which
	 * version is in use. We only use the ino variant here.
	 */
	__le64 scoutfs_ino;
};

static void exit_usage(void)
{
	printf(
		" -e            exit once stable meta_seq has been reached\n"
		" -m <string>   scoutfs mount path string for seq walk\n"
		" -s <number>   start from meta_seq number, instead of 0\n"
		);
	exit(1);
}

static int write_at(int tracefd, char *path, char *val)
{
	int fd = -1;
	int ret;

	fd = openat(tracefd, path, O_TRUNC | O_RDWR);
	if (fd < 0)
		return errno;
	ret = write(fd, val, strlen(val));
	if (ret < 0)
		ret = errno;

	close(fd);
	return 0;
}

static int do_trace(int fd, uint64_t ino)
{
	struct our_handle handle;
	int tracefd = -1;
	int targetfd = -1;
	int outfd = -1;
	int infd = -1;
	char *pidstr;
	char *name;
	char *buf;
	ssize_t bytes;
	ssize_t written;
	ssize_t off = 0;
	unsigned long e = 0;
	int ret;

	if (asprintf(&pidstr, "%u", getpid()) < 0)
		return ENOMEM;

	if (asprintf(&name, "trace.scoutfs.open_by_handle_at.ino-%lu", ino) < 0)
		return ENOMEM;

	buf = malloc(4096);
	if (!buf)
		return ENOMEM;

	handle.handle.handle_bytes = sizeof(struct our_handle);
	handle.handle.handle_type = FILEID_SCOUTFS;
	handle.scoutfs_ino = htole64(ino);

	/* keep a quick dirfd around for easy writing sysfs files */
	tracefd = open("/sys/kernel/debug/tracing", 0);
	if (tracefd < 0)
		return errno;

	/* start tracing */
	ret = write_at(tracefd, "current_tracer", "nop") ?:
	      write_at(tracefd, "current_tracer", "function_graph") ?:
	      write_at(tracefd, "set_ftrace_pid", pidstr) ?:
	      write_at(tracefd, "tracing_on", "1");

	tracing_on = true;

	if (ret)
		goto out;

	targetfd = open_by_handle_at(fd, &handle.handle, O_RDWR);
	e = errno;

out:
	/* turn off tracing first */
	ret = write_at(tracefd, "tracing_on", "0");
	if (ret)
		return ret;

	tracing_on = false;

	if (targetfd != -1) {
		close(targetfd);
		return 0;
	}

	if (e == ESTALE) {
		/* capture trace */
		outfd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
		if (outfd < 0) {
			fprintf(stderr, "Error opening trace\n");
			return errno;
		}
		infd = openat(tracefd, "trace", O_RDONLY);
		if (infd < 0) {
			fprintf(stderr, "Error opening trace output\n");
			return errno;
		}
		for (;;) {
			bytes = pread(infd, buf, 4096, off);
			if (bytes < 0)
				return errno;
			if (bytes == 0)
				break;
			written = pwrite(outfd, buf, bytes, off);
			if (written < 0)
				return errno;
			if (written != bytes)
				return EIO;
			off += bytes;
		}
		close(outfd);
		close(infd);

		fprintf(stderr, "Wrote \"%s\"\n", name);
	}

	/* cleanup */
	ret = write_at(tracefd, "current_tracer", "nop");

	free(pidstr);
	free(name);
	free(buf);
	close(tracefd);
	/* collect trace output */
	return ret;
}

/*
 * lookup path for ino using ino_path
 */
struct ino_args {
	char *path;
	__u64 ino;
};

static int do_resolve(int fd, uint64_t ino, char **path)
{
	struct scoutfs_ioctl_ino_path ioctl_args = {0};
	struct scoutfs_ioctl_ino_path_result *res;
	unsigned int result_bytes;
	int ret;

	result_bytes = offsetof(struct scoutfs_ioctl_ino_path_result,
				path[PATH_MAX]);

	res = malloc(result_bytes);
	if (!res)
		return ENOMEM;

	ioctl_args.ino = ino;
	ioctl_args.dir_ino = 0;
	ioctl_args.dir_pos = 0;
	ioctl_args.result_ptr = (intptr_t)res;
	ioctl_args.result_bytes = result_bytes;

	ret = ioctl(fd, SCOUTFS_IOC_INO_PATH, &ioctl_args);
	if (ret < 0) {
		if (errno == ENOENT) {
			*path = NULL;
			return 0;
		}
		return errno;
	}

	ret = asprintf(path, "%.*s", res->path_bytes, res->path);
	if (ret <= 0)
		return ENOMEM;

	free(res);

	return 0;
}

static int do_test_ino(int fd, uint64_t ino)
{
	struct our_handle handle = {{0}};
	struct stat sb = {0};
	char *path = NULL;
	int targetfd = -1;
	int ret;

	/* filter: open_by_handle_at() must fail */
	handle.handle.handle_bytes = sizeof(struct our_handle);
	handle.handle.handle_type = FILEID_SCOUTFS;
	handle.scoutfs_ino = htole64(ino);

	targetfd = open_by_handle_at(fd, &handle.handle, O_RDWR);
	if (targetfd != -1) {
		close(targetfd);
		return 0;
	}

	/* filter: errno must be ESTALE */
	if (errno != ESTALE)
		return 0;

	/* filter: path resolution succeeds to an actual file entry */
	ret = do_resolve(fd, ino, &path);
	if (path == NULL)
		return 0;
	if (ret)
		return ret;

	/* filter: stat() must succeed on resolved path */
	ret = fstatat(fd, path, &sb, AT_SYMLINK_NOFOLLOW);
	free(path);
	if (ret != 0) {
		if (errno == ENOENT)
			/* doesn't exist */
			return 0;
		return errno;
	}

	return do_trace(fd, ino);
}

static uint64_t do_get_meta_seq_stable(int fd)
{
	struct scoutfs_ioctl_stat_more stm;

	if (ioctl(fd, SCOUTFS_IOC_STAT_MORE, &stm) < 0)
		return errno;

	return stm.meta_seq;
}

static int do_walk_seq(int fd)
{
	struct scoutfs_ioctl_walk_inodes_entry ents[128];
	struct scoutfs_ioctl_walk_inodes walk = {{0}};
	struct timespec ts;
	time_t seconds;
	int ret;
	uint64_t total = 0;
	uint64_t stable;
	int i;
	int j;

	walk.index = SCOUTFS_IOC_WALK_INODES_META_SEQ;

	/* make sure not to advance to stable meta_seq, we can just trail behind */
	stable = do_get_meta_seq_stable(fd);
	if (stable == 0)
		return 0;
	if (meta_seq >= stable - 1) {
		if (exit_on_current)
			exiting = true;
		return 0;
	}

	meta_seq = meta_seq ? meta_seq + 1 : 0;

	walk.first.major = meta_seq;
	walk.first.minor = 0;
	walk.first.ino = 0;

	walk.last.major = stable - 1;
	walk.last.minor = ~0;
	walk.last.ino = ~0ULL;

	walk.entries_ptr = (unsigned long)ents;
	walk.nr_entries = array_size(ents);

	clock_gettime(CLOCK_REALTIME, &ts);
	seconds = ts.tv_sec;

	for (j = 0;; j++) {
		if (sig_received)
			return 0;

		ret = ioctl(fd, SCOUTFS_IOC_WALK_INODES, &walk);
		if (ret < 0)
			return ret;

		if (ret == 0)
			break;

		for (i = 0; i < ret; i++) {
			meta_seq = ents[i].major;
			if (ents[i].ino == 1)
				continue;

			/* poke at it */
			ret = do_test_ino(fd, ents[i].ino);

			count++;

			if (ret < 0)
				return ret;
		}

		total += i;

		walk.first = ents[i - 1];
		if (++walk.first.ino == 0 && ++walk.first.minor == 0)
			walk.first.major++;

		/* yield once in a while */
		if (j % 32 == 0) {
			clock_gettime(CLOCK_REALTIME, &ts);
			if (ts.tv_sec > seconds + 1)
				break;
		}
	}

	return 0;
}

void handle_signal(int sig)
{
	int tracefd = -1;

	sig_received = true;

	if (!tracing_on)
		return;

	tracefd = open("/sys/kernel/debug/tracing", 0);
	write_at(tracefd, "tracing_on", "0");
	close(tracefd);
}

int main(int argc, char **argv)
{
	char *mnt = NULL;
	char c;
	int mntfd;
	int ret;

	meta_seq = 0;

	/* All we need is the mount point arg */
	while ((c = getopt(argc, argv, "+em:s:")) != -1) {
		switch (c) {
			case 'e':
				exit_on_current = true;
				break;
			case 'm':
				mnt = strdup(optarg);
				break;
			case 's':
				meta_seq = strtoull(optarg, NULL, 0);
				break;
			case '?':
				printf("unknown argument: %c\n", optind);
			case 'h':
				exit_usage();
		}
	}

	if (!mnt) {
		fprintf(stderr, "Must provide a mount point with -m\n");
		exit(EXIT_FAILURE);
	}

	if (meta_seq > 0)
		fprintf(stdout, "Starting from meta_seq = %lu\n", meta_seq);

	/* lower prio */
	ret = nice(10);
	if (ret == -1)
		fprintf(stderr, "Error setting nice value\n");
	ret = syscall(SYS_ioprio_set, 1, 0, 0); /* IOPRIO_WHO_PROCESS = 1, IOPRIO_PRIO_CLASS(IOPRIO_CLASS_IDLE) = 0 */
	if (ret == -1)
		fprintf(stderr, "Error setting ioprio value\n");

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	for (;;) {
		if (sig_received)
			break;

		mntfd = open(mnt, O_RDONLY);
		if (mntfd == -1) {
			perror("open(mntfd)");
			exit(EXIT_FAILURE);
		}

		ret = do_walk_seq(mntfd);
		/* handle unmounts? EAGAIN? */
		if (ret)
			break;

		close(mntfd);

		if (exiting)
			break;

		/* yield */
		if (!sig_received)
			sleep(5);
	}

	free(mnt);

	fprintf(stdout, "Last meta_seq = %lu\n", meta_seq);

	if (ret)
		fprintf(stderr, "Error walking inodes: %s(%d)\n", strerror(errno), ret);

	exit(ret);
}
