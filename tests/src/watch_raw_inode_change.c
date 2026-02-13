/*
 * Copyright (C) 2026 Versity Software, Inc.  All rights reserved.
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
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <linux/types.h>
#include <assert.h>
#include <stdbool.h>

#include "../../utils/src/util.h"
#include "ioctl.h"
#include "format.h"

/*
 * This is a quick example of using the raw reading ioctls to get info
 * on inodes as they change.  We maintain an array of meta_seq items for
 * inodes that we've seen.  If we read the current meta_seq items and
 * see differences then we get inode info and update our array with what
 * we find.
 *
 * This only maintains one array and sorts it back and forth as we walk
 * the meta_seq items and then search by inode number.  This will
 * eventually use far too much cpu as the number of inodes increases.
 */

#define MSF		"%llu.%llu"
#define MSA(ms)		(ms)->meta_seq, (ms)->ino
#define NERRF		"nerr %d (\"%s\")"
#define NERRA(nerr)	nerr, strerror(-nerr)

#define prerror(fmt, args...) \
	fprintf(stderr, "error: "fmt"\n", ##args)

#define prdebug(fmt, args...) \
do { \
	if (opts.debug) \
		printf(fmt"\n", ##args); \
} while (0)

static struct opts {
	bool debug;
	char *path;
	char *names;
	size_t names_size;
	size_t names_count;
} opts;

struct stats {
	__u64 start;
	__u64 last;

	struct per_call {
		__u64 begin;
		__u64 calls;
		__u64 time;
		__u64 inos;
	} rms, rii;

	__u64 inodes;
	__u64 add;
	__u64 remove;
	__u64 update;

	unsigned lines;
} stats;

struct meta_seq_array {
	size_t nr;
	size_t alloc;
	struct scoutfs_ioctl_meta_seq *ms;
};

#define INO_BATCH	1000
/* *2 for gratuitous allowance for struct expansion */
#define RESULTS_SIZE	(INO_BATCH * 2 * (sizeof(struct scoutfs_ioctl_raw_read_result) + \
		                          sizeof(__u64) + \
		                          180 /* ~= sizeof(struct scoutfs_inode) */ + \
		                          sizeof(struct scoutfs_ioctl_inode_attr_x)))

#define NSEC_PER_SEC 1000000000

static __u64 get_ns(void)
{
	struct timespec tp;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &tp);
	if (ret != 0) {
		ret = -errno;
		prerror("clock_gettime() error: "NERRF, NERRA(ret));
		exit(2);
	}

	return ((__u64)tp.tv_sec * NSEC_PER_SEC) + (__u64)tp.tv_nsec;
}
static void begin_call(struct per_call *pc)
{
	pc->begin = get_ns();
}

static void end_call(struct per_call *pc)
{
	pc->calls++;
	pc->time += get_ns() - pc->begin;
}

static int expand_array(struct meta_seq_array *arr, size_t additional)
{
#define ALLOC_BATCH	(1024 * 1024 / (sizeof(struct scoutfs_ioctl_meta_seq)))
	struct scoutfs_ioctl_meta_seq *ms;
	size_t expand;

	if (arr->nr + additional <= arr->alloc)
		return 0;

	expand = arr->alloc + ALLOC_BATCH;
	ms = reallocarray(arr->ms, expand, sizeof(arr->ms[0]));
	if (!ms) {
		prerror("allocating ms array with %zu elements failed", expand);
		return -ENOMEM;
	}

	arr->alloc = expand;
	arr->ms = ms;

	return 0;
}

static void inc_ms(struct scoutfs_ioctl_meta_seq *ms)
{
	if (++ms->ino == 0)
		ms->meta_seq++;
}

static void set_ms(struct scoutfs_ioctl_meta_seq *ms, __u64 meta_seq, __u64 ino)
{
	ms->meta_seq = meta_seq;
	ms->ino = ino;
}

static int compar_ms_ino(const void *A, const void *B)
{
	const struct scoutfs_ioctl_meta_seq *a = A;
	const struct scoutfs_ioctl_meta_seq *b = B;

	return a->ino < b->ino ? -1 : a->ino > b->ino ? 1 : 0;
}

static int compar_ms_meta_seq(const void *A, const void *B)
{
	const struct scoutfs_ioctl_meta_seq *a = A;
	const struct scoutfs_ioctl_meta_seq *b = B;

	return a->meta_seq < b->meta_seq ? -1 : a->meta_seq > b->meta_seq ? 1 :
	       compar_ms_ino(A, B);
}

static int compar_u64(const void *A, const void *B)
{
	const __u64 *a = A;
	const __u64 *b = B;

	return *a < *b ? -1 : *a > *b ? 1 : 0;
}

struct bsearch_ind_key {
	int (*compar)(const void *a, const void *b);
	void *key;
	size_t size;
	void **index;
};

static int bsearch_ind_compar(const void *a, const void *b)
{
	const struct bsearch_ind_key *bik = (const void *)((unsigned long)a ^ 1);
	int cmp;

	/* this key hack only works if compar is always called where a is key and b is &base[..] */
	assert((unsigned long)a & 1);
	assert(!((unsigned long)b & 1));

	cmp = bik->compar(bik->key, b);
	if (cmp > 0)
		*(bik->index) = (void *)b + bik->size;
	else
		*(bik->index) = (void *)b;

	return cmp;
}

static size_t bsearch_ind(const void *key, const void *base, size_t nmemb, size_t size,
			  int (*compar)(const void *a, const void *b))
{
	void *index = (void *)base;
	struct bsearch_ind_key bik = {
		.compar = compar,
		.key = (void *)key,
		.size = size,
		.index = &index,
	};

	bsearch((void *)(((unsigned long)&bik) | 1), base, nmemb, size, bsearch_ind_compar);

	return (index - base) / size;
}

/*
 * Generate a sorted list of inode numbers for the meta_seq items that
 * differ between the results from raw_read_meta_seq and the items we
 * have saved in our array. 
 */
static int differing_inos(__u64 *inos, struct meta_seq_array *arr,
			  struct scoutfs_ioctl_meta_seq *start,
			  struct scoutfs_ioctl_meta_seq *last,
			  struct scoutfs_ioctl_meta_seq *ms, size_t nr)
{
	size_t arr_last;
	size_t a;
	size_t m;
	int nr_inos;
	int cmp;
	int i;
	int n;

	/* find where we're going to stop in arr */
	arr_last = bsearch_ind(last, arr->ms, arr->nr, sizeof(arr->ms[0]), compar_ms_meta_seq);
	if (arr_last < arr->nr && compar_ms_meta_seq(&arr->ms[arr_last], last) == 0)
		arr_last++;

	a = bsearch_ind(start, arr->ms, arr->nr, sizeof(arr->ms[0]), compar_ms_meta_seq);

	for (m = 0, nr_inos = 0; (a < arr_last || m < nr) && nr_inos < INO_BATCH; ) {

		prdebug("diffing: m %zu nr %zu | a %zu arr_last %zu | nr_inos %d",
			m, nr, a, arr_last, nr_inos);
		if (a < arr_last)
			prdebug("  arr->ms[%zu] = "MSF, a, MSA(&arr->ms[a]));
		if (m < nr)
			prdebug("  ms[%zu] = "MSF, m, MSA(&ms[m]));

		/* setup comparison to copy lesser or only */
		if (a < arr_last && m < nr)
			cmp = compar_ms_meta_seq(&arr->ms[a], &ms[m]);
		else if (a < arr_last)
			cmp = -1;
		else
			cmp = 1;

		prdebug("  cmp %d", cmp);

		if (cmp == 0) {
			/* ignore both when they match */
			a++;
			m++;
		} else if (cmp < 0) {
			inos[nr_inos++] = arr->ms[a++].ino;
		} else { /* cmp > 0 */
			inos[nr_inos++] = ms[m++].ino;
		}
	}

	/* if we didn't consume all the read meta_seq then we might need to clamp last */
	if (m < nr && compar_ms_meta_seq(&ms[m], last) <= 0) {
		*last = ms[m];
		last->ino--; /* must be non-zero, can't wrap */
	}

	/* sort and remove duplicate inode numbers */
	if (nr_inos > 0) {
		qsort(inos, nr_inos, sizeof(inos[0]), compar_u64);
		for (i = 1, n = 1; i < nr_inos; i++) {
			if (inos[i] != inos[n - 1])
				inos[n++] = inos[i];
		}
		nr_inos = n;
	}

	return nr_inos;
}

/*
 * We're not really validating the result stream.  We assume that the offset currently
 * points at an inode.  We fill the caller's ms with its info then iterate through
 * all its results until the next ino.
 */
static ssize_t read_inode_results(void *buf, size_t off, size_t size,
				  struct scoutfs_ioctl_meta_seq *found)
{
	struct scoutfs_ioctl_raw_read_result res;
	size_t len;
	__le64 ms;

	found->ino = 0;

	while (off < size) {
		memcpy(&res, buf + off, sizeof(res));
		prdebug("res %u %u", res.type, res.size);

		if (res.type == SCOUTFS_IOC_RAW_READ_RESULT_INODE && found->ino != 0)
			break;

		off += sizeof(res);

		switch(res.type) {
			case SCOUTFS_IOC_RAW_READ_RESULT_INODE:
				memcpy(&found->ino, buf + off, sizeof(__u64));
				memcpy(&ms, buf + off + sizeof(__u64) +
				       offsetof(struct scoutfs_inode, meta_seq), sizeof(__le64));
				found->meta_seq = le64_to_cpu(ms);
				prdebug("res ino %llu ms %llu", found->ino, found->meta_seq);
				break;

			case SCOUTFS_IOC_RAW_READ_RESULT_XATTR:
				len = strlen((char *)buf + off) + 1;
				prdebug("res xattr '%s' len %d: '%.*s'",
					(char *)buf + off, 
					(int)(res.size - len),
					(int)(res.size - len),
					(char *)buf + off + len);
				break;
		};
		off += res.size;
	}

	return off;
}

/*
 * inos[] contains the inode numbers that we're interested in.  Get
 * their info and update our array with what we find.
 */
static int read_inode_info(int fd, void *buf, struct meta_seq_array *arr, __u64 *inos, int nr_inos)
{
	struct scoutfs_ioctl_raw_read_inode_info rii;
	struct scoutfs_ioctl_meta_seq found;
	struct scoutfs_ioctl_meta_seq ms;
	ssize_t off;
	size_t size;
	size_t ind;
	size_t added;
	int i;
	int ret;

	rii = (struct scoutfs_ioctl_raw_read_inode_info) {
		.inos_ptr = (unsigned long)inos,
		.inos_count = nr_inos,
		.names_ptr = (unsigned long)opts.names,
		.names_count = opts.names_count,
		.results_ptr = (unsigned long)buf,
		.results_size = RESULTS_SIZE,
	};

	begin_call(&stats.rii);
	ret = ioctl(fd, SCOUTFS_IOC_RAW_READ_INODE_INFO, &rii);
	if (ret < 0) {
		ret = -errno;
		prerror("READ_INODE_INFO ioctl failed: "NERRF, NERRA(ret));
		goto out;
	}
	end_call(&stats.rii);

	prdebug("gii ret %d", ret);

	off = 0;
	size = ret;
	set_ms(&found, 0, 0);
	added = 0;
	i = 0;

	/* sort by ino so we can search by ino for updates */
	qsort(arr->ms, arr->nr, sizeof(arr->ms[0]), compar_ms_ino);

	while (i < nr_inos) {
		/* find next ino */
		if (!found.ino && off < size) {
			off = read_inode_results(buf, off, size, &found);
			if (off < 0) {
				ret = off;
				goto out;
			}
			stats.rii.inos++;
		}

		if (i < nr_inos && (!found.ino || inos[i] < found.ino)) {
			/* delete any record of inodes we didn't find */
			set_ms(&ms, UINT64_MAX, inos[i]);
			i++;

		} else if (found.ino) {
			/* update/add arr to match the found ino */
			ms = found;
			if (i < nr_inos && inos[i] == found.ino)
				i++;
			set_ms(&found, 0, 0);
		}

		/* find existing record */
		ind = bsearch_ind(&ms, arr->ms, arr->nr, sizeof(arr->ms[0]), compar_ms_ino);
		if (ind < arr->nr && arr->ms[ind].ino == ms.ino) {
			/* update existing ino, can be marking for deletion */
			prdebug("updating arr [%zu] ino %llu ms %llu -> %llu",
					ind, ms.ino, arr->ms[ind].meta_seq, ms.meta_seq);
			arr->ms[ind].meta_seq = ms.meta_seq;
			if (ms.meta_seq == UINT64_MAX)
				stats.remove++;
			else
				stats.update++;

		} else if (ms.meta_seq != UINT64_MAX) {
			/* append new found, maintaining existing sorting */
			arr->ms[arr->nr + added] = ms;
			prdebug("adding arr [%zu] ino %llu ms %llu",
					arr->nr + added, ms.ino, ms.meta_seq);
			added++;
			stats.add++;
		}
	}

	/* sort by seq again for next meta seq read */
	arr->nr += added;
	qsort(arr->ms, arr->nr, sizeof(arr->ms[0]), compar_ms_meta_seq);

	/* and trim off any deletions */
	while (arr->nr > 0 && arr->ms[arr->nr - 1].meta_seq == UINT64_MAX)
		arr->nr--;

	ret = 0;
out:
	return ret;
}

static double secs(u64 a_ns, u64 b_ns)
{
	return (double)(a_ns - b_ns) / NSEC_PER_SEC;
}

static double nr_per_sec(u64 nr, __u64 nsec)
{
	if (nsec == 0)
		return 0;

	return (double)nr / secs(nsec, 0);
}

static void print_stats(void)
{
	u64 now = get_ns();

	if (secs(now, stats.last) < 1.0)
		return;

	if ((stats.lines++ % 16) == 0) {
		printf("%6s | %-29s | %-23s | %-23s\n",
			"", "inodes", "meta_seq", "inode_info");
		printf("%6s | %8s %6s %6s %6s | %7s %7s %7s | %7s %7s %7s\n",
			"now",
			"total", "add", "remove", "update",
			"calls", "inos", "inos/s",
			"calls", "inos", "inos/s");
	}

	printf("%6.3lf | %8llu %6llu %6llu %6llu | %7llu %7llu %7.0lf | %7llu %7llu %7.0lf\n",
		secs(now, stats.start),
		stats.inodes, stats.add, stats.remove, stats.update,
		stats.rms.calls, stats.rms.inos, nr_per_sec(stats.rms.inos, stats.rms.time),
		stats.rii.calls, stats.rii.inos, nr_per_sec(stats.rms.inos, stats.rii.time));

	stats.last = now;

	{
		struct stats save = stats;
		stats = (struct stats) {
			.start = save.start,
			.last = save.last,
			.lines = save.lines,
		};
	}
}

static void add_xattr(char *name)
{
	size_t len_null;
	char *names;
	int ret;

	len_null = strlen(name) + 1;
	names = realloc(opts.names, opts.names_size + len_null);
	if (!names) {
		ret = -errno;
		prerror("allocation of xattr names buffer failed: "NERRF, NERRA(ret));
		exit(3);
	}

	memcpy(names + opts.names_size, name, len_null);

	opts.names = names;
	opts.names_size += len_null;
	opts.names_count++;
}

static bool parse_opts(int argc, char **argv)
{
	bool usage = false;
	int c;

	opts = (struct opts) {
		.debug = false,
	};

        while ((c = getopt(argc, argv, "dp:x:")) != -1) {
                switch(c) {
                case 'd':
                        opts.debug = true;
                        break;
                case 'p':
                        opts.path = strdup(optarg);
                        break;
                case 'x':
			add_xattr(optarg);
                        break;
                case '?':
                        printf("Unknown option '%c'\n", optopt);
			usage = true;
                }
	}

	if (!usage) {
		usage = true;
		if (!opts.path)
			printf("need -p path option\n");
		else
			usage = false;
	}

	if (usage) {
		printf("\nusage:\n"
		       " -d      | enable verbose debugging output\n"
		       " -p PATH | path to file system to watch\n"
		       " -x NAME | try to read named xattr with inodes, can be many\n"
		      );
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	struct scoutfs_ioctl_raw_read_meta_seq rms = {0,};
	struct scoutfs_ioctl_meta_seq *ms;
	struct meta_seq_array arr = {0,};
	__u64 *inos = NULL;
	void *buf = NULL;
	int fd = -1;
	int nr_inos;
	int nr;
	int i;
	int ret;

	if (!parse_opts(argc, argv))
		exit(1);

	inos = calloc(INO_BATCH, sizeof(inos[0]));
	buf = malloc(RESULTS_SIZE);
	if (!inos || !buf) {
		ret = -ENOMEM;
		goto out;
	}

	rms.results_ptr = (unsigned long)buf;
	rms.results_size = min(RESULTS_SIZE, INO_BATCH * sizeof(struct scoutfs_ioctl_meta_seq));

	fd = open(opts.path, O_RDONLY);
	if (fd == -1) {
		perror("error");
		exit(1);
	}

	stats.start = get_ns();

	for (;;) {
		set_ms(&rms.start, 0, 0);
		set_ms(&rms.end, UINT64_MAX, UINT64_MAX);

		do {
			begin_call(&stats.rms);
			ret = ioctl(fd, SCOUTFS_IOC_RAW_READ_META_SEQ, &rms);
			if (ret < 0) {
				ret = -errno;
				prerror("READ_META_SEQ ioctl failed, "
					"start "MSF" end "MSF", "NERRF,
					MSA(&rms.start), MSA(&rms.end), NERRA(ret));
				goto out;
			}
			end_call(&stats.rms);
			stats.rms.inos += ret;

			prdebug("RMS last "MSF" ret %d:", MSA(&rms.last), ret);

			nr = ret;
			ms = buf;

			if (opts.debug && nr > 0) {
				for (i = 0; i < nr; i++)
					prdebug(" [%u] "MSF"", i, MSA(&ms[i]));
			}

			nr_inos = differing_inos(inos, &arr, &rms.start, &rms.last, ms, nr);

			if (nr_inos > 0) {
				prdebug("diff inos %d:", nr_inos);
				for (i = 0; i < nr_inos; i++)
					prdebug(" [%u] %llu", i, inos[i]);

				ret = expand_array(&arr, nr_inos) ?:
				      read_inode_info(fd, buf, &arr, inos, nr_inos);
				if (ret < 0)
					goto out;
			}

			stats.inodes = arr.nr;
			print_stats();

			rms.start = rms.last;
			inc_ms(&rms.start);

		} while (rms.last.meta_seq != UINT64_MAX || rms.last.ino != UINT64_MAX);


		sleep(1);
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);

	free(inos);
	free(buf);
	free(arr.ms);
	free(opts.names);

	return ret;
}
