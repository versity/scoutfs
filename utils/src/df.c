#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"

#define ROWS 3
#define COLS 6
#define CHARS 20

static int df_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_alloc_detail ad;
	struct scoutfs_ioctl_alloc_detail_entry *ade = NULL;
	struct scoutfs_ioctl_statfs_more sfm;
	static char cells[ROWS][COLS][CHARS];
	int wid[COLS] = {0};
	u64 nr = 4096 / sizeof(*ade);
	u64 meta_free = 0;
	u64 data_free = 0;
	int ret;
	int fd;
	int i;
	int r;
	int c;

	if (argc != 2) {
		fprintf(stderr, "must specify path\n");
		return -EINVAL;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[1], strerror(errno), errno);
		return ret;
	}

	sfm.valid_bytes = sizeof(struct scoutfs_ioctl_statfs_more);
	ret = ioctl(fd, SCOUTFS_IOC_STATFS_MORE, &sfm);
	if (ret < 0) {
		fprintf(stderr, "statfs_more returned %d: error %s (%d)\n",
			ret, strerror(errno), errno);
		ret = -EIO;
		goto out;
	}

	do {
		free(ade);
		ade = calloc(nr, sizeof(*ade));
		if (!ade) {
			ret = -ENOMEM;
			goto out;
		}

		ad.entries_ptr = (intptr_t)ade;
		ad.entries_nr = nr;
		ret = ioctl(fd, SCOUTFS_IOC_ALLOC_DETAIL, &ad);
		if (ret < 0 && errno == EOVERFLOW)
			nr = nr + (nr >> 2);
	} while (ret < 0 && errno == EOVERFLOW);

	if (ret < 0) {
		fprintf(stderr, "alloc_detail returned %d: error %s (%d)\n",
			ret, strerror(errno), errno);
		ret = -EIO;
		goto out;
	}

	for (i = 0; i < ret; i++) {
		if (ade[i].meta)
			meta_free += ade[i].blocks;
		else
			data_free += ade[i].blocks;
	}

	snprintf(cells[0][0], CHARS, "Type");
	snprintf(cells[0][1], CHARS, "Size");
	snprintf(cells[0][2], CHARS, "Total");
	snprintf(cells[0][3], CHARS, "Used");
	snprintf(cells[0][4], CHARS, "Free");
	snprintf(cells[0][5], CHARS, "Use%%");

	snprintf(cells[1][0], CHARS, "MetaData");
	snprintf(cells[1][1], CHARS, "64KB");
	snprintf(cells[1][2], CHARS, "%llu", sfm.total_meta_blocks);
	snprintf(cells[1][3], CHARS, "%llu", sfm.total_meta_blocks - meta_free);
	snprintf(cells[1][4], CHARS, "%llu", meta_free);
	snprintf(cells[1][5], CHARS, "%llu",
		((sfm.total_meta_blocks - meta_free) * 100) /
		sfm.total_meta_blocks);

	snprintf(cells[2][0], CHARS, "Data");
	snprintf(cells[2][1], CHARS, "4KB");
	snprintf(cells[2][2], CHARS, "%llu", sfm.total_data_blocks);
	snprintf(cells[2][3], CHARS, "%llu", sfm.total_data_blocks - data_free);
	snprintf(cells[2][4], CHARS, "%llu", data_free);
	snprintf(cells[2][5], CHARS, "%llu",
		((sfm.total_data_blocks - data_free) * 100) /
		sfm.total_data_blocks);

	for (r = 0; r < ROWS; r++) {
		for (c = 0; c < COLS; c++) {
			wid[c] = max(wid[c], strlen(cells[r][c]));
		}
	}

	for (r = 0; r < ROWS; r++) {
		for (c = 0; c < COLS; c++) {
			printf("%*s  ", wid[c], cells[r][c]);
		}
		printf("\n");
	}

	ret = 0;
out:
	free(ade);
	return ret;
}

static void __attribute__((constructor)) df_ctor(void)
{
	cmd_register("df", "<path>",
		     "show metadata and data block usage", df_cmd);
}
