#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <argp.h>

#include "sparse.h"
#include "parse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"
#include "dev.h"

#define ROWS 3
#define COLS 6
#define CHARS 20

struct df_args {
	char *path;
	bool human_readable;
};

static int do_df(struct df_args *args)
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

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

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

	if (meta_free >= sfm.reserved_meta_blocks)
		meta_free -= sfm.reserved_meta_blocks;
	else
		meta_free = 0;

	snprintf(cells[0][0], CHARS, "Type");
	snprintf(cells[0][1], CHARS, "Size");
	snprintf(cells[0][2], CHARS, "Total");
	snprintf(cells[0][3], CHARS, "Used");
	snprintf(cells[0][4], CHARS, "Free");
	snprintf(cells[0][5], CHARS, "Use%%");

	snprintf(cells[1][0], CHARS, "MetaData");
	snprintf(cells[1][1], CHARS, "64KB");
	if (args->human_readable) {
		snprintf(cells[1][2], CHARS, BASE_SIZE_FMT,
			 BASE_SIZE_ARGS(sfm.total_meta_blocks * SCOUTFS_BLOCK_LG_SIZE));
		snprintf(cells[1][3], CHARS, BASE_SIZE_FMT,
			 BASE_SIZE_ARGS((sfm.total_meta_blocks - meta_free)
					* SCOUTFS_BLOCK_LG_SIZE));
		snprintf(cells[1][4], CHARS, BASE_SIZE_FMT,
			 BASE_SIZE_ARGS(meta_free * SCOUTFS_BLOCK_LG_SIZE));
	} else {
		snprintf(cells[1][2], CHARS, "%llu", sfm.total_meta_blocks);
		snprintf(cells[1][3], CHARS, "%llu", sfm.total_meta_blocks - meta_free);
		snprintf(cells[1][4], CHARS, "%llu", meta_free);
	}
	snprintf(cells[1][5], CHARS, "%llu",
		((sfm.total_meta_blocks - meta_free) * 100) /
		sfm.total_meta_blocks);

	snprintf(cells[2][0], CHARS, "Data");
	snprintf(cells[2][1], CHARS, "4KB");
	if (args->human_readable) {
		snprintf(cells[2][2], CHARS, BASE_SIZE_FMT,
			 BASE_SIZE_ARGS(sfm.total_data_blocks * SCOUTFS_BLOCK_SM_SIZE));
		snprintf(cells[2][3], CHARS, BASE_SIZE_FMT,
			 BASE_SIZE_ARGS((sfm.total_data_blocks - data_free)
					* SCOUTFS_BLOCK_SM_SIZE));
		snprintf(cells[2][4], CHARS, BASE_SIZE_FMT,
			 BASE_SIZE_ARGS(data_free * SCOUTFS_BLOCK_SM_SIZE));
	} else {
		snprintf(cells[2][2], CHARS, "%llu", sfm.total_data_blocks);
		snprintf(cells[2][3], CHARS, "%llu", sfm.total_data_blocks - data_free);
		snprintf(cells[2][4], CHARS, "%llu", data_free);
	}
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

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct df_args *args = state->input;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case 'h':
		args->human_readable = true;
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "human-readable", 'h', NULL, 0, "Print sizes in human readable format (e.g., 1KB 234MB 2GB)"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"",
	"Show metadata and data block usage"
};

static int df_cmd(int argc, char **argv)
{
	struct df_args df_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &df_args);
	if (ret)
		return ret;

	return do_df(&df_args);

}

static void __attribute__((constructor)) df_ctor(void)
{
	cmd_register_argp("df", &argp, GROUP_CORE, df_cmd);
}
