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

#define COLS 8

static int df_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_alloc_detail ad;
	struct scoutfs_ioctl_alloc_detail_entry *ade = NULL;
	struct scoutfs_ioctl_statfs_more sfm;
	char *title[COLS];
	u64 fields[COLS];
	int wid[COLS];
	u64 nr = 4096 / sizeof(*ade);
	u64 meta_free = 0;
	u64 data_free = 0;
	int ret;
	int fd;
	int i;

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

	title[0] = "64K-Meta";
	title[1] = "Used";
	title[2] = "Avail";
	title[3] = "Use%";
	title[4] = "4K-Data";
	title[5] = "Used";
	title[6] = "Avail";
	title[7] = "Use%";

	fields[0] = sfm.total_meta_blocks;
	fields[1] = sfm.total_meta_blocks - meta_free;
	fields[2] = meta_free;
	fields[3] = fields[1] * 100 / fields[0];
	fields[4] = sfm.total_data_blocks;
	fields[5] = sfm.total_data_blocks - data_free;
	fields[6] = data_free;
	fields[7] = fields[5] * 100 / fields[4];

	for (i = 0; i < array_size(fields); i++)
		wid[i] = max(snprintf(NULL, 0, "%s", title[i]),
			     snprintf(NULL, 0, "%llu", fields[i]));

	for (i = 0; i < array_size(fields); i++)
		printf("%*s  ", wid[i], title[i]);
	printf("\n");
	for (i = 0; i < array_size(fields); i++)
		wid[i] = printf("%*llu  ", wid[i], fields[i]);
	printf("\n");

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
