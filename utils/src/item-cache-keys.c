#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"
#include "key.h"

static int item_cache_keys(int argc, char **argv, int which)
{
	struct scoutfs_ioctl_item_cache_keys ick;
	struct scoutfs_key keys[32];
	int ret;
	int fd;
	int i;

	if (argc != 2) {
		fprintf(stderr, "too many arguments, only scoutfs path needed");
		return -EINVAL;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[1], strerror(errno), errno);
		return ret;
	}

	memset(&ick, 0, sizeof(ick));
	ick.buf_ptr = (unsigned long)keys;
	ick.buf_nr = array_size(keys);
	ick.which = which;

	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_ITEM_CACHE_KEYS, &ick);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "walk_inodes ioctl failed: %s (%d)\n",
				strerror(errno), errno);
			break;
		} else if (ret == 0) {
			break;
		}

		for (i = 0; i < ret; i++) {
			printf(SK_FMT, SK_ARG(&keys[i]));

			if (which == SCOUTFS_IOC_ITEM_CACHE_KEYS_ITEMS ||
			    (i & 1))
				printf("\n");
			else
				printf("  -  ");
		}

		ick.key = keys[i - 1];
		scoutfs_key_inc(&ick.key);
	}

	close(fd);
	return ret;
};

static int item_keys(int argc, char **argv)
{
	return item_cache_keys(argc, argv, SCOUTFS_IOC_ITEM_CACHE_KEYS_ITEMS);
}

static int range_keys(int argc, char **argv)
{
	return item_cache_keys(argc, argv, SCOUTFS_IOC_ITEM_CACHE_KEYS_RANGES);
}

static void __attribute__((constructor)) item_cache_key_ctor(void)
{
	cmd_register("item-cache-keys", "<path>",
		     "print range of indexed inodes", item_keys);
	cmd_register("item-cache-range-keys", "<path>",
		     "print range of indexed inodes", range_keys);
}
