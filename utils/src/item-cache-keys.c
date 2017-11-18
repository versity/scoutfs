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

#define BUF_SIZE (64 * 1024)

static int item_cache_keys(int argc, char **argv, int which)
{
	struct scoutfs_ioctl_item_cache_keys ick;
	unsigned nr;
	u16 key_len;
	void *buf;
	void *ptr;
	int ret;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "too many arguments, only scoutfs path needed");
		return -EINVAL;
	}

	buf = malloc(BUF_SIZE);
	if (!buf) {
		ret = -errno;
		fprintf(stderr, "failed to allocate buf: %s (%d)\n",
			strerror(errno), errno);
		return ret;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[1], strerror(errno), errno);
		free(buf);
		return ret;
	}

	ick.buf_ptr = (unsigned long)buf;
	ick.buf_len = BUF_SIZE;
	ick.key_ptr = 0;
	ick.key_len = 0;
	ick.which = which;

	nr = 1;
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

		ptr = (void *)(unsigned long)ick.buf_ptr;

		while (ret) {
			if (ret < sizeof(key_len)) {
				fprintf(stderr, "truncated len: %d\n", ret);
				ret = -EINVAL;
				break;
			}

			memcpy(&key_len, ptr, sizeof(key_len));
			ptr += sizeof(key_len);
			ret -= sizeof(key_len);

			if (ret < key_len) {
				fprintf(stderr, "key len %d  < buffer %d\n",
						key_len, ret);
				ret = -EINVAL;
				break;
			}

			print_key(ptr, key_len);
			if (which == SCOUTFS_IOC_ITEM_CACHE_KEYS_ITEMS ||
			    (nr % 2) == 0)
				printf("\n");
			else
				printf("  -  ");

			ick.key_ptr = (unsigned long)ptr;
			ick.key_len = key_len;

			ptr += key_len;
			ret -= key_len;

			nr++;
		}
		if (ret < 0)
			break;
	}

	close(fd);
	free(buf);
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
