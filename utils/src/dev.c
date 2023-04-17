#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>
#include <stdbool.h>

#include "sparse.h"
#include "dev.h"

int get_device_size(char *path, int fd, u64 *size_ret)
{
	struct stat st;
	u64 size;
	int ret;

	if (fstat(fd, &st)) {
		ret = -errno;
		fprintf(stderr, "failed to stat '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	if (S_ISREG(st.st_mode)) {
		size = st.st_size;
	} else if (S_ISBLK(st.st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &size)) {
			ret = -errno;
			fprintf(stderr, "BLKGETSIZE64 failed '%s': %s (%d)\n",
				path, strerror(errno), errno);
			return ret;
		}
	} else {
		fprintf(stderr, "path isn't regular or device file '%s'\n",
			path);
		return -EINVAL;
	}

	*size_ret = size;
	return 0;
}

int limit_device_size(char *path, int fd, u64 min_size, u64 max_size, bool allow_small_size,
		      char *use_type, u64 *size_ret)
{
	u64 size;
	int ret;

	ret = get_device_size(path, fd, &size);
	if (ret < 0)
		return ret;

	if (max_size) {
		if (size > max_size) {
			printf("Limiting use of "BASE_SIZE_FMT
			       " %s device to "BASE_SIZE_FMT"\n",
			       BASE_SIZE_ARGS(size), use_type,
			       BASE_SIZE_ARGS(max_size));
			size = max_size;
		} else if (size < max_size) {
			printf("Device size limit of "BASE_SIZE_FMT
			       " for %s device"
			       " is greater than "BASE_SIZE_FMT
			       " available, ignored.\n",
			       BASE_SIZE_ARGS(max_size), use_type,
			       BASE_SIZE_ARGS(size));
		}
	}

	if (size < min_size) {
		fprintf(stderr,
			BASE_SIZE_FMT" too small for min "
			BASE_SIZE_FMT" %s device%s\n",
			BASE_SIZE_ARGS(size),
			BASE_SIZE_ARGS(min_size), use_type,
			allow_small_size ? ", allowing with -A" : "");

		if (!allow_small_size)
			return -EINVAL;
	}

	*size_ret = size;

	return 0;
}

float size_flt(u64 nr, unsigned size)
{
	float x = (float)nr * (float)size;

	while (x >= 1024)
		x /= 1024;

	return x;
}

char *size_str(u64 nr, unsigned size)
{
	float x = (float)nr * (float)size;
	static char *suffixes[] = {
		"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB",
	};
	int i = 0;

	while (x >= 1024) {
		x /= 1024;
		i++;
	}

	return suffixes[i];
}

/*
 * Try to flush the local read cache for a device.  This is only a best
 * effort as these interfaces don't block waiting to fully purge the
 * cache.  This is OK because it's used by cached readers that are known
 * to be racy anyway.
 */
int flush_device(int fd)
{
	struct stat st;
	int ret;

	ret = fstat(fd, &st);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "fstat failed: %s (%d)\n", strerror(errno), errno);
		goto out;
	}

	if (S_ISREG(st.st_mode)) {
		ret = posix_fadvise(fd, 0, st.st_size, POSIX_FADV_DONTNEED);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "POSIX_FADV_DONTNEED failed: %s (%d)\n",
				strerror(errno), errno);
			goto out;
		}

	} else if (S_ISBLK(st.st_mode)) {
		ret = ioctl(fd, BLKFLSBUF, 0);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "BLKFLSBUF, failed: %s (%d)\n", strerror(errno), errno);
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}
