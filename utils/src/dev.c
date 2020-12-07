#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>

#include "sparse.h"
#include "dev.h"

int device_size(char *path, int fd,
		u64 min_size, u64 max_size,
		char *use_type, u64 *size_ret)
{
	struct stat st;
	u64 size;
	char *target_type;
	int ret;

	if (fstat(fd, &st)) {
		ret = -errno;
		fprintf(stderr, "failed to stat '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	if (S_ISREG(st.st_mode)) {
		size = st.st_size;
		target_type = "file";
	} else if (S_ISBLK(st.st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &size)) {
			ret = -errno;
			fprintf(stderr, "BLKGETSIZE64 failed '%s': %s (%d)\n",
				path, strerror(errno), errno);
			return ret;
		}
		target_type = "device";
	} else {
		fprintf(stderr, "path isn't regular or device file '%s'\n",
			path);
		return -EINVAL;
	}

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
			BASE_SIZE_FMT" %s too small for min "
			BASE_SIZE_FMT" %s device\n",
			BASE_SIZE_ARGS(size), target_type,
			BASE_SIZE_ARGS(min_size), use_type);
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
