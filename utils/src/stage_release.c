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
#include "ioctl.h"
#include "cmd.h"

static int stage_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_stage args;
	char *endptr = NULL;
	char *buf = NULL;
	int afd = -1;
	int fd = -1;
	u64 offset;
	u64 count;
	u64 vers;
	int ret;

	if (argc != 5) {
		fprintf(stderr, "must specify moar args\n");
		return -EINVAL;
	}

	fd = open(argv[0], O_RDWR);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[0], strerror(errno), errno);
		return ret;
	}

	vers = strtoull(argv[1], &endptr, 0);
	if (*endptr != '\0' ||
	    ((vers == LLONG_MIN || vers == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing data version '%s'\n",
			argv[1]);
		ret = -EINVAL;
		goto out;
	}

	offset = strtoull(argv[2], &endptr, 0);
	if (*endptr != '\0' ||
	    ((offset == LLONG_MIN || offset == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing offset '%s'\n",
			argv[2]);
		ret = -EINVAL;
		goto out;
	}

	count = strtoull(argv[3], &endptr, 0);
	if (*endptr != '\0' ||
	    ((count == LLONG_MIN || count == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing count '%s'\n",
			argv[3]);
		ret = -EINVAL;
		goto out;
	}

	if (count > INT_MAX) {
		fprintf(stderr, "count %llu too large, limited to %d\n",
			count, INT_MAX);
		ret = -EINVAL;
		goto out;
	}

	afd = open(argv[4], O_RDONLY);
	if (afd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[4], strerror(errno), errno);
		goto out;
	}

	buf = malloc(count);
	if (!buf) {
		fprintf(stderr, "couldn't allocate %llu byte buffer\n",
			count);
		ret = -ENOMEM;
		goto out;
	}

	ret = read(afd, buf, count);
	if (ret < count) {
		fprintf(stderr, "archive read returned %d, not %llu: error %s (%d)\n",
			ret, count, strerror(errno), errno);
		ret = -EIO;
		goto out;
	}

	args.data_version = vers;
	args.buf_ptr = (unsigned long)buf;
	args.offset = offset;
	args.count = count;

	ret = ioctl(fd, SCOUTFS_IOC_STAGE, &args);
	if (ret < count) {
		fprintf(stderr, "stage returned %d, not %llu: error %s (%d)\n",
			ret, count, strerror(errno), errno);
		ret = -EIO;
	}
out:
	free(buf);
	if (fd > -1)
		close(fd);
	if (afd > -1)
		close(afd);
	return ret;
};

static void __attribute__((constructor)) stage_ctor(void)
{
	cmd_register("stage", "<file> <vers> <offset> <count> <archive file>",
		     "write archive file contents to offline region", stage_cmd);
}

static int release_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_release args;
	char *endptr = NULL;
	u64 offset;
	u64 count;
	u64 vers;
	int ret;
	int fd;

	if (argc != 4) {
		fprintf(stderr, "must specify path, data version, offset, and count\n");
		return -EINVAL;
	}

	fd = open(argv[0], O_RDWR);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[0], strerror(errno), errno);
		return ret;
	}

	vers = strtoull(argv[1], &endptr, 0);
	if (*endptr != '\0' ||
	    ((vers == LLONG_MIN || vers == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing data version '%s'\n",
			argv[1]);
		ret = -EINVAL;
		goto out;
	}

	offset = strtoull(argv[2], &endptr, 0);
	if (*endptr != '\0' ||
	    ((offset == LLONG_MIN || offset == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing starting offset '%s'\n",
			argv[2]);
		ret = -EINVAL;
		goto out;
	}

	count = strtoull(argv[3], &endptr, 0);
	if (*endptr != '\0' ||
	    ((count == LLONG_MIN || count == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing length '%s'\n",
			argv[3]);
		ret = -EINVAL;
		goto out;
	}

	args.offset = offset;
	args.count = count;
	args.data_version = vers;

	ret = ioctl(fd, SCOUTFS_IOC_RELEASE, &args);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "release ioctl failed: %s (%d)\n",
			strerror(errno), errno);
	}
out:
	close(fd);
	return ret;
};

static void __attribute__((constructor)) release_ctor(void)
{
	cmd_register("release", "<path> <vers> <offset> <count>",
		     "mark file region offline and free extents", release_cmd);
}
