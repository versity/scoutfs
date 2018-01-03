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

static int ino_path_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_ino_path args;
	struct scoutfs_ioctl_ino_path_result *res;
	unsigned int result_bytes;
	char *endptr = NULL;
	u64 ino;
	int ret;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "must specify ino and path\n");
		return -EINVAL;
	}

	ino = strtoull(argv[1], &endptr, 0);
	if (*endptr != '\0' ||
	    ((ino == LLONG_MIN || ino == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing inode number '%s'\n",
			argv[1]);
		return -EINVAL;
	}


	fd = open(argv[2], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[2], strerror(errno), errno);
		return ret;
	}

	result_bytes = offsetof(struct scoutfs_ioctl_ino_path_result,
				path[PATH_MAX]);
	res = malloc(result_bytes);
	if (!res) {
		fprintf(stderr, "couldn't allocate %u byte buffer\n",
			result_bytes);
		ret = -ENOMEM;
		goto out;
	}

	args.ino = ino;
	args.dir_ino = 0;
	args.dir_pos = 0;
	args.result_ptr = (intptr_t)res;
	args.result_bytes = result_bytes;
	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_INO_PATH, &args);
		if (ret < 0) {
			ret = -errno;
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		printf("%.*s\n", res->path_bytes, res->path);

		args.dir_ino = res->dir_ino;
		args.dir_pos = res->dir_pos;
		if (++args.dir_pos == 0) {
			if (++args.dir_ino == 0)
				break;
		}
	}

	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "inodes_since ioctl failed: %s (%d)\n",
			strerror(errno), errno);
	}
out:
	free(res);
	close(fd);
	return ret;
};

static void __attribute__((constructor)) ino_path_ctor(void)
{
	cmd_register("ino-path", "<ino> <path>",
		     "print paths that refer to inode #", ino_path_cmd);
}
