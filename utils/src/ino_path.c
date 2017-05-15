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
	char *endptr = NULL;
	char *path = NULL;
	char *curs = NULL;
	u64 ino;
	int ret;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "must specify ino and path\n");
		return -EINVAL;
	}

	ino = strtoull(argv[0], &endptr, 0);
	if (*endptr != '\0' ||
	    ((ino == LLONG_MIN || ino == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing inode number '%s'\n",
			argv[0]);
		return -EINVAL;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[1], strerror(errno), errno);
		return ret;
	}

	path = malloc(PATH_MAX);
	if (!path) {
		fprintf(stderr, "couldn't allocate %d byte buffer\n", PATH_MAX);
		ret = -ENOMEM;
		goto out;
	}

	curs = calloc(1, SCOUTFS_IOC_INO_PATH_CURSOR_BYTES);
	if (!curs) {
		fprintf(stderr, "couldn't allocate %ld byte cursor\n",
			SCOUTFS_IOC_INO_PATH_CURSOR_BYTES);
		ret = -ENOMEM;
		goto out;
	}

	args.ino = ino;
	args.cursor_ptr = (intptr_t)curs;
	args.path_ptr = (intptr_t)path;
	args.cursor_bytes = SCOUTFS_IOC_INO_PATH_CURSOR_BYTES;
	args.path_bytes = PATH_MAX;
	do {
		ret = ioctl(fd, SCOUTFS_IOC_INO_PATH, &args);
		if (ret > 0)
			printf("%s\n", path);
	} while (ret > 0);

	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "inodes_since ioctl failed: %s (%d)\n",
			strerror(errno), errno);
	}
out:
	free(path);
	free(curs);
	close(fd);
	return ret;
};

static void __attribute__((constructor)) ino_path_ctor(void)
{
	cmd_register("ino-path", "<ino> <path>",
		     "print paths that refer to inode #", ino_path_cmd);
}
