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

static int inode_paths_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_inode_paths args;
	char *endptr;
	void *ptr = NULL;
	char *path;
	u64 ino;
	int len;
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

	len = 16 * PATH_MAX;
	do {
		free(ptr);
		ptr = malloc(len);
		if (!ptr) {
			fprintf(stderr, "couldn't allocate %d byte buffer\n",
				len);
			ret = -EINVAL;
			goto out;
		}

		args.ino = ino;
		args.buf_ptr = (intptr_t)ptr;
		args.buf_len = len;

		ret = ioctl(fd, SCOUTFS_IOC_INODE_PATHS, &args);
		if (ret < 0 && errno != EOVERFLOW) {
			ret = -errno;
			fprintf(stderr, "inodes_since ioctl failed: %s (%d)\n",
				strerror(errno), errno);
			goto out;
		}

		len *= 2;

	} while (ret < 0 && errno == EOVERFLOW);

	path = ptr;
	while (*path) {
		printf("%s\n", path);
		path += strlen(path) + 1;
	}

out:
	free(ptr);
	close(fd);
	return ret;
};

static void __attribute__((constructor)) since_ctor(void)
{
	cmd_register("inode-paths", "<ino> <path>",
		     "print paths that refer to inode #", inode_paths_cmd);
}
