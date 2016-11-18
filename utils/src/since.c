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

static int since_cmd(int argc, char **argv, unsigned long ioc)
{
	struct scoutfs_ioctl_inodes_since args;
	struct scoutfs_ioctl_ino_seq *iseq;
	int len = 4 * 1024 * 1024;
	char *endptr;
	u64 nrs[3];
	void *ptr;
	int ret;
	int fd;
	u64 n;
	int i;

	if (argc != 4) {
		fprintf(stderr, "must specify seq and path\n");
		return -EINVAL;
	}

	for (i = 0; i < array_size(nrs); i++) {
		n = strtoull(argv[i], &endptr, 0);
		if (*endptr != '\0' ||
		    ((n == LLONG_MIN || n == LLONG_MAX) && errno == ERANGE)) {
			fprintf(stderr, "error parsing 64bit value '%s'\n",
			        argv[i]);
			return -EINVAL;
		}
		nrs[i] = n;
	}

	fd = open(argv[3], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[3], strerror(errno), errno);
		return ret;
	}

	ptr = malloc(len);
	if (!ptr) {
		fprintf(stderr, "must specify seq and path\n");
		close(fd);
		return -EINVAL;
	}

	args.first_ino = nrs[0];
	args.last_ino = nrs[1];
	args.seq = nrs[2];
	args.buf_ptr = (intptr_t)ptr;
	args.buf_len = len;

	ret = ioctl(fd, ioc, &args);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "inodes_since ioctl failed: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	n = ret / sizeof(*iseq);
	for (i = 0, iseq = ptr; i < n; i++, iseq++)
		printf("ino %llu seq %llu\n", iseq->ino, iseq->seq);

out:
	free(ptr);
	close(fd);
	return ret;
};

static int inodes_since_cmd(int argc, char **argv)
{
	return since_cmd(argc, argv, SCOUTFS_IOC_INODES_SINCE);
}

static int data_since_cmd(int argc, char **argv)
{
	return since_cmd(argc, argv, SCOUTFS_IOC_INODE_DATA_SINCE);
}

static void __attribute__((constructor)) since_ctor(void)
{
	cmd_register("inodes-since", "<first> <last> <seq> <path>",
		     "print inodes modified since seq #", inodes_since_cmd);
	cmd_register("data-since", "<first> <last> <seq> <path>",
		     "print inodes with data blocks modified since seq #", data_since_cmd);
}
