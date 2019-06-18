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

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"

static struct option long_ops[] = {
	{ "name", 1, NULL, 'n' },
	{ "file", 1, NULL, 'f' },
	{ NULL, 0, NULL, 0}
};

static int find_xattrs_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_find_xattrs fx;
	char *path = NULL;
	char *name = NULL;
	u64 inos[32];
	int fd = -1;
	int ret;
	int c;
	int i;

	memset(&fx, 0, sizeof(fx));

	while ((c = getopt_long(argc, argv, "f:n:", long_ops, NULL)) != -1) {
		switch (c) {
		case 'f':
			path = strdup(optarg);
			if (!path) {
				fprintf(stderr, "path mem alloc failed\n");
				ret = -ENOMEM;
				goto out;
			}
			break;
		case 'n':
			name = strdup(optarg);
			if (!name) {
				fprintf(stderr, "name mem alloc failed\n");
				ret = -ENOMEM;
				goto out;
			}
			break;
		case '?':
		default:
			ret = -EINVAL;
			goto out;
		}
	}

	if (path == NULL) {
		fprintf(stderr, "must specify -f path to file\n");
		ret = -EINVAL;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	fx.next_ino = 0;
	fx.name_ptr = (unsigned long)name;
	fx.inodes_ptr = (unsigned long)inos;
	fx.name_bytes = strlen(name);
	fx.nr_inodes = array_size(inos);

	for (;;) {

		ret = ioctl(fd, SCOUTFS_IOC_FIND_XATTRS, &fx);
		if (ret == 0)
			break;
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "find_xattrs ioctl failed: "
				"%s (%d)\n", strerror(errno), errno);
			goto out;
		}

		for (i = 0; i < ret; i++)
			printf("%llu\n", inos[i]);

		fx.next_ino = inos[ret - 1] + 1;
		if (fx.next_ino == 0)
			break;
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(path);
	free(name);

	return ret;
};

static void __attribute__((constructor)) find_xattrs_ctor(void)
{
	cmd_register("find-xattrs", "-n name -f <path>",
		     "print inode numbers of inodes which may have given xattr",
		     find_xattrs_cmd);
}
