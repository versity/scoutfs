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

/*
 * There are significant constant costs to each search call, we
 * want to get the inodes in as few calls as possible.
 */
#define BATCH_SIZE 1000000

static int search_xattrs_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_search_xattrs sx;
	char *path = NULL;
	char *name = NULL;
	u64 *inos = NULL;
	int fd = -1;
	int ret;
	int c;
	int i;

	memset(&sx, 0, sizeof(sx));
	inos = malloc(BATCH_SIZE * sizeof(inos[0]));
	if (!inos) {
		fprintf(stderr, "inos mem alloc failed\n");
		ret = -ENOMEM;
		goto out;
	}

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

	if (name == NULL) {
		fprintf(stderr, "must specify -n xattr name to search for\n");
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

	sx.next_ino = 0;
	sx.last_ino = U64_MAX;
	sx.name_ptr = (unsigned long)name;
	sx.inodes_ptr = (unsigned long)inos;
	sx.name_bytes = strlen(name);
	sx.nr_inodes = BATCH_SIZE;

	do {
		ret = ioctl(fd, SCOUTFS_IOC_SEARCH_XATTRS, &sx);
		if (ret == 0)
			break;
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "search_xattrs ioctl failed: "
				"%s (%d)\n", strerror(errno), errno);
			goto out;
		}

		for (i = 0; i < ret; i++)
			printf("%llu\n", inos[i]);

		sx.next_ino = inos[ret - 1] + 1;
	} while (!(sx.output_flags & SCOUTFS_SEARCH_XATTRS_OFLAG_END));

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(path);
	free(name);
	free(inos);

	return ret;
};

static void __attribute__((constructor)) search_xattrs_ctor(void)
{
	cmd_register("search-xattrs", "-n name -f <path>",
		     "print inode numbers of inodes which may have given xattr",
		     search_xattrs_cmd);
}
