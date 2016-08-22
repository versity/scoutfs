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
#include <stdbool.h>
#include <stdint.h>

#include "sparse.h"
#include "util.h"
#include "ioctl.h"
#include "format.h"
#include "cmd.h"

static int find_xattrs(bool find_name, int argc, char **argv)
{
	struct scoutfs_ioctl_find_xattr find;
	char *endptr;
	u64 first;
	u64 last;
	u64 *ino;
	int ret;
	int fd;
	int ioc;
	int count;
	int i;

	if (find_name)
		ioc = SCOUTFS_IOC_FIND_XATTR_NAME;
	else
		ioc = SCOUTFS_IOC_FIND_XATTR_VAL;

	if (argc != 4) {
		fprintf(stderr, "must specify ino range, xattr str, and path\n");
		return -EINVAL;
	}

	first = strtoull(argv[0], &endptr, 0);
	if (*endptr != '\0' ||
	    ((first == LLONG_MIN || first == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing inode number '%s'\n",
			argv[0]);
		return -EINVAL;
	}

	last = strtoull(argv[1], &endptr, 0);
	if (*endptr != '\0' ||
	    ((last == LLONG_MIN || last == LLONG_MAX) && errno == ERANGE)) {
		fprintf(stderr, "error parsing inode number '%s'\n",
			argv[1]);
		return -EINVAL;
	}

	fd = open(argv[3], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[3], strerror(errno), errno);
		return ret;
	}

	count = 256;
	ino = calloc(count, sizeof(*ino));
	if (!ino) {
		fprintf(stderr, "couldn't allocate buffer for results\n");
		ret = -ENOMEM;
		goto out;
	}

	find.first_ino = first;
	find.last_ino = last;
	find.str_ptr = (unsigned long)argv[2];
	find.str_len = strlen(argv[2]);
	find.ino_ptr = (unsigned long)ino;
	find.ino_count = count;

	if (find.str_len > SCOUTFS_MAX_XATTR_LEN) {
		fprintf(stderr, "xattr string len %u > %d\n",
			find.str_len, SCOUTFS_MAX_XATTR_LEN);
		ret = -EINVAL;
		goto out;
	}

	do {
		ret = ioctl(fd, ioc, &find);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "inodes_find_xattr ioctl failed: %s (%d)\n",
				strerror(errno), errno);
			goto out;
		}

		for (i = 0; i < ret; i++) {
			printf("%llu\n", ino[i]);
			find.first_ino = ino[i] + 1;

			if (find.first_ino == 0) {
				ret = 0;
				break;
			}
		}
	} while (ret > 0);

out:
	free(ino);
	close(fd);

	return ret;
};

static int find_xattr_name(int argc, char **argv)
{
	return find_xattrs(true, argc, argv);
}

static int find_xattr_val(int argc, char **argv)
{
	return find_xattrs(false, argc, argv);
}

static void __attribute__((constructor)) find_xattr_ctor(void)
{
	cmd_register("find-xattr-name", "<first> <last> <name> <path>",
		     "print inodes that might contain xattr name",
		     find_xattr_name);
	cmd_register("find-xattr-value", "<first> <last> <value> <path>",
		     "print inodes that might contain xattr value",
		     find_xattr_val);
}
