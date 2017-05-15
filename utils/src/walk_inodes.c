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

/*
 * Parse the command line specification of a walk inodes entry of the
 * form "major.minor.ino".  At least one value must be given, the rest
 * default to 0.
 */
static int parse_walk_entry(struct scoutfs_ioctl_walk_inodes_entry *ent,
			    char *str)
{
	char *endptr;
	char *c;
	u64 ull;
	u64 minor;
	u64 *val;

	memset(ent, 0, sizeof(*ent));
	val = &ent->major;

	for (;;) {
		c = index(str, '.');
		if (c)
			*c = '\0';

		endptr = NULL;
		ull = strtoull(str, &endptr, 0);
		if (*endptr != '\0' ||
		    ((ull == LLONG_MIN || ull == LLONG_MAX) &&
		     errno == ERANGE) ||
		    (val == &minor && (*val < INT_MIN || *val > INT_MAX))) {
			fprintf(stderr, "bad index pos at '%s'\n", str);
			return -EINVAL;
		}

		*val = ull;

		if (val == &ent->major)
			val = &minor;
		else if (val == &minor)
			val = &ent->ino;
		else
			break;

		if (c)
			str = c + 1;
		else
			break;
	}

	ent->minor = minor;
	return 0;
}

static int walk_inodes_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_walk_inodes_entry ents[128];
	struct scoutfs_ioctl_walk_inodes walk;
	u64 total = 0;
	int ret;
	int fd;
	int i;

	if (argc != 4) {
		fprintf(stderr, "must specify seq and path\n");
		return -EINVAL;
	}

	if (!strcasecmp(argv[0], "size"))
		walk.index = SCOUTFS_IOC_WALK_INODES_SIZE;
	else if (!strcasecmp(argv[0], "ctime"))
		walk.index = SCOUTFS_IOC_WALK_INODES_CTIME;
	else if (!strcasecmp(argv[0], "mtime"))
		walk.index = SCOUTFS_IOC_WALK_INODES_MTIME;
	else {
		fprintf(stderr, "unknown index '%s', try 'size', 'ctime, or "
			"mtime'\n", argv[0]);
		return -EINVAL;
	}

	ret = parse_walk_entry(&walk.first, argv[1]);
	if (ret) {
		fprintf(stderr, "invalid first position '%s', try '1.2.3' or "
			"'-1'\n", argv[1]);
		return -EINVAL;

	}

	ret = parse_walk_entry(&walk.last, argv[2]);
	if (ret) {
		fprintf(stderr, "invalid last position '%s', try '1.2.3' or "
			"'-1'\n", argv[2]);
		return -EINVAL;

	}

	fd = open(argv[3], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[3], strerror(errno), errno);
		return ret;
	}

	walk.entries_ptr = (unsigned long)ents;
	walk.nr_entries = array_size(ents);

	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_WALK_INODES, &walk);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "walk_inodes ioctl failed: %s (%d)\n",
				strerror(errno), errno);
			break;
		} else if (ret == 0) {
			break;
		}

		for (i = 0; i < ret; i++) {
			if ((total + i) % 25 == 0)
				printf("%-20s %-20s %-10s %-20s\n",
				       "#", "major", "minor", "ino");

			printf("%-20llu %-20llu %-10u %-20llu\n",
			       total + i, ents[i].major, ents[i].minor,
			       ents[i].ino);
		}

		total += i;

		walk.first = ents[i - 1];
		if (++walk.first.ino == 0 && ++walk.first.minor == 0)
			walk.first.major++;
	}

	close(fd);
	return ret;
};

static void __attribute__((constructor)) walk_inodes_ctor(void)
{
	cmd_register("walk-inodes", "<index> <first> <last> <path>",
		     "print range of indexed inodes", walk_inodes_cmd);
}
