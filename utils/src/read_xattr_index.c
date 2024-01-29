#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>

#include "sparse.h"
#include "parse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"
#include "cmp.h"

#define ENTF	"%llu.%llu.%llu"
#define ENTA(e)	(e)->a, (e)->b, (e)->ino

struct xattr_args {
	char *path;
	char *first_entry;
	char *last_entry;
};

static int compare_entries(struct scoutfs_ioctl_xattr_index_entry *a,
			   struct scoutfs_ioctl_xattr_index_entry *b)
{
	return scoutfs_cmp(a->a, b->a) ?: scoutfs_cmp(a->b, b->b) ?: scoutfs_cmp(a->ino, b->ino);
}

static int parse_entry(struct scoutfs_ioctl_xattr_index_entry *ent, char *str)
{
	int ret;

	ret = sscanf(str, "%lli.%lli.%lli", &ent->a, &ent->b, &ent->ino);
	if (ret != 3) {
		fprintf(stderr, "bad index position entry argument '%s', it must be "
				"in the form \"a.b.ino\" where each value can be prefixed by "
				"'0' for octal or '0x' for hex\n", str);
		return -EINVAL;
	}

	return 0;
}

#define NR_ENTRIES 1024

static int do_read_xattr_index(struct xattr_args *args)
{
	struct scoutfs_ioctl_read_xattr_index rxi;
	struct scoutfs_ioctl_xattr_index_entry *ents;
	struct scoutfs_ioctl_xattr_index_entry *ent;
	int fd = -1;
	int ret;
	int i;

	ents = calloc(NR_ENTRIES, sizeof(struct scoutfs_ioctl_xattr_index_entry));
	if (!ents) {
		fprintf(stderr, "xattr index entry allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	memset(&rxi, 0, sizeof(rxi));
	memset(&rxi.last, 0xff, sizeof(rxi.last));
	rxi.entries_ptr = (unsigned long)ents;
	rxi.entries_nr = NR_ENTRIES;

	ret = 0;
	if (args->first_entry)
		ret = parse_entry(&rxi.first, args->first_entry);
	if (args->last_entry)
		ret = parse_entry(&rxi.last, args->last_entry);
	if (ret < 0)
		goto out;

	if (compare_entries(&rxi.first, &rxi.last) > 0) {
		fprintf(stderr, "first index position "ENTF" must be less than last index position "ENTF"\n",
			       ENTA(&rxi.first), ENTA(&rxi.last));
		ret = -EINVAL;
		goto out;
	}

	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_READ_XATTR_INDEX, &rxi);
		if (ret == 0)
			break;
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "read_xattr_index ioctl failed: "
				"%s (%d)\n", strerror(errno), errno);
			goto out;
		}

		for (i = 0; i < ret; i++) {
			ent = &ents[i];
			printf("%llu.%llu = %llu\n",
				ent->a, ent->b, ent->ino);
		}

		rxi.first = *ent;

		if ((++rxi.first.ino == 0 && ++rxi.first.b == 0 && ++rxi.first.a == 0) ||
		    compare_entries(&rxi.first, &rxi.last) > 0)
			break;
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(ents);

	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct xattr_args *args = state->input;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_ARG:
		if (!args->first_entry)
			args->first_entry = strdup_or_error(state, arg);
		else if (!args->last_entry)
			args->last_entry = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two entry arguments given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"FIRST-ENTRY LAST-ENTRY",
	"Search and print inode numbers indexed by their .indx. xattrs"
};

static int read_xattr_index_cmd(int argc, char **argv)
{

	struct xattr_args xattr_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &xattr_args);
	if (ret)
		return ret;

	return do_read_xattr_index(&xattr_args);
}

static void __attribute__((constructor)) read_xattr_index_ctor(void)
{
	cmd_register_argp("read-xattr-index", &argp, GROUP_INFO, read_xattr_index_cmd);
}
