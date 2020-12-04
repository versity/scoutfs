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
#include <argp.h>

#include "sparse.h"
#include "parse.h"
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
	u64 minor = 0;
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

struct walk_inodes_args {
	char *path;
	char *index;
	char *first_entry;
	char *last_entry;
};

static int do_walk_inodes(struct walk_inodes_args *args)
{
	struct scoutfs_ioctl_walk_inodes_entry ents[128];
	struct scoutfs_ioctl_walk_inodes walk;
	u64 total = 0;
	int ret;
	int fd;
	int i;

	if (!strcasecmp(args->index, "meta_seq"))
		walk.index = SCOUTFS_IOC_WALK_INODES_META_SEQ;
	else if (!strcasecmp(args->index, "data_seq"))
		walk.index = SCOUTFS_IOC_WALK_INODES_DATA_SEQ;
	else {
		fprintf(stderr, "unknown index '%s', try 'meta_seq' or "
				"'data_seq'\n", args->index);
		return -EINVAL;
	}

	ret = parse_walk_entry(&walk.first, args->first_entry);
	if (ret) {
		fprintf(stderr, "invalid first position '%s', try '1.2.3' or "
			"'-1'\n", args->first_entry);
		return -EINVAL;

	}

	ret = parse_walk_entry(&walk.last, args->last_entry);
	if (ret) {
		fprintf(stderr, "invalid last position '%s', try '1.2.3' or "
			"'-1'\n", args->last_entry);
		return -EINVAL;

	}

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

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

static int walk_inodes_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct walk_inodes_args *args = state->input;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_ARG:
		if (!args->index)
			args->index = strdup_or_error(state, arg);
		else if (!args->first_entry)
			args->first_entry = strdup_or_error(state, arg);
		else if (!args->last_entry)
			args->last_entry = strdup_or_error(state, arg);
		else
			argp_error(state, "more than three arguments given");
		break;
	case ARGP_KEY_FINI:
		if (!args->index)
			argp_error(state, "no index given");
		if (!args->first_entry)
			argp_error(state, "no first entry given");
		if (!args->last_entry)
			argp_error(state, "no last entry given");
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

static int walk_inodes_cmd(int argc, char **argv)
{
	struct argp argp = {
		options,
		walk_inodes_parse_opt,
		"<meta_seq|data_seq> FIRST-ENTRY LAST-ENTRY"
	};
	struct walk_inodes_args walk_inodes_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &walk_inodes_args);
	if (ret)
		return ret;

	return do_walk_inodes(&walk_inodes_args);
}


static void __attribute__((constructor)) walk_inodes_ctor(void)
{
	cmd_register("walk-inodes", "<index> <first> <last>",
		     "print range of indexed inodes", walk_inodes_cmd);
}
