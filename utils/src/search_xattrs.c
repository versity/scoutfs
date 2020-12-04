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

/*
 * There are significant constant costs to each search call, we
 * want to get the inodes in as few calls as possible.
 */
#define BATCH_SIZE 1000000

struct xattr_args {
	char *name;
	char *path;
};

static int do_search_xattrs(struct xattr_args *args)
{
	struct scoutfs_ioctl_search_xattrs sx = {0};
	u64 *inos = NULL;
	int fd = -1;
	int ret;
	int i;

	memset(&sx, 0, sizeof(sx));

	inos = malloc(BATCH_SIZE * sizeof(inos[0]));
	if (!inos) {
		fprintf(stderr, "inos mem alloc failed\n");
		ret = -ENOMEM;
		goto out;
	}

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	sx.next_ino = 0;
	sx.last_ino = U64_MAX;
	sx.name_ptr = (unsigned long)args->name;
	sx.inodes_ptr = (unsigned long)inos;
	sx.name_bytes = strlen(args->name);
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
	free(inos);

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
		if (args->name)
			argp_error(state, "more than one name argument given");

		args->name = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_FINI:
		if (!args->name) {
			argp_error(state, "must provide xattr containing .srch. scoutfs tag");
		}
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
	"XATTR-NAME",
	"Print inode numbers of inodes which may have given xattr"
};

static int search_xattrs_cmd(int argc, char **argv)
{

	struct xattr_args xattr_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &xattr_args);
	if (ret)
		return ret;

	return do_search_xattrs(&xattr_args);
}

static void __attribute__((constructor)) search_xattrs_ctor(void)
{
	cmd_register_argp("search-xattrs", &argp, GROUP_INFO, search_xattrs_cmd);
}
