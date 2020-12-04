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
#include "parse.h"
#include "cmd.h"

struct ino_args {
	char *path;
	u64 ino;
};

static int do_ino_path(struct ino_args *args)
{
	struct scoutfs_ioctl_ino_path ioctl_args;
	struct scoutfs_ioctl_ino_path_result *res;
	unsigned int result_bytes;
	int ret;
	int fd;

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	result_bytes = offsetof(struct scoutfs_ioctl_ino_path_result,
				path[PATH_MAX]);
	res = malloc(result_bytes);
	if (!res) {
		fprintf(stderr, "couldn't allocate %u byte buffer\n",
			result_bytes);
		ret = -ENOMEM;
		goto out;
	}

	ioctl_args.ino = args->ino;
	ioctl_args.dir_ino = 0;
	ioctl_args.dir_pos = 0;
	ioctl_args.result_ptr = (intptr_t)res;
	ioctl_args.result_bytes = result_bytes;
	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_INO_PATH, &ioctl_args);
		if (ret < 0) {
			ret = -errno;
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		printf("%.*s\n", res->path_bytes, res->path);

		ioctl_args.dir_ino = res->dir_ino;
		ioctl_args.dir_pos = res->dir_pos;
		if (++ioctl_args.dir_pos == 0) {
			if (++ioctl_args.dir_ino == 0)
				break;
		}
	}

	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "inodes_since ioctl failed: %s (%d)\n",
			strerror(errno), errno);
	}
out:
	free(res);
	close(fd);
	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct ino_args *args = state->input;
	int ret;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_ARG:
		if (args->ino)
			argp_error(state, "more than one argument given");
		ret = parse_u64(arg, &args->ino);
		if (ret)
			argp_error(state, "inode parse error");
		break;
	case ARGP_KEY_FINI:
		if (!args->ino) {
			argp_error(state, "must provide inode number");
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
	"INODE-NUM",
	"Print paths that refer to inode number"
};

static int ino_path_cmd(int argc, char **argv)
{
	struct ino_args ino_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &ino_args);
	if (ret)
		return ret;

	return do_ino_path(&ino_args);
}


static void __attribute__((constructor)) ino_path_ctor(void)
{
	cmd_register_argp("ino-path", &argp, GROUP_SEARCH, ino_path_cmd);
}
