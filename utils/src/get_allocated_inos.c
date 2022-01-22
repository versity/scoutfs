#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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

struct get_allocated_inos_args {
	char *path;
	u64 ino;
	bool have_ino;
	bool single;
};

static int do_get_allocated_inos(struct get_allocated_inos_args *args)
{
	struct scoutfs_ioctl_get_allocated_inos gai;
	u64 *inos = NULL;
	int fd = -1;
	u64 bytes;
	int ret;
	int i;

	if (args->single)
		bytes = sizeof(*inos);
	else
		bytes = SCOUTFS_LOCK_INODE_GROUP_NR * sizeof(*inos);

	inos = malloc(bytes);
	if (!inos) {
		fprintf(stderr, "inode number array allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	memset(&gai, 0, sizeof(gai));
	gai.start_ino = args->ino;
	gai.inos_ptr = (unsigned long)inos;
	gai.inos_bytes = bytes;

	ret = ioctl(fd, SCOUTFS_IOC_GET_ALLOCATED_INOS, &gai);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "get_allocated_inos ioctl failed: "
			"%s (%d)\n", strerror(errno), errno);
		goto out;
	}

	if (args->single && ret > 0 && inos[0] != args->ino)
		ret = 0;

	for (i = 0; i < ret; i++)
		printf("%llu\n", inos[i]);

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(inos);

	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct get_allocated_inos_args *args = state->input;
	int ret;

	switch (key) {
	case 'i':
		ret = parse_u64(arg, &args->ino);
		if (ret)
			return ret;
		args->have_ino = true;
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case 's':
		args->single = true;
		break;
	case ARGP_KEY_FINI:
		if (!args->have_ino)
			argp_error(state, "must provide --ino starting inode number option");
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "ino", 'i', "NUMBER", 0, "Start from 64bit inode number (required)"},
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "single", 's', NULL, 0, "Only print single specific inode number argument"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	NULL,
	"Print allocated inode numbers from starting inode number"
};

static int get_allocated_inos_cmd(int argc, char **argv)
{

	struct get_allocated_inos_args get_allocated_inos_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &get_allocated_inos_args);
	if (ret)
		return ret;

	return do_get_allocated_inos(&get_allocated_inos_args);
}

static void __attribute__((constructor)) get_allocated_inos_ctor(void)
{
	cmd_register_argp("get-allocated-inos", &argp, GROUP_DEBUG, get_allocated_inos_cmd);
}
