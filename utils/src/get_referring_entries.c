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

struct gre_args {
	char *path;
	u64 ino;
};

static int do_get_referring_entries(struct gre_args *args)
{
	struct scoutfs_ioctl_get_referring_entries gre;
	struct scoutfs_ioctl_dirent *dent;
	unsigned int bytes;
	void *buf;
	int ret;
	int fd;

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	bytes = PATH_MAX * 1024;
	buf = malloc(bytes);
	if (!buf) {
		fprintf(stderr, "couldn't allocate %u byte buffer\n", bytes);
		ret = -ENOMEM;
		goto out;
	}

	gre.ino = args->ino;
	gre.dir_ino = 0;
	gre.dir_pos = 0;
	gre.entries_ptr = (intptr_t)buf;
	gre.entries_bytes = bytes;

	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_GET_REFERRING_ENTRIES, &gre);
		if (ret <= 0) {
			if (ret < 0) {
				ret = -errno;
				fprintf(stderr, "ioctl failed: %s (%d)\n", strerror(errno), errno);
			}
			goto out;
		}

		dent = buf;
		while (ret-- > 0) {
			printf("dir %llu pos %llu type %u name %s\n",
			       dent->dir_ino, dent->dir_pos, dent->d_type, dent->name);

			gre.dir_ino = dent->dir_ino;
			gre.dir_pos = dent->dir_pos;

			if (dent->flags & SCOUTFS_IOCTL_DIRENT_FLAG_LAST) {
				ret = 0;
				goto out;
			}

			dent = (void *)dent + dent->entry_bytes;
		}

		if (++gre.dir_pos == 0) {
			if (++gre.dir_ino == 0) {
				ret = 0;
				goto out;
			}
		}
	}

out:
	close(fd);
	free(buf);

	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct gre_args *args = state->input;
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
	"Print directory entries that refer to inode number"
};

static int get_referring_entries_cmd(int argc, char **argv)
{
	struct gre_args args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_get_referring_entries(&args);
}


static void __attribute__((constructor)) get_referring_entries_ctor(void)
{
	cmd_register_argp("get-referring-entries", &argp, GROUP_SEARCH, get_referring_entries_cmd);
}
