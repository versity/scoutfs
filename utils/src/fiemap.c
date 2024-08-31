#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
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
 * This is wholly modeled after e2fsprogs/filefrag.c from tso
 */

struct get_fiemap_args {
	char *filename;
	bool phys;
	bool byte;
};

static int do_get_fiemap(struct get_fiemap_args *args)
{
	__u64 buf[2048];        /* __u64 for proper field alignment */
	struct fiemap *fiemap = (struct fiemap *)buf;
	struct fiemap_extent *fm_ext = &fiemap->fm_extents[0];
	int count = (sizeof(buf) - sizeof(*fiemap)) /
			sizeof(struct fiemap_extent);
	int fd;
	int ret;
	int i;
	int nr = 0; /* XXX we could put this in fm_start to make start/count an option */
	int last = 0;
	int written = 0;
	u64 off;
	u64 len;

	memset(fiemap, 0, sizeof(struct fiemap));

	fd = open(args->filename, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->filename, strerror(errno), errno);
		goto out;
	}

	do {
		fiemap->fm_length = ~0ULL;
		fiemap->fm_extent_count = count;

		ret = ioctl(fd, FS_IOC_FIEMAP, (unsigned long) fiemap);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "get_fiemap ioctl failed: "
				"%s (%d)\n", strerror(errno), errno);
			goto out;
		}

		/* nothing returned, so exit */
		if (fiemap->fm_mapped_extents == 0)
			break;

		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			if (args->phys)
				off = fm_ext[i].fe_physical;
			else
				off = fm_ext[i].fe_logical;

			len = fm_ext[i].fe_length;

			if (!args->byte) {
				off /= SCOUTFS_BLOCK_SM_SIZE;
				len /= SCOUTFS_BLOCK_SM_SIZE;
			}

			printf("%d: offset: %llu, length: %llu, flags: %c%c%c\n",
				nr++, off, len,
				(fm_ext[i].fe_flags & FIEMAP_EXTENT_UNKNOWN) ? 'O' : '.',
				(fm_ext[i].fe_flags & FIEMAP_EXTENT_UNWRITTEN) ? 'U' : '.',
				(fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST) ? 'L' : '.');

			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST)
				last = 1;

			if ((fm_ext[i].fe_flags & FIEMAP_EXTENT_UNWRITTEN) == 0)
				written++;
		}
	} while (last == 0);

	printf("entries: %u, extents: %u\n", nr, written);

out:
	if (fd >= 0)
		close(fd);

	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct get_fiemap_args *args = state->input;

	switch (key) {
	case 'P':
		args->phys = true;
		break;
	case 'b':
		args->byte = true;
		break;
	case ARGP_KEY_ARG:
		if (!args->filename)
			args->filename = strdup_or_error(state, arg);
		else
			argp_error(state, "more than one argument given");
		break;
	case ARGP_KEY_FINI:
		if (!args->filename)
			argp_error(state, "no filename given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "physical", 'P', NULL, 0, "Output physical offsets instead of logical"},
	{ "byte", 'b', NULL, 0, "Output byte values instead of blocks"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"FILE",
	"Print fiemap extent mapping"
};

static int get_fiemap_cmd(int argc, char **argv)
{
	struct get_fiemap_args get_fiemap_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &get_fiemap_args);
	if (ret)
		return ret;

	return do_get_fiemap(&get_fiemap_args);
}

static void __attribute__((constructor)) get_fiemap_ctor(void)
{
	cmd_register_argp("get-fiemap", &argp, GROUP_DEBUG, get_fiemap_cmd);
}
