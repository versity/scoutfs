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
	bool logical;
	bool byte;
};

static int do_get_fiemap(struct get_fiemap_args *args)
{
	__u64 buf[2048];        /* __u64 for proper field alignment */
	struct stat st;
	struct fiemap *fiemap = (struct fiemap *)buf;
	struct fiemap_extent *fm_ext = &fiemap->fm_extents[0];
	int count = (sizeof(buf) - sizeof(*fiemap)) /
			sizeof(struct fiemap_extent);
	int fd;
	int ret;
	int i;
	u64 nr = 0; /* XXX we could put this in fm_start to make start/count an option */
	int last = 0;
	u64 off_p, off_l;
	u64 len;

	memset(fiemap, 0, sizeof(struct fiemap));

	fd = open(args->filename, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->filename, strerror(errno), errno);
		goto out;
	}

	/* get block size from stat */
	if (fstat(fd, &st) != 0) {
		ret = -errno;
		fprintf(stderr, "stat failed on '%s': %s (%d)\n",
			args->filename, strerror(errno), errno);
		goto out;
	};

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
			off_p = fm_ext[i].fe_physical;
			off_l = fm_ext[i].fe_logical;
			len = fm_ext[i].fe_length;

			if (!args->byte) {
				off_p /= st.st_blksize;
				off_l /= st.st_blksize;
				len /= st.st_blksize;
			}

			printf("%llu: offset: ", nr++);

			if (!args->phys)
				printf("%llu ", off_l);
			else if (!args->logical)
				printf("%llu ", off_p);
			else
				printf("%llu %llu ", off_l, off_p);

			printf("length: %llu flags: %c%c%c\n",
				len,
				(fm_ext[i].fe_flags & FIEMAP_EXTENT_UNKNOWN) ? 'O' : '.',
				(fm_ext[i].fe_flags & FIEMAP_EXTENT_UNWRITTEN) ? 'U' : '.',
				(fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST) ? 'L' : '.');

			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST)
				last = 1;
		}

		/* fm_start from the next logical extent */
		fiemap->fm_start = fm_ext[i-1].fe_logical + fm_ext[i-1].fe_length;
	} while (last == 0);

	printf("extents: %llu\n", nr);

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
		args->logical = false;
		break;
	case 'L':
		args->phys = false;
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
		if ((!args->logical) && (!args->phys))
			argp_error(state, "can't pass both -P and -L options");
		if (!args->filename)
			argp_error(state, "no filename given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "physical", 'P', NULL, 0, "Output physical offsets only"},
	{ "logical", 'L', NULL, 0, "Output logical offsets only"},
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

	get_fiemap_args.phys = true;
	get_fiemap_args.logical = true;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &get_fiemap_args);
	if (ret)
		return ret;

	return do_get_fiemap(&get_fiemap_args);
}

static void __attribute__((constructor)) get_fiemap_ctor(void)
{
	cmd_register_argp("get-fiemap", &argp, GROUP_DEBUG, get_fiemap_cmd);
}
