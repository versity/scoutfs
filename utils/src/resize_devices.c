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

struct resize_args {
	char *path;
	u64 meta_size;
	u64 data_size;
};

static int do_resize_devices(struct resize_args *args)
{
	struct scoutfs_ioctl_resize_devices rd;
	int ret;
	int fd;

	if (args->meta_size & SCOUTFS_BLOCK_LG_MASK) {
		printf("metadata device size %llu is not a multiple of %u metadata block size, truncating down to %llu byte size\n",
		args->meta_size, SCOUTFS_BLOCK_LG_SIZE,
		args->meta_size & ~(u64)SCOUTFS_BLOCK_LG_MASK);
	}

	if (args->data_size & SCOUTFS_BLOCK_SM_MASK) {
		printf("data device size %llu is not a multiple of %u data block size, truncating down to %llu byte size\n",
		args->data_size, SCOUTFS_BLOCK_SM_SIZE,
		args->data_size & ~(u64)SCOUTFS_BLOCK_SM_MASK);
	}

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	rd.new_total_meta_blocks = args->meta_size >> SCOUTFS_BLOCK_LG_SHIFT;
	rd.new_total_data_blocks = args->data_size >> SCOUTFS_BLOCK_SM_SHIFT;

	ret = ioctl(fd, SCOUTFS_IOC_RESIZE_DEVICES, &rd);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "resize_devices ioctl failed: %s (%d)\n", strerror(errno), errno);
	}

	close(fd);
	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct resize_args *args = state->input;
	int ret;

	switch (key) {
	case 'm': /* meta-size */
	{
		ret = parse_human(arg, &args->meta_size);
		if (ret)
			return ret;
		break;
	}
	case 'd': /* data-size */
	{
		ret = parse_human(arg, &args->data_size);
		if (ret)
			return ret;
		break;
	}
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "meta-size", 'm', "SIZE", 0, "New metadata device size (bytes or KMGTP units)"},
	{ "data-size", 'd', "SIZE", 0, "New data device size (bytes or KMGTP units)"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"",
	"Online resize of metadata and/or data devices",
};

static int resize_devices_cmd(int argc, char **argv)
{

	struct resize_args resize_args = {NULL,};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &resize_args);
	if (ret)
		return ret;

	return do_resize_devices(&resize_args);
}

static void __attribute__((constructor)) read_xattr_totals_ctor(void)
{
	cmd_register_argp("resize-devices", &argp, GROUP_CORE, resize_devices_cmd);
}
