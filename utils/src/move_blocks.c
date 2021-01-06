#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <argp.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"
#include "parse.h"

struct move_blocks_args {
	char *from_path;
	u64 from_offset;
	u64 length;
	char *to_path;
	u64 to_offset;

	unsigned from_off_set:1,
	         len_set:1,
	         to_off_set:1;
};

static int do_move_blocks(struct move_blocks_args *args)
{
	struct scoutfs_ioctl_move_blocks mb;
	int from_fd = -1;
	int to_fd = -1;
	int ret;

	from_fd = open(args->from_path, O_RDWR);
	if (from_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->from_path, strerror(errno), errno);
		goto out;
	}

	to_fd = open(args->to_path, O_RDWR);
	if (to_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->to_path, strerror(errno), errno);
		goto out;
	}

	mb.from_fd = from_fd;
	mb.from_off = args->from_offset;
	mb.len = args->length;
	mb.to_off = args->to_offset;

	ret = ioctl(to_fd, SCOUTFS_IOC_MOVE_BLOCKS, &mb);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "ioctl failed on '%s': %s (%d)\n",
			args->to_path, strerror(errno), errno);
	}

out:
	if (from_fd >= 0)
		close(from_fd);
	if (to_fd >= 0)
		close(to_fd);

	return ret;
}

static int parse_move_blocks_opts(int key, char *arg, struct argp_state *state)
{
	struct move_blocks_args *args = state->input;
	int ret;

	switch (key) {
	case 'f':
		ret = parse_u64(arg, &args->from_offset);
		if (ret)
			return ret;
		args->from_off_set = 1;
		break;
	case 'l':
		ret = parse_human(arg, &args->length);
		if (ret)
			return ret;
		args->len_set = 1;
		break;
	case 't':
		ret = parse_human(arg, &args->to_offset);
		if (ret)
			return ret;
		args->to_off_set = 1;
		break;
	case ARGP_KEY_ARG:
		if (args->to_path)
			argp_error(state, "more than two file path arguments given");
		if (args->from_path)
			args->to_path = strdup_or_error(state, arg);
		else
			args->from_path = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_FINI:
		if (!args->from_path)
			argp_error(state, "must provide from file path");
		if (!args->to_path)
			argp_error(state, "must provide to file path");
		if (!args->from_off_set)
			argp_error(state, "must provide from file offset --from-offset");
		if (!args->len_set)
			argp_error(state, "must provide region length --length");
		if (!args->to_off_set)
			argp_error(state, "must provide to file offset --to-offset");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option move_blocks_options[] = {
	{ "from-offset", 'f', "OFFSET", 0,
	   "Byte offset in from file of region to move [Required]"},
	{ "length", 'l', "LENGTH", 0,
	   "Length in bytes of region to move between files [Required]"},
	{ "to-offset", 't', "OFFSET", 0,
	   "Byte offset in to file where region will be moved to [Required]"},
	{ NULL }
};

static struct argp move_blocks_argp = {
	move_blocks_options,
	parse_move_blocks_opts,
	"FROM_FILE --from-offset OFFSET --length LENGTH TO_FILE --to-offset OFFSET",
	"Move a fixed-size region of extents from one regular file to another",
};

static int move_blocks_cmd(int argc, char **argv)
{
	struct move_blocks_args args = {NULL};
	int ret;

	ret = argp_parse(&move_blocks_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_move_blocks(&args);
}

static void __attribute__((constructor)) move_blocks_ctor(void)
{
	cmd_register_argp("move-blocks", &move_blocks_argp, GROUP_AGENT,
			  move_blocks_cmd);
}
