#define _GNU_SOURCE /* O_DIRECT */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <argp.h>

#include "sparse.h"
#include "parse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"
#include "dev.h"

#include "alloc.h"
#include "block.h"
#include "debug.h"
#include "meta.h"
#include "super.h"

struct check_args {
	char *meta_device;
	char *data_device;
	char *debug_path;
};

static int do_check(struct check_args *args)
{
	int debug_fd = -1;
	int meta_fd = -1;
	int data_fd = -1;
	int ret;

	if (args->debug_path) {
		if (strcmp(args->debug_path, "-") == 0)
			debug_fd = dup(STDERR_FILENO);
		else
			debug_fd = open(args->debug_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (debug_fd < 0) {
			ret = -errno;
			fprintf(stderr, "error opening debug output file '%s': %s (%d)\n",
				args->debug_path, strerror(errno), errno);
			goto out;
		}

		debug_enable(debug_fd);
	}

	meta_fd = open(args->meta_device, O_DIRECT | O_RDWR | O_EXCL);
	if (meta_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open meta device '%s': %s (%d)\n",
			args->meta_device, strerror(errno), errno);
		goto out;
	}

	data_fd = open(args->data_device, O_DIRECT | O_RDWR | O_EXCL);
	if (data_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open data device '%s': %s (%d)\n",
			args->data_device, strerror(errno), errno);
		goto out;
	}

	ret = block_setup(meta_fd, 128 * 1024 * 1024, 32 * 1024 * 1024);
	if (ret < 0)
		goto out;

	ret = check_supers() ?:
	      check_meta_refs();
out:
	/* and tear it all down */
	block_shutdown();
	super_shutdown();
	debug_disable();

	if (meta_fd >= 0)
		close(meta_fd);
	if (data_fd >= 0)
		close(data_fd);
	if (debug_fd >= 0)
		close(debug_fd);

	return ret;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct check_args *args = state->input;

	switch (key) {
	case 'd':
		args->debug_path = strdup_or_error(state, arg);
		break;
	case 'e':
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else if (!args->data_device)
			args->data_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two device arguments given");
		break;
	case ARGP_KEY_FINI:
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		if (!args->data_device)
			argp_error(state, "no data device argument given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "debug", 'd', "FILE_PATH", 0, "Path to debug output file, will be created or truncated"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"META-DEVICE DATA-DEVICE",
	"Check filesystem consistency"
};

static int check_cmd(int argc, char **argv)
{
	struct check_args check_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &check_args);
	if (ret)
		return ret;

	return do_check(&check_args);
}

static void __attribute__((constructor)) check_ctor(void)
{
	cmd_register_argp("check", &argp, GROUP_CORE, check_cmd);
}
