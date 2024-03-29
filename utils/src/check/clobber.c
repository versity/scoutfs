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

#include "problem.h"
#include "clobber.h"

struct clobber_args {
	char *meta_device;
	char *data_device;
	char *debug_path;
	prob_t problem;
	int (*do_clobber)(char *);
	char *data;
	bool list_clobbers;
	prob_t describe_clobber;
};

static int do_clobber(struct clobber_args *args)
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

	ret = check_supers(data_fd);
	if (ret < 0)
		goto out;

	/* and call the clobber function */
	ret = args->do_clobber(args->data);

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
	struct clobber_args *args = state->input;
	struct clobber_function **cf;

	switch (key) {
	case 'D':
		args->data = strdup_or_error(state, arg);
		break;
	case 'd':
		args->debug_path = strdup_or_error(state, arg);
		break;
	case 'e':
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else if (!args->data_device)
			args->data_device = strdup_or_error(state, arg);
		else if (!args->do_clobber) {
			for (cf = clobber_functions; *cf != NULL; cf++) {
				if (strcmp(arg, prob_strs[(*cf)->problem]) == 0) {
					args->problem = (*cf)->problem;
					args->do_clobber = (*cf)->do_clobber;
					break;
				}
			}
			if (args->problem == PB__NR)
				argp_error(state, "invalid problem given (\"%s\")", arg);

		} else
			argp_error(state, "more than two device arguments and a clobber function given");
		break;
	case ARGP_KEY_FINI:
		if (args->list_clobbers)
			break;
		if (args->describe_clobber != PB__NR)
			break;

		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		if (!args->data_device)
			argp_error(state, "no data device argument given");
		if (!args->do_clobber)
			argp_error(state, "no clobber function argument given");
		break;
	case 'l':
		args->list_clobbers = true;
		break;
	case 'S':
		for (cf = clobber_functions; *cf != NULL; cf++) {
			if (strcmp(arg, prob_strs[(*cf)->problem]) == 0) {
				args->describe_clobber = (*cf)->problem;
				break;
			}
		}
		if (args->describe_clobber == PB__NR)
			argp_error(state, "invalid problem given (\"%s\")", arg);
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "debug", 'd', "FILE_PATH", 0, "Path to debug output file, will be created or truncated"},
	{ "describe", 'S', "CLOBBER-FUNCTION", 0, "Describe clobber function and data values used by the function"},
	{ "list-clobbers", 'l', NULL, 0, "List known clobbers that can be applied the filesystem"},
	{ "data", 'D', "DATA", 0, "Data to pass to the clobber function. Each clobber function may use this data differently"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"META-DEVICE DATA-DEVICE CLOBBER-FUNCTION",
	"Clobber filesystem consistency (DESTRUCTIVE)"
};

static int clobber_cmd(int argc, char **argv)
{
	struct clobber_args clobber_args = {NULL};
	struct clobber_function **cf;
	int ret;

	/* initialize enums to invalid */
	clobber_args.problem = PB__NR;
	clobber_args.describe_clobber = PB__NR;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &clobber_args);
	if (ret)
		return ret;

	if (clobber_args.list_clobbers) {
		for (cf = clobber_functions; *cf != NULL; cf++)
			fprintf(stdout, "%s\n", prob_strs[(*cf)->problem]);

		return 1;
	} else if (clobber_args.describe_clobber != PB__NR) {
		for (cf = clobber_functions; *cf != NULL; cf++)
			if ((*cf)->problem == clobber_args.describe_clobber)
				fprintf(stdout, "%s:\n%s",
					prob_strs[(*cf)->problem],
					(*cf)->description);
		return 1;
	} else
		return do_clobber(&clobber_args);
}

static void __attribute__((constructor)) clobber_ctor(void)
{
	cmd_register_argp("clobber", &argp, GROUP_CORE, clobber_cmd);
}
