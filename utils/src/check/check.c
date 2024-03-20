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

struct check_args {
	char *meta_device;
	char *data_device;
	char *debug_path;
	bool repair;
};

static int do_check(struct check_args *args)
{
	int debug_fd = -1;
	int meta_fd = -1;
	int data_fd = -1;
	int ret;

	if (args->debug_path) {
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

	/*
	 * At some point we may convert this to a multi-pass system where we may
	 * try and repair items, and, as long as repairs are made, we will rerun
	 * the checks more times. We may need to start counting how many problems we
	 * fix in the process of these loops, so that we don't stall on unrepairable
	 * problems and are making actual repair progress. IOW - when we do a full
	 * check loop without any problems fixed, we stop trying.
	 */
	ret = check_supers() ?:
	      check_meta_alloc();

	if (ret < 0)
		goto out;

	debug("problem count %lu", problems_count());
	if (problems_count() > 0) {
		printf("Problems detected.\n");

		if (!args->repair)
			printf("Run the command again with the \"-r|--repair\" flag to try and repair issues detected.\n");
	}

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
	case 'r':
		args->repair = true;
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
	{ "repair", 'r', NULL, 0, "Repair detected issues"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"META-DEVICE DATA-DEVICE",
	"Check filesystem consistency"
};

/*
 * Called by main() essentially, this function has custom exit() values
 * to help automation and user interpretation of what needs to be done after
 * `check` has completed. The normal main() function just exits with 0 or 1
 * and a cryptic strerror(errno) which doesn't really translate well. For instance,
 * if we'd want to return EAGAIN, it would print "resource temporary unavailable"
 * which isn't the same as "run this thing again".
 *
 * To facilitate some sort of cross operability, we take the exit codes for `fsck`
 * here and mirror them exactly. That way we can conceivably implement `fsck.scoutfs`
 * at some point as a wrapper to `scoutfs check ...` and have the same exit value
 * mapping.
 *
 * The exit codes is a bitmap of the following values, with 0 being none of the
 * bits are set:
 *
 * 0 - no filesystem issues detected
 *
 * 1 - file system issues were corrected
 * 2 - retry needed (unused)
 * 4 - file system issues were not corrected
 * 8 - operational error
 * 16 - usage error
 * 32 - cancelled by user (SIGINT)
 *
 * See: util-linux/include/exitcodes.h
 */

/* Exit codes used by fsck-type programs */
#define FSCK_EX_NONDESTRUCT	1	/* File system errors corrected */
#define FSCK_EX_UNCORRECTED	4	/* File system errors left uncorrected */
#define FSCK_EX_ERROR		8	/* Operational error */
#define FSCK_EX_USAGE		16	/* Usage or syntax error */

static int check_cmd(int argc, char **argv)
{
	struct check_args check_args = {NULL};
	int ret;

	/*
	 * repair is off by default
	 */
	check_args.repair = false;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &check_args);
	if (ret)
		exit(FSCK_EX_USAGE);

	ret = do_check(&check_args);
	if (ret < 0)
		ret = FSCK_EX_ERROR;

	//FIXME: we should determine whether we can return FSCK_EX_NONDESTRUCT somehow

	if (problems_count() > 0)
		ret |= FSCK_EX_UNCORRECTED;

	exit(ret);
}

static void __attribute__((constructor)) check_ctor(void)
{
	cmd_register_argp("check", &argp, GROUP_CORE, check_cmd);
}
