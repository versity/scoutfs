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
#include <argp.h>
#include <stdbool.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "parse.h"
#include "cmd.h"

struct setattr_args {
	char *filename;
	struct timespec ctime;
	u64 data_version;
	u64 i_size;
	bool offline;
};

static int do_setattr(struct setattr_args *args)
{
	struct scoutfs_ioctl_setattr_more sm = {0};
	int fd = -1;
	int ret;

	fd = open(args->filename, O_WRONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->filename, strerror(errno), errno);
		goto out;
	}

	sm.ctime_sec = args->ctime.tv_sec;
	sm.ctime_nsec = args->ctime.tv_nsec;
	sm.data_version = args->data_version;
	if (args->offline)
		sm.flags |= SCOUTFS_IOC_SETATTR_MORE_OFFLINE;
	sm.i_size = args->i_size;

	ret = ioctl(fd, SCOUTFS_IOC_SETATTR_MORE, &sm);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "setattr_more ioctl failed on '%s': "
			"%s (%d)\n", args->filename, strerror(errno), errno);
		goto out;
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct setattr_args *args = state->input;
	int ret;

	switch (key) {
	case 't': /* timespec */
		ret = parse_timespec(arg, &args->ctime);
		if (ret)
			return ret;
		break;
	case 'V': /* data version */
		ret = parse_u64(arg, &args->data_version);
		if (ret)
			return ret;
		if (args->data_version == 0)
			argp_error(state, "data version must not be 0");
		break;
	case 's': /* size */
		ret = parse_human(arg, &args->i_size);
		if (ret)
			return ret;
		break;
	case 'o': /* offline */
		args->offline = true;
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
		if (args->i_size && !args->data_version) {
			argp_error(state, "must provide data-version if using --size option");
		}
		if (!args->i_size && args->offline) {
			argp_error(state, "must provide size if using --offline option");
		}
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "ctime", 't', "TIMESPEC", 0, "Set creation time using \"<seconds-since-epoch>.<nanoseconds>\" format"},
	{ "data-version", 'V', "VERSION", 0, "Set data version"},
	{ "size", 's', "SIZE", 0, "Set file size (bytes or KMGTP units). Requires --data-version"},
	{ "offline", 'o', NULL, 0, "Set file contents as offline, not sparse. Requires --size"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"FILE",
	"Set attributes on newly-created zero-length file"
};

static int setattr_cmd(int argc, char **argv)
{
	struct setattr_args setattr_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &setattr_args);
	if (ret)
		return ret;

	return do_setattr(&setattr_args);
}

static void __attribute__((constructor)) setattr_more_ctor(void)
{
	cmd_register_argp("setattr", &argp, GROUP_AGENT, setattr_cmd);
}
