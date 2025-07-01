#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>

#include "sparse.h"
#include "parse.h"
#include "util.h"
#include "ioctl.h"
#include "cmd.h"

struct po_args {
	char *path;
	u64 offset;
	u64 length;
	u64 data_version;
};

static int do_punch_offline(struct po_args *args)
{
	struct scoutfs_ioctl_punch_offline ioctl_args;
	int ret;
	int fd;

	fd = get_path(args->path, O_RDWR);
	if (fd < 0)
		return fd;

	ioctl_args.offset = args->offset;
	ioctl_args.len = args->length;
	ioctl_args.data_version = args->data_version;
	ioctl_args.flags = 0;

	ret = ioctl(fd, SCOUTFS_IOC_PUNCH_OFFLINE, &ioctl_args);

	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "punch_offline ioctl failed: %s (%d)\n",
			strerror(errno), errno);
	}

	close(fd);
	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct po_args *args = state->input;
	int ret = 0;

	switch (key) {
	case 'V':
		ret = parse_u64(arg, &args->data_version);
		if (ret)
			return ret;
		break;
	case 'o': /* offset */
		ret = parse_human(arg, &args->offset);
		if (ret)
			return ret;
		break;
	case 'l': /* length */
		ret = parse_human(arg, &args->length);
		if (ret)
			return ret;
		break;
	case ARGP_KEY_ARG:
		if (!args->path)
			args->path = strdup_or_error(state, arg);
		else
			argp_error(state, "unknown extra argument given");
		break;
	case ARGP_KEY_FINI:
		if (!args->path)
			argp_error(state, "must provide path to file");
		if (args->offset < 0)
			argp_error(state, "must provide offset");
		if (args->length < 0)
			argp_error(state, "must provide length");
		if (args->data_version < 0)
			argp_error(state, "must provide data_version");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "data-version", 'V', "VERSION", 0, "Data version of the file [Required]"},
	{ "offset", 'o', "OFFSET", 0, "Offset (bytes or KMGTP units) in file to stage (default: 0)"},
	{ "length", 'l', "LENGTH", 0, "Length of range (bytes or KMGTP units) of file to stage. (default: size of ARCHIVE-FILE)"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"PATH",
	"Make a (sparse) hole in the file at offset and with length"
};

static int punch_offline_cmd(int argc, char **argv)
{
	struct po_args po_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &po_args);
	if (ret)
		return ret;

	return do_punch_offline(&po_args);
}

static void __attribute__((constructor)) punch_offline_ctor(void)
{
	cmd_register_argp("punch-offline", &argp, GROUP_AGENT, punch_offline_cmd);
}
