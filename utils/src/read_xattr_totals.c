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

struct xattr_args {
	char *path;
};

static int do_read_xattr_totals(struct xattr_args *args)
{
	struct scoutfs_ioctl_read_xattr_totals rxt;
	struct scoutfs_ioctl_xattr_total *xts = NULL;
	struct scoutfs_ioctl_xattr_total *xt;
	u64 bytes = 1024 * 1024;
	int fd = -1;
	int ret;
	int i;

	xts = malloc(bytes);
	if (!xts) {
		fprintf(stderr, "xattr total mem alloc failed\n");
		ret = -ENOMEM;
		goto out;
	}

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	memset(&rxt, 0, sizeof(rxt));
	rxt.totals_ptr = (unsigned long)xts;
	rxt.totals_bytes = bytes;

	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_READ_XATTR_TOTALS, &rxt);
		if (ret == 0)
			break;
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "read_xattr_totals ioctl failed: "
				"%s (%d)\n", strerror(errno), errno);
			goto out;
		}

		for (i = 0, xt = xts; i < ret; i++, xt++)
			printf("%llu.%llu.%llu = %lld, %lld\n",
				xt->name[0], xt->name[1], xt->name[2], xt->total, xt->count);

		memcpy(&rxt.pos_name, &xts[ret - 1].name, sizeof(rxt.pos_name));
		if (++rxt.pos_name[2] == 0 && ++rxt.pos_name[1] == 0 && ++rxt.pos_name[0] == 0)
			break;
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(xts);

	return ret;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct xattr_args *args = state->input;

	switch (key) {
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
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"",
	"Print global value totals of .totl. xattrs"
};

static int read_xattr_totals_cmd(int argc, char **argv)
{

	struct xattr_args xattr_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &xattr_args);
	if (ret)
		return ret;

	return do_read_xattr_totals(&xattr_args);
}

static void __attribute__((constructor)) read_xattr_totals_ctor(void)
{
	cmd_register_argp("read-xattr-totals", &argp, GROUP_INFO, read_xattr_totals_cmd);
}
