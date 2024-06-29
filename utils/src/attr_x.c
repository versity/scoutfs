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

struct attr_x_args {
	bool set;
	char *filename;
	struct scoutfs_ioctl_inode_attr_x iax;
};

#define pr(iax, name, label, fmt, args...)			\
do {								\
	if ((iax->x_mask & SCOUTFS_IOC_IAX_##name)) {		\
		if (__builtin_popcount(iax->x_mask) > 1)	\
			printf(label ": " fmt "\n", ##args);	\
		else						\
			printf(fmt "\n", ##args);		\
	}							\
} while (0)

#define prb(iax, name, label) \
	pr(iax, name, label, "%u", !!((iax)->bits & SCOUTFS_IOC_IAX_B_##name))

static int do_attr_x(struct attr_x_args *args)
{
	struct scoutfs_ioctl_inode_attr_x *iax = &args->iax;
	int fd = -1;
	int ret;
	int op;

	if (args->set) {
		/* nothing to do if not setting */
		if (iax->x_mask == 0)
			return 0;
		op = SCOUTFS_IOC_SET_ATTR_X;
	} else {
		/* get all known if none specified */
		if (iax->x_mask == 0)
			iax->x_mask = ~SCOUTFS_IOC_IAX__UNKNOWN;
		op = SCOUTFS_IOC_GET_ATTR_X;
	}

	fd = open(args->filename, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->filename, strerror(errno), errno);
		goto out;
	}

	ret = ioctl(fd, op, iax);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "attr_x ioctl failed on '%s': "
			"%s (%d)\n", args->filename, strerror(errno), errno);
		goto out;
	}

	if (!args->set) {
		pr(iax, META_SEQ, "meta_seq", "%llu", iax->meta_seq);
		pr(iax, DATA_SEQ, "data_seq", "%llu", iax->data_seq);
		pr(iax, DATA_VERSION, "data_version", "%llu", iax->data_version);
		pr(iax, ONLINE_BLOCKS, "online_blocks", "%llu", iax->online_blocks);
		pr(iax, OFFLINE_BLOCKS, "offline_blocks", "%llu", iax->offline_blocks);
		pr(iax, CTIME, "ctime", "%llu.%u", iax->ctime_sec, iax->ctime_nsec);
		pr(iax, CRTIME, "crtime", "%llu.%u", iax->crtime_sec, iax->crtime_nsec);
		pr(iax, SIZE, "size", "%llu", iax->size);
		prb(iax, RETENTION, "retention");
		pr(iax, PROJECT_ID, "project_id", "%llu", iax->project_id);
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	return ret;
}

/*
 * This is called for both get and set.  The get calls won't have
 * arguments and are only setting the mask.  The set calls parse the
 * value to set.  We could have defaults by making set option arguments
 * optional, like setting the current time for timestamps, but that
 * hasn't been needed.
 *
 * Option value parsing places no constraints on the attributes or
 * values themselves once parsed.  This lets us use the set command to
 * test the kernel's testing for invalid attribute combinations and
 * values.
 */
static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct attr_x_args *args = state->input;
	struct timespec ts;
	int ret;
	u64 x;

	switch (key) {
	case 'm':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_META_SEQ;
		if (arg) {
			ret = parse_u64(arg, &args->iax.meta_seq);
			if (ret)
				return ret;
		}
		break;
	case 'd':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_DATA_SEQ;
		if (arg) {
			ret = parse_u64(arg, &args->iax.data_seq);
			if (ret)
				return ret;
		}
		break;
	case 'v':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_DATA_VERSION;
		if (arg) {
			ret = parse_u64(arg, &args->iax.data_version);
			if (ret)
				return ret;
			if (args->iax.data_version == 0)
				argp_error(state, "data version must not be 0");
		}
		break;
	case 'n':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_ONLINE_BLOCKS;
		if (arg) {
			ret = parse_u64(arg, &args->iax.online_blocks);
			if (ret)
				return ret;
		}
		break;
	case 'f':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_OFFLINE_BLOCKS;
		if (arg) {
			ret = parse_u64(arg, &args->iax.offline_blocks);
			if (ret)
				return ret;
		}
		break;
	case 'c':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_CTIME;
		if (arg) {
			ret = parse_timespec(arg, &ts);
			if (ret)
				return ret;
			args->iax.ctime_sec = ts.tv_sec;
			args->iax.ctime_nsec = ts.tv_nsec;
		}
		break;
	case 'r':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_CRTIME;
		if (arg) {
			ret = parse_timespec(arg, &ts);
			if (ret)
				return ret;
			args->iax.crtime_sec = ts.tv_sec;
			args->iax.crtime_nsec = ts.tv_nsec;
		}
		break;
	case 's':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_SIZE;
		if (arg) {
			ret = parse_u64(arg, &args->iax.size);
			if (ret)
				return ret;
		}
		break;
	case 't':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_RETENTION;
		if (arg) {
			ret = parse_u64(arg, &x);
			if (ret)
				return ret;
			if (x)
				args->iax.bits |= SCOUTFS_IOC_IAX_B_RETENTION;
		}
		break;
	case 'p':
		args->iax.x_mask |= SCOUTFS_IOC_IAX_PROJECT_ID;
		if (arg) {
			ret = parse_u64(arg, &args->iax.project_id);
			if (ret)
				return ret;
		}
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

/*
 * The get options are derived from these by copying the struct and
 * modifying fields.
 */
static struct argp_option set_options[] = {
	{ "meta_seq", 'm', "SEQ", 0, "Inode Metadata change index sequence number"},
	{ "data_seq", 'd', "SEQ", 0, "File Data change index sequence number"},
	{ "data_version", 'v', "VERSION", 0, "File Data contents version"},
	{ "online_blocks", 'n', "COUNT", 0, "Online data block count"},
	{ "offline_blocks", 'f', "COUNT", 0, "Offline data block count"},
	{ "ctime", 'c', "SECS.NSECS", 0, "Inode change time (posix ctime)"},
	{ "crtime", 'r', "SECS.NSECS", 0, "ScoutFS creation time"},
	{ "size", 's', "SIZE", 0, "Inode i_size field"},
	{ "retention", 't', "0|1", 0, "Retention flag"},
	{ "project_id", 'p', "PROJECT_ID", 0, "Project ID"},
	{ NULL }
};

static struct argp get_argp = {
	NULL, /* dynamically built */
	parse_opt,
	"FILE",
	"get extensible file attributes"
};

static int get_attr_x_cmd(int argc, char **argv)
{
	struct attr_x_args args = {0,};
	int ret;

	ret = argp_parse(&get_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_attr_x(&args);
}

/*
 * The set options match the get arguments but don't take argument
 * values to set.
 */
static void build_get_options(void)
{
	struct argp_option **opts = (struct argp_option **)&get_argp.options;
	int i;

	*opts = calloc(array_size(set_options), sizeof(set_options[0]));
	assert(*opts);

	memcpy(*opts, set_options, array_size(set_options) * sizeof(set_options[0]));

	for (i = 0; i < array_size(set_options) - 1; i++)
		(*opts)[i].arg = NULL;
}

static void __attribute__((constructor)) get_ctor(void)
{
	build_get_options();

	cmd_register_argp("get-attr-x", &get_argp, GROUP_AGENT, get_attr_x_cmd);
}

static struct argp set_argp = {
	set_options,
	parse_opt,
	"FILE",
	"Set extensible file attributes"
};

static int set_attr_x_cmd(int argc, char **argv)
{
	struct attr_x_args args = {.set = true,};
	int ret;

	ret = argp_parse(&set_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_attr_x(&args);
}

static void __attribute__((constructor)) set_ctor(void)
{
	cmd_register_argp("set-attr-x", &set_argp, GROUP_AGENT, set_attr_x_cmd);
}
