#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <argp.h>
#include <stdbool.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"
#include "parse.h"

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#endif

#define OP_FMT "%s%s"

/*
 * Print the caller's string for the bit if it's set, and if it's set
 * and there are more significant bits coming then we also print a
 * separating comma.
 */
#define op_str(ops, bit, str)				\
	(((ops) & (bit)) ? (str) : ""),			\
	(((ops) & (bit)) && ((ops) & ~(((bit) << 1) - 1)) ? "," : "")


struct waiting_args {
	char *path;
	bool inode_set;
	u64 inode;
	bool blkno_set;
	u64 blkno;
};

static int do_waiting(struct waiting_args *args)
{
	struct scoutfs_ioctl_data_waiting_entry dwe[16];
	struct scoutfs_ioctl_data_waiting idw;
	int ret;
	int fd;
	int i;

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	idw.flags = 0;
	idw.after_ino = args->inode;
	idw.after_iblock = args->blkno;
	idw.ents_ptr = (unsigned long)dwe;
	idw.ents_nr = array_size(dwe);

	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_DATA_WAITING, &idw);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "waiting ioctl failed: %s (%d)\n",
				strerror(errno), errno);
			break;
		} else if (ret == 0) {
			break;
		}

		for (i = 0; i < ret; i++)
			printf("ino %llu iblock %llu pid %i ops "
			       OP_FMT OP_FMT OP_FMT"\n",
			       dwe[i].ino, dwe[i].iblock, dwe[i].pid,
			       op_str(dwe[i].op, SCOUTFS_IOC_DWO_READ,
				      "read"),
			       op_str(dwe[i].op, SCOUTFS_IOC_DWO_WRITE,
				      "write"),
			       op_str(dwe[i].op, SCOUTFS_IOC_DWO_CHANGE_SIZE,
				      "change_size"));

		idw.after_ino = dwe[i - 1].ino;
		idw.after_iblock = dwe[i - 1].iblock;
	}

	close(fd);
	return ret;
};

static int waiting_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct waiting_args *args = state->input;
	int ret;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case 'I': /* inode */
		ret = parse_u64(arg, &args->inode);
		if (ret)
			argp_error(state, "inode parse error");
		args->inode_set = true;
		break;
	case 'B': /* blkno */
		ret = parse_u64(arg, &args->blkno);
		if (ret)
			argp_error(state, "blkno parse error");
		args->blkno_set = true;
		break;
	case ARGP_KEY_FINI:
		if (!args->inode_set)
			argp_error(state, "no inode given");
		if (!args->blkno_set)
			argp_error(state, "no blkno given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option waiting_options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "inode", 'I', "INODE-NUM", 0, "Inode number [Required]"},
	{ "block", 'B', "BLKNO-NUM", 0, "Block number [Required]"},
	{ NULL }
};

static struct argp waiting_argp = {
	waiting_options,
	waiting_parse_opt,
	"--inode INODE-NUM --block BLOCK-NUM",
	"Print operations waiting for data blocks"
};

static int waiting_cmd(int argc, char **argv)
{
	struct waiting_args waiting_args = {NULL};
	int ret;

	ret = argp_parse(&waiting_argp, argc, argv, 0, NULL, &waiting_args);
	if (ret)
		return ret;

	return do_waiting(&waiting_args);
}

static void __attribute__((constructor)) waiting_ctor(void)
{
	cmd_register_argp("data-waiting", &waiting_argp, GROUP_AGENT, waiting_cmd);
}

struct wait_err_args {
	char *path;
	bool inode_set;
	u64 inode;
	bool version_set;
	u64 version;
	bool offset_set;
	u64 offset;
	bool count_set;
	u64 count;
	char *op;
	bool err_set;
	s64 err;
};

static int do_wait_err(struct wait_err_args *args)
{
	struct scoutfs_ioctl_data_wait_err dwe = {0};
	int fd = -1;
	int ret;


	dwe.ino = args->inode;
	dwe.data_version = args->version;
	dwe.offset = args->offset;
	dwe.count = args->count;
	if (!strcmp(args->op, "read")) {
		dwe.op = SCOUTFS_IOC_DWO_READ;
	} else if (!strcmp(args->op, "write")) {
		dwe.op = SCOUTFS_IOC_DWO_WRITE;
	} else if (!strcmp(args->op, "change_size")) {
		dwe.op = SCOUTFS_IOC_DWO_CHANGE_SIZE;
	} else {
		fprintf(stderr, "invalid data wait op: '%s'\n", args->op);
		return -EINVAL;
	}
	dwe.err = args->err;

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	ret = ioctl(fd, SCOUTFS_IOC_DATA_WAIT_ERR, &dwe);
	if (ret < 0) {
		fprintf(stderr, "data_wait_err returned %d: error %s (%d)\n",
			ret, strerror(errno), errno);
		ret = -EIO;
		goto out;
	}
	printf("data_wait_err found %d waiters.\n", ret);

out:
	if (fd > -1)
		close(fd);
	return ret;
};

static int wait_err_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct wait_err_args *args = state->input;
	int ret;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case 'I': /* inode */
		ret = parse_u64(arg, &args->inode);
		if (ret)
			argp_error(state, "inode parse error");
		args->inode_set = true;
		break;
	case 'V': /* version */
		ret = parse_u64(arg, &args->version);
		if (ret)
			argp_error(state, "version parse error");
		args->version_set = true;
		break;
	case 'F': /* offset */
		ret = parse_human(arg, &args->offset);
		if (ret)
			argp_error(state, "version parse error");
		args->offset_set = true;
		break;
	case 'C': /* count */
		ret = parse_u64(arg, &args->count);
		if (ret)
			argp_error(state, "count parse error");
		args->count_set = true;
		break;
	case 'O': /* op */
		args->op = strdup_or_error(state, arg);
		break;
	case 'E': /* err */
		ret = parse_s64(arg, &args->err);
		if (ret)
			argp_error(state, "error parse error");
		if ((args->err >= 0) || (args->err < -MAX_ERRNO))
			argp_error(state, "errno out of range");
		args->err_set = true;
		break;
	case ARGP_KEY_FINI:
		if (!args->inode_set)
			argp_error(state, "no inode given");
		if (!args->version_set)
			argp_error(state, "no version given");
		if (!args->offset_set)
			argp_error(state, "no offset given");
		if (!args->count_set)
			argp_error(state, "no count given");
		if (!args->op)
			argp_error(state, "no operation given");
		if (!args->err_set)
			argp_error(state, "no error given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option wait_err_options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "inode", 'I', "INODE-NUM", 0, "Inode number [Required]"},
	{ "version", 'V', "VER-NUM", 0, "Version [Required]"},
	{ "offset", 'F', "OFF-NUM", 0, "Offset (bytes or KMGTP units) [Required]"},
	{ "count", 'C', "COUNT", 0, "Count [Required]"},
	{ "op", 'O', "OP", 0, "Operation: \"read\", \"write\", \"change_size\" [Required]"},
	{ "err", 'E', "ERR", 0, "Error [Required]"},
	{ NULL }
};

static struct argp wait_err_argp = {
	wait_err_options,
	wait_err_parse_opt,
	"--inode INODE-NUM --version VER-NUM "
	"--offset OFF-NUM --count COUNT --op OP --err ERR",
	"Return error from matching waiters"
};

static int wait_err_cmd(int argc, char **argv)
{
	struct wait_err_args wait_err_args = {NULL};
	int ret;

	ret = argp_parse(&wait_err_argp, argc, argv, 0, NULL, &wait_err_args);
	if (ret)
		return ret;

	return do_wait_err(&wait_err_args);
}


static void __attribute__((constructor)) data_wait_err_ctor(void)
{
	cmd_register_argp("data-wait-err", &wait_err_argp, GROUP_AGENT, wait_err_cmd);
}
