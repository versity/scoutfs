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

static int waiting_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_data_waiting_entry dwe[16];
	struct scoutfs_ioctl_data_waiting idw;
	int ret;
	int fd;
	int i;

	if (argc != 4) {
		fprintf(stderr, "must specify ino, iblock, and path\n");
		return -EINVAL;
	}

	ret = parse_u64(argv[1], &idw.after_ino) ?:
	      parse_u64(argv[2], &idw.after_iblock);
	if (ret)
		return ret;

	fd = open(argv[3], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[3], strerror(errno), errno);
		return ret;
	}

	idw.flags = 0;
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
			printf("ino %llu iblock %llu ops "
			       OP_FMT OP_FMT OP_FMT"\n",
			       dwe[i].ino, dwe[i].iblock,
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

static void __attribute__((constructor)) waiting_ctor(void)
{
	cmd_register("data-waiting", "<ino> <iblock> <path>",
		     "print ops waiting for data blocks", waiting_cmd);
}

static int data_wait_err_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_data_wait_err args;
	int fd = -1;
	int ret;

	memset(&args, 0, sizeof(args));

	if (argc != 8) {
		fprintf(stderr, "must specify path, ino, version, offset, count,op, and err\n");
		return -EINVAL;
	}

	ret = parse_u64(argv[2], &args.ino) ?:
	      parse_u64(argv[3], &args.data_version) ?:
	      parse_u64(argv[4], &args.offset) ?:
	      parse_u64(argv[5], &args.count) ?:
	      parse_s64(argv[7], &args.err);
	if (ret)
		return ret;

	if ((args.err >= 0) || (args.err < -MAX_ERRNO)) {
		fprintf(stderr, "err %lld invalid\n", args.err);
		ret = -EINVAL;
		goto out;
	}

	if (!strcmp(argv[6], "read")) {
		args.op = SCOUTFS_IOC_DWO_READ;
	} else if (!strcmp(argv[6], "write")) {
		args.op = SCOUTFS_IOC_DWO_WRITE;
	} else if (!strcmp(argv[6], "change_size")) {
		args.op = SCOUTFS_IOC_DWO_CHANGE_SIZE;
	} else {
		fprintf(stderr, "invalid data wait op: '%s'\n", argv[6]);
		return -EINVAL;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			argv[1], strerror(errno), errno);
		return ret;
	}

	ret = ioctl(fd, SCOUTFS_IOC_DATA_WAIT_ERR, &args);
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

static void __attribute__((constructor)) data_wait_err_ctor(void)
{
	cmd_register("data-wait-err", "<path> <ino> <vers> <offset> <count> <op> <err>",
		     "return error from matching waiters",
		     data_wait_err_cmd);
}
