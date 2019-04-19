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

static int parse_u64(char *str, u64 *val_ret)
{
	unsigned long long ull;
	char *endptr = NULL;

	ull = strtoull(str, &endptr, 0);
	if (*endptr != '\0' ||
	    ((ull == LLONG_MIN || ull == LLONG_MAX) &&
	     errno == ERANGE)) {
		fprintf(stderr, "invalid 64bit value: '%s'\n", str);
		*val_ret = 0;
		return -EINVAL;
	}

	*val_ret = ull;

	return 0;
}

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
			argv[4], strerror(errno), errno);
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
