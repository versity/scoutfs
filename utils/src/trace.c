#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "sparse.h"
#include "util.h"
#include "ioctl.h"
#include "cmd.h"

static int get_ibuf(int fd, int cmd, struct scoutfs_ioctl_buf *ibuf)
{
	int ret;

	ibuf->ptr = 0;
	ret = 1024 * 1024;
	do {
		ibuf->len = ret;
		if (ibuf->ptr)
			free((void *)(intptr_t)ibuf->ptr);
		ibuf->ptr = (intptr_t)malloc(ibuf->len);
		if (!ibuf->ptr) {
			ret = -errno;
			fprintf(stderr, "allocate %d bytes failed: %s (%d)\n",
				ibuf->len, strerror(errno), errno);
			break;
		}

		ret = ioctl(fd, cmd, ibuf);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "ioctl cmd %u failed: %s (%d)\n",
				cmd, strerror(errno), errno);
			break;
		}
	} while (ret > ibuf->len);

	if (ret >= 0) {
		ibuf->len = ret;
		ret = 0;
	}

	return ret;
}

static int decode_u64_bytes(struct scoutfs_trace_record *rec, u64 *args)
{
	u8 *data;
	int shift;
	u64 val;
	int i;

	data = rec->data;
	for (i = 0; i < rec->nr; i++) {
		val = 0;
		shift = 0;
		for (;;) {
			val |= (u64)(*data & 127) << shift;

			if (!((*(data++)) & 128))
				break;

			shift += 7;
		}

		args[i] = val;
	}

	return data - rec->data;
}

/* MY EYES */
static void printf_nr_args(char *fmt, int nr, u64 *args)
{
	switch(nr) {
	case 0: printf(fmt); break;
	case 1: printf(fmt, args[0]); break;
	case 2: printf(fmt, args[0], args[1]); break;
	case 3: printf(fmt, args[0], args[1], args[2]); break;
	case 4: printf(fmt, args[0], args[1], args[2], args[3]); break;
	case 5: printf(fmt, args[0], args[1], args[2], args[3], args[4]); break;
	case 6: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5]); break;
	case 7: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6]); break;
	case 8: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7]); break;
	case 9: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8]); break;
	case 10: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8], args[9]); break;
	case 11: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8], args[9],
		       args[10]); break;
	case 12: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8], args[9],
		       args[10], args[11]); break;
	case 13: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8], args[9],
		       args[10], args[11], args[12]); break;
	case 14: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8], args[9],
		       args[10], args[11], args[12], args[13]); break;
	case 15: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8], args[9],
		       args[10], args[11], args[12], args[13], args[14]); break;
	case 16: printf(fmt, args[0], args[1], args[2], args[3], args[4],
		       args[5], args[6], args[7], args[8], args[9],
		       args[10], args[11], args[12], args[13], args[14],
		       args[15]); break;
	default:
		 printf("(too many args: fmt '%s' nr %d)\n", fmt, nr);
		 break;
	}
}

static int trace_cmd(int argc, char **argv)
{
	char *path = "/sys/kernel/debug/scoutfs/trace";
	struct scoutfs_ioctl_buf fmts = {0,};
	struct scoutfs_ioctl_buf recs = {0,};
	struct scoutfs_trace_record *rec;
	u64 args[32]; /* absurdly huge */
	int off;
	int ret;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	/*
	 * Read the formats and records.  Our fd on the debugfs file
	 * should prevent the module from unloading which is the only
	 * way the per-module formats could change.
	 */
	ret = get_ibuf(fd, SCOUTFS_IOC_GET_TRACE_FORMATS, &fmts) ?:
	      get_ibuf(fd, SCOUTFS_IOC_GET_TRACE_RECORDS, &recs);
	if (ret)
		goto out;

	for (off = 0; off < recs.len; ) {
		rec = (void *)(intptr_t)(recs.ptr + off);
		off += sizeof(*rec) + decode_u64_bytes(rec, args);

		printf_nr_args((char *)fmts.ptr + rec->format_off,
			       rec->nr, args);
		printf("\n");
	}

out:
	close(fd);
	return ret;
};

static void __attribute__((constructor)) trace_ctor(void)
{
	cmd_register("trace", "<device>", "print scoutfs kernel traces",
		     trace_cmd);
}
