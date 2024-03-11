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

static int do_clobber_pb_meta_extent_invalid(char *data)
{
	fprintf(stderr, "do_clobber_pb_meta_extent_invalid()\n");
	return 0;
}

static struct clobber_function clobber_pb_meta_extent_invalid = {
	PB_META_EXTENT_INVALID,
	"Makes a metadata device extent invalid.\n" \
	"DATA: no data used by this function\n",
	&do_clobber_pb_meta_extent_invalid,
};

struct clobber_function *clobber_functions[] = {
	&clobber_pb_meta_extent_invalid,
	NULL,
};
