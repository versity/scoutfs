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
#include <time.h>

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
#include "crc.h"

#include "problem.h"
#include "clobber.h"

/*
 * Clobber a meta extent
 */
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

/*
 * Clobber the CRC of the superblock by bit-flipping a random bit
 */
static int do_clobber_pb_sb_hdr_crc_invalid(char *data)
{
	struct scoutfs_super_block *super = NULL;
	struct block *blk = NULL;
	u32 crc;
	int ret;

	ret = block_get(&blk, SCOUTFS_SUPER_BLKNO, BF_SM | BF_DIRTY);
	if (ret < 0) {
		printf("error reading super block\n");
		return ret;
	}

	super = block_buf(blk);
	crc = crc_block((struct scoutfs_block_header *)super, block_size(blk));

	/* pick a random value [0,31] */
	srandom(time(NULL));
	u32 flip = random() & 0x1f;

	/* flip one bit with xor at the random position chosen */
	debug("clobber superblock crc from 0x%08x to 0x%08x\n", crc, crc ^ (1 << flip));
	super->hdr.crc = crc ^ (1 << flip);

	block_try_commit(true);

	block_put(&blk);

	fprintf(stderr, "do_clobber_pb_sb_hdr_crc_invalid()\n");
	return 0;
}

static struct clobber_function clobber_pb_sb_hdr_crc_invalid = {
	PB_SB_HDR_CRC_INVALID,
	"Sets an invalid CRC in the superblock.\n" \
	"DATA: no data used by this function\n",
	&do_clobber_pb_sb_hdr_crc_invalid,
};

/*
 * list all clobber functions
 */
struct clobber_function *clobber_functions[] = {
	&clobber_pb_meta_extent_invalid,
	&clobber_pb_sb_hdr_crc_invalid,
	NULL,
};
