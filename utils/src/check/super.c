#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "crc.h"

#include "block.h"
#include "super.h"
#include "problem.h"

/*
 * After we check the super blocks we provide a global buffer to track
 * the current super block.  It is referenced to get static information
 * about the system and is also modified and written as part of
 * transactions.
 */
struct scoutfs_super_block *global_super;

/*
 * Check superblock crc. We can't use global_super here since it's not the
 * whole block itself, but only the struct scoutfs_super_block, so it needs
 * to reload a copy here.
 */
int check_super_crc(bool repair)
{
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_block_header *hdr;
	struct block *blk = NULL;
	u32 crc;
	int ret;

	ret = block_get(&blk, SCOUTFS_SUPER_BLKNO, BF_SM | BF_DIRTY);
	if (ret < 0) {
		fprintf(stderr, "error reading super block\n");
		return ret;
	}

	super = block_buf(blk);
	crc = crc_block((struct scoutfs_block_header *)super, block_size(blk));
	hdr = &global_super->hdr;
	debug("superblock crc 0x%04x calculated 0x%04x " "%s", hdr->crc, crc, hdr->crc == crc ? "(match)" : "(mismatch)");

	if (crc != hdr->crc) {
		problem(PB_SB_HDR_CRC_INVALID, "crc 0x%04x calculated 0x%04x", hdr->crc, crc);
		if (repair) {
			super->hdr.crc = crc;
			block_try_commit(true);
		}
	}
	block_put(&blk);

	return 0;
}

/*
 * After checking the supers we save a copy of it in a global buffer that's used by
 * other modules to track the current super.  It can be modified and written during commits.
 */
int check_supers(void)
{
	struct scoutfs_super_block *super = NULL;
	struct block *blk = NULL;
	int ret;

	global_super = malloc(sizeof(struct scoutfs_super_block));
	if (!global_super) {
		fprintf(stderr, "error allocating super block buffer\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = block_get(&blk, SCOUTFS_SUPER_BLKNO, BF_SM);
	if (ret < 0) {
		fprintf(stderr, "error reading super block\n");
		goto out;
	}

	super = block_buf(blk);

	memcpy(global_super, super, sizeof(struct scoutfs_super_block));
	ret = 0;
out:
	block_put(&blk);

	return ret;
}

void super_shutdown(void)
{
	free(global_super);
}
