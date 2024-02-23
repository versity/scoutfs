#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"

#include "block.h"
#include "super.h"

/*
 * After we check the super blocks we provide a global buffer to track
 * the current super block.  It is referenced to get static information
 * about the system and is also modified and written as part of
 * transactions.
 */
struct scoutfs_super_block *global_super;

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
