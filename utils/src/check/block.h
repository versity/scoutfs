#ifndef _SCOUTFS_UTILS_CHECK_BLOCK_H_
#define _SCOUTFS_UTILS_CHECK_BLOCK_H_

#include <unistd.h>
#include <stdbool.h>

struct block;

#include "sparse.h"

/* block flags passed to block_get() */
enum {
	BF_ZERO      = (1 << 0), /* zero contents buf as block is returned */
	BF_DIRTY     = (1 << 1), /* block will be written with transaction */
	BF_SM        = (1 << 2), /* small 4k block instead of large 64k block */
	BF_OVERWRITE = (1 << 3), /* caller will overwrite contents, don't read */
};

int block_get(struct block **blk_ret, u64 blkno, int bf);
void block_put(struct block **blkp);

void *block_buf(struct block *blk);
size_t block_size(struct block *blk);
void block_drop(struct block **blkp);

void block_readahead(u64 *blknos, size_t nr);
int block_try_commit(bool force);

int block_setup(int meta_fd, size_t max_cached_bytes, size_t max_dirty_bytes);
void block_shutdown(void);

int block_hdr_valid(struct block *blk, u64 blkno, int bf, u32 magic);

#endif
