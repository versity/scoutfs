#ifndef _SCOUTFS_ALLOC_H_
#define _SCOUTFS_ALLOC_H_

#include "ext.h"

/*
 * These are implementation-specific metrics, they don't need to be
 * consistent across implementations.  They should probably be run-time
 * knobs.
 */

/*
 * The largest extent that we'll try to allocate with fallocate.  We're
 * trying not to completely consume a transactions data allocation all
 * at once.  This is only allocation granularity, repeated allocations
 * can produce large contiguous extents.
 */
#define SCOUTFS_FALLOCATE_ALLOC_LIMIT \
	(128ULL * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * The largest aligned region that we'll try to allocate at the end of
 * the file as it's extended.  This is also limited to the current file
 * size so we can only waste at most twice the total file size when
 * files are less than this.  We try to keep this around the point of
 * diminishing returns in streaming performance of common data devices
 * to limit waste.
 */
#define SCOUTFS_DATA_EXTEND_PREALLOC_LIMIT \
	(8ULL * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * Small data allocations are satisfied by cached extents stored in
 * the run-time alloc struct to minimize item operations for small
 * block allocations.  Large allocations come directly from btree
 * extent items, and this defines the threshold beetwen them.
 */
#define SCOUTFS_ALLOC_DATA_LG_THRESH \
	(8ULL * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)

/* the client will force commits if data allocators get too low */
#define SCOUTFS_ALLOC_DATA_REFILL_THRESH \
	((256ULL * 1024 * 1024) >> SCOUTFS_BLOCK_SM_SHIFT)

/*
 * Fill client alloc roots to the target when they fall below the lo
 * threshold.
 *
 * We're giving the client the most available meta blocks we can so that
 * it has the freedom to build large transactions before worrying that
 * it might run out of meta allocs during commits.
 */
#define SCOUTFS_SERVER_META_FILL_TARGET \
	SCOUTFS_ALLOC_LIST_MAX_BLOCKS
#define SCOUTFS_SERVER_META_FILL_LO \
	(SCOUTFS_ALLOC_LIST_MAX_BLOCKS / 2)
#define SCOUTFS_SERVER_DATA_FILL_TARGET \
	(4ULL * 1024 * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)
#define SCOUTFS_SERVER_DATA_FILL_LO \
	(1ULL * 1024 * 1024 * 1024 >> SCOUTFS_BLOCK_SM_SHIFT)


/*
 * Log merge meta allocations are only used for one request and will
 * never use more than the dirty limit.
 */
#define SCOUTFS_LOG_MERGE_DIRTY_BYTE_LIMIT	(64ULL * 1024 * 1024)
/* a few extra blocks for alloc blocks */
#define SCOUTFS_SERVER_MERGE_FILL_TARGET	\
	((SCOUTFS_LOG_MERGE_DIRTY_BYTE_LIMIT >> SCOUTFS_BLOCK_LG_SHIFT) + 4)
#define SCOUTFS_SERVER_MERGE_FILL_LO		SCOUTFS_SERVER_MERGE_FILL_TARGET

/*
 * A run-time use of a pair of persistent avail/freed roots as a
 * metadata allocator.  It has the machinery needed to lock and avoid
 * recursion when dirtying the list blocks that are used during the
 * transaction.
 */
struct scoutfs_alloc {
	/* writers rarely modify list_head avail/freed.  readers often check for _meta_alloc_low */
	seqlock_t seqlock;
	struct mutex mutex;
	struct scoutfs_block *dirty_avail_bl;
	struct scoutfs_block *dirty_freed_bl;
	struct scoutfs_alloc_list_head avail;
	struct scoutfs_alloc_list_head freed;
};

/*
 * A run-time data allocator.  We have a cached extent in memory that is
 * a lot cheaper to work with than the extent items, and we have a
 * consistent record of the total_len that can be sampled outside of the
 * usual heavy serialization of the extent modifications.
 */
struct scoutfs_data_alloc {
	struct scoutfs_alloc_root root;
	struct scoutfs_extent cached;
	atomic64_t total_len;
};

void scoutfs_alloc_init(struct scoutfs_alloc *alloc,
			struct scoutfs_alloc_list_head *avail,
			struct scoutfs_alloc_list_head *freed);
int scoutfs_alloc_prepare_commit(struct super_block *sb,
				 struct scoutfs_alloc *alloc,
				 struct scoutfs_block_writer *wri);

int scoutfs_alloc_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri, u64 *blkno);
int scoutfs_free_meta(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri, u64 blkno);

void scoutfs_dalloc_init(struct scoutfs_data_alloc *dalloc,
			 struct scoutfs_alloc_root *data_avail);
void scoutfs_dalloc_get_root(struct scoutfs_data_alloc *dalloc,
			     struct scoutfs_alloc_root *data_avail);
u64 scoutfs_dalloc_total_len(struct scoutfs_data_alloc *dalloc);
int scoutfs_dalloc_return_cached(struct super_block *sb,
				 struct scoutfs_alloc *alloc,
				 struct scoutfs_block_writer *wri,
				 struct scoutfs_data_alloc *dalloc);
int scoutfs_alloc_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_data_alloc *dalloc, u64 count,
		       u64 *blkno_ret, u64 *count_ret);
int scoutfs_free_data(struct super_block *sb, struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_alloc_root *root, u64 blkno, u64 count);

int scoutfs_alloc_move(struct super_block *sb, struct scoutfs_alloc *alloc,
		       struct scoutfs_block_writer *wri,
		       struct scoutfs_alloc_root *dst,
		       struct scoutfs_alloc_root *src, u64 total,
		       __le64 *exclusive, __le64 *vacant, u64 zone_blocks, u64 meta_reserved);
int scoutfs_alloc_insert(struct super_block *sb, struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri, struct scoutfs_alloc_root *root,
			 u64 start, u64 len);
int scoutfs_alloc_remove(struct super_block *sb, struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri, struct scoutfs_alloc_root *root,
			 u64 start, u64 len);

int scoutfs_alloc_fill_list(struct super_block *sb,
			    struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_alloc_list_head *lhead,
			    struct scoutfs_alloc_root *root,
			    u64 lo, u64 target);
int scoutfs_alloc_empty_list(struct super_block *sb,
			     struct scoutfs_alloc *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_alloc_root *root,
			     struct scoutfs_alloc_list_head *lhead);
int scoutfs_alloc_splice_list(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_alloc_list_head *dst,
			      struct scoutfs_alloc_list_head *src);

bool scoutfs_alloc_meta_low(struct super_block *sb,
			    struct scoutfs_alloc *alloc, u32 nr);
void scoutfs_alloc_meta_remaining(struct scoutfs_alloc *alloc, u32 *avail_total, u32 *freed_space);
bool scoutfs_alloc_meta_low_since(struct scoutfs_alloc *alloc, u32 avail_start, u32 freed_start,
				  u32 budget, u32 nr);
bool scoutfs_alloc_test_flag(struct super_block *sb,
			    struct scoutfs_alloc *alloc, u32 flag);

typedef int (*scoutfs_alloc_foreach_cb_t)(struct super_block *sb, void *arg,
					  int owner, u64 id,
					  bool meta, bool avail, u64 blocks);
int scoutfs_alloc_foreach(struct super_block *sb,
			  scoutfs_alloc_foreach_cb_t cb, void *arg);
int scoutfs_alloc_foreach_super(struct super_block *sb, struct scoutfs_super_block *super,
				scoutfs_alloc_foreach_cb_t cb, void *arg);

typedef void (*scoutfs_alloc_extent_cb_t)(struct super_block *sb, void *cb_arg,
					  struct scoutfs_extent *ext);
int scoutfs_alloc_extents_cb(struct super_block *sb, struct scoutfs_alloc_root *root,
			     scoutfs_alloc_extent_cb_t cb, void *cb_arg);

#endif
