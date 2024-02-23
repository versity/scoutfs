#define _ISOC11_SOURCE /* aligned_alloc */
#define _DEFAULT_SOURCE /* syscall() */
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/aio_abi.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "list.h"
#include "cmp.h"
#include "hash.h"

#include "block.h"
#include "debug.h"
#include "eno.h"

static struct block_data {
	struct list_head *hash_lists;
	size_t hash_nr;

	struct list_head active_head;
	struct list_head inactive_head;
	struct list_head dirty_list;
	size_t nr_active;
	size_t nr_inactive;
	size_t nr_dirty;

	int meta_fd;
	size_t max_cached;
	size_t nr_events;

	aio_context_t ctx;
	struct iocb *iocbs;
	struct iocb **iocbps;
	struct io_event *events;
} global_bdat;

struct block {
	struct list_head hash_head;
	struct list_head lru_head;
	struct list_head dirty_head;
	struct list_head submit_head;
	unsigned long refcount;
	unsigned long uptodate:1,
		      active:1;
	u64 blkno;
	void *buf;
	size_t size;
};

#define BLK_FMT \
	"blkno %llu rc %ld d %u a %u"
#define BLK_ARG(blk) \
	(blk)->blkno, (blk)->refcount, !list_empty(&(blk)->dirty_head), blk->active
#define debug_blk(blk, fmt, args...) \
	debug(fmt " " BLK_FMT, ##args, BLK_ARG(blk))

/*
 * This just allocates and initialzies the block.  The caller is
 * responsible for putting it on the appropriate initial lists and
 * managing refcounts.
 */
static struct block *alloc_block(struct block_data *bdat, u64 blkno, size_t size)
{
	struct block *blk;

	blk = calloc(1, sizeof(struct block));
	if (blk) {
		blk->buf = aligned_alloc(4096, size); /* XXX static alignment :/ */
		if (!blk->buf) {
			free(blk);
			blk = NULL;
		} else {
			INIT_LIST_HEAD(&blk->hash_head);
			INIT_LIST_HEAD(&blk->lru_head);
			INIT_LIST_HEAD(&blk->dirty_head);
			INIT_LIST_HEAD(&blk->submit_head);
			blk->blkno = blkno;
			blk->size = size;
		}
	}

	return blk;
}

static void free_block(struct block_data *bdat, struct block *blk)
{
	debug_blk(blk, "free");

	if (!list_empty(&blk->lru_head)) {
		if (blk->active)
			bdat->nr_active--;
		else
			bdat->nr_inactive--;
		list_del(&blk->lru_head);
	}

	if (!list_empty(&blk->dirty_head)) {
		bdat->nr_dirty--;
		list_del(&blk->dirty_head);
	}

	if (!list_empty(&blk->hash_head))
		list_del(&blk->hash_head);

	if (!list_empty(&blk->submit_head))
		list_del(&blk->submit_head);

	free(blk->buf);
	free(blk);
}

static bool blk_is_dirty(struct block *blk)
{
	return !list_empty(&blk->dirty_head);
}

/*
 * Rebalance the cache.
 *
 * First we shrink the cache to limit it to max_cached blocks.
 * Logically, we walk from oldest to newest in the inactive list and
 * then in the active list.  Since these lists are physically one
 * list_head list we achieve this with a reverse walk starting from the
 * active head.
 *
 * Then we rebalnace the size of the two lists.  The constraint is that
 * we don't let the active list grow larger than the inactive list.  We
 * move blocks from the oldest tail of the active list to the newest
 * head of the inactive list.
 *
 * <- [active head] <-> [ .. active list .. ] <-> [inactive head] <-> [ .. inactive list .. ] ->
 */
static void rebalance_cache(struct block_data *bdat)
{
	struct block *blk;
	struct block *blk_;

	list_for_each_entry_safe_reverse(blk, blk_, &bdat->active_head, lru_head) {
		if ((bdat->nr_active + bdat->nr_inactive) < bdat->max_cached)
			break;

		if (&blk->lru_head == &bdat->inactive_head || blk->refcount > 0 ||
		    blk_is_dirty(blk))
			continue;

		free_block(bdat, blk);
	}

	list_for_each_entry_safe_reverse(blk, blk_, &bdat->inactive_head, lru_head) {
		if (bdat->nr_active <= bdat->nr_inactive || &blk->lru_head == &bdat->active_head)
			break;

		list_move(&blk->lru_head, &bdat->inactive_head);
		blk->active = 0;
		bdat->nr_active--;
		bdat->nr_inactive++;
	}
}

static void make_active(struct block_data *bdat, struct block *blk)
{
	if (!blk->active) {
		if (!list_empty(&blk->lru_head)) {
			list_move(&blk->lru_head, &bdat->active_head);
			bdat->nr_inactive--;
		} else {
			list_add(&blk->lru_head, &bdat->active_head);
		}

		blk->active = 1;
		bdat->nr_active++;
	}
}

static int compar_iocbp(const void *A, const void *B)
{
	struct iocb *a = *(struct iocb **)A;
	struct iocb *b = *(struct iocb **)B;

	return scoutfs_cmp(a->aio_offset, b->aio_offset);
}

static int submit_and_wait(struct block_data *bdat, struct list_head *list)
{
	struct io_event *event;
	struct iocb *iocb;
	struct block *blk;
	int ret;
	int err;
	int nr;
	int i;

	err = 0;
	nr = 0;
	list_for_each_entry(blk, list, submit_head) {
		iocb = &bdat->iocbs[nr];
		bdat->iocbps[nr] = iocb;

		memset(iocb, 0, sizeof(struct iocb));

		iocb->aio_data = (intptr_t)blk;
		iocb->aio_lio_opcode = blk_is_dirty(blk) ? IOCB_CMD_PWRITE : IOCB_CMD_PREAD;
		iocb->aio_fildes = bdat->meta_fd;
		iocb->aio_buf = (intptr_t)blk->buf;
		iocb->aio_nbytes = blk->size;
		iocb->aio_offset = blk->blkno * blk->size;

		nr++;

		debug_blk(blk, "submit");

		if ((nr < bdat->nr_events) && blk->submit_head.next != list)
			continue;

		qsort(bdat->iocbps, nr, sizeof(bdat->iocbps[0]), compar_iocbp);

		ret = syscall(__NR_io_submit, bdat->ctx, nr, bdat->iocbps);
		if (ret != nr) {
			if (ret >= 0)
				errno = EIO;
			ret = -errno;
			printf("fatal system error submitting async IO: "ENO_FMT"\n",
				ENO_ARG(-ret));
			goto out;
		}

		ret = syscall(__NR_io_getevents, bdat->ctx, nr, nr, bdat->events, NULL);
		if (ret != nr) {
			if (ret >= 0)
				errno = EIO;
			ret = -errno;
			printf("fatal system error getting IO events: "ENO_FMT"\n",
				ENO_ARG(-ret));
			goto out;
		}

		ret = 0;
		for (i = 0; i < nr; i++) {
			event = &bdat->events[i];
			iocb = (struct iocb *)(intptr_t)event->obj;
			blk = (struct block *)(intptr_t)event->data;

			debug_blk(blk, "complete res %lld", (long long)event->res);

			if (event->res >= 0 && event->res != blk->size)
				event->res = -EIO;

			/* io errors are fatal */
			if (event->res < 0) {
				ret = event->res;
				goto out;
			}

			if (iocb->aio_lio_opcode == IOCB_CMD_PREAD) {
				blk->uptodate = 1;
			} else {
				list_del_init(&blk->dirty_head);
				bdat->nr_dirty--;
			}
		}
		nr = 0;
	}

	ret = 0;
out:
	return ret ?: err;
}

static void inc_refcount(struct block *blk)
{
	blk->refcount++;
}

void block_put(struct block **blkp)
{
	struct block_data *bdat = &global_bdat;
	struct block *blk = *blkp;

	if (blk) {
		blk->refcount--;
		*blkp = NULL;

		rebalance_cache(bdat);
	}
}

static struct list_head *hash_bucket(struct block_data *bdat, u64 blkno)
{
	u32 hash = scoutfs_hash32(&blkno, sizeof(blkno));

	return &bdat->hash_lists[hash % bdat->hash_nr];
}

static struct block *get_or_alloc(struct block_data *bdat, u64 blkno, int bf)
{
	struct list_head *bucket = hash_bucket(bdat, blkno);
	struct block *search;
	struct block *blk;
	size_t size;

	size = (bf & BF_SM) ? SCOUTFS_BLOCK_SM_SIZE : SCOUTFS_BLOCK_LG_SIZE;

	blk = NULL;
	list_for_each_entry(search, bucket, hash_head) {
		if (search->blkno && blkno && search->size == size) {
			blk = search;
			break;
		}
	}

	if (!blk) {
		blk = alloc_block(bdat, blkno, size);
		if (blk) {
			list_add(&blk->hash_head, bucket);
			list_add(&blk->lru_head, &bdat->inactive_head);
			bdat->nr_inactive++;
		}
	}
	if (blk)
		inc_refcount(blk);

	return blk;
}

/*
 * Get a block.
 *
 * The caller holds a refcount to the block while it's in use that
 * prevents it from being removed from the cache.  It must be dropped
 * with block_put();
 */
int block_get(struct block **blk_ret, u64 blkno, int bf)
{
	struct block_data *bdat = &global_bdat;
	struct block *blk;
	LIST_HEAD(list);
	int ret;

	blk = get_or_alloc(bdat, blkno, bf);
	if (!blk) {
		ret = -ENOMEM;
		goto out;
	}

	if ((bf & BF_ZERO)) {
		memset(blk->buf, 0, blk->size);
		blk->uptodate = 1;
	}

	if (bf & BF_OVERWRITE)
		blk->uptodate = 1;

	if (!blk->uptodate) {
		list_add(&blk->submit_head, &list);
		ret = submit_and_wait(bdat, &list);
		list_del_init(&blk->submit_head);
		if (ret < 0)
			goto out;
	}

	if ((bf & BF_DIRTY) && !blk_is_dirty(blk)) {
		list_add_tail(&bdat->dirty_list, &blk->dirty_head);
		bdat->nr_dirty++;
	}

	make_active(bdat, blk);

	rebalance_cache(bdat);
	ret = 0;
out:
	if (ret < 0)
		block_put(&blk);
	*blk_ret = blk;
	return ret;
}

void *block_buf(struct block *blk)
{
	return blk->buf;
}

size_t block_size(struct block *blk)
{
	return blk->size;
}

/*
 * Drop the block from the cache, regardless of if it was free or not.
 * This is used to avoid writing blocks which were dirtied but then
 * later freed.
 *
 * The block is immediately freed and can't be referenced after this
 * returns.
 */
void block_drop(struct block **blkp)
{
	struct block_data *bdat = &global_bdat;

	free_block(bdat, *blkp);
	*blkp = NULL;
	rebalance_cache(bdat);
}

/*
 * This doesn't quite work for mixing large and small blocks, but that's
 * fine, we never do that.
 */
static int compar_u64(const void *A, const void *B)
{
	u64 a = *((u64 *)A);
	u64 b = *((u64 *)B);

	return scoutfs_cmp(a, b);
}

/*
 * This read-ahead is synchronous and errors are ignored.  If any of the
 * blknos aren't present in the cache then we issue concurrent reads for
 * them and wait.  Any existing cached blocks will be left as is.
 *
 * We might be trying to read a lot more than the number of events so we
 * sort the caller's blknos before iterating over them rather than
 * relying on submission sorting the blocks in each submitted set.
 */
void block_readahead(u64 *blknos, size_t nr)
{
	struct block_data *bdat = &global_bdat;
	struct block *blk;
	struct block *blk_;
	LIST_HEAD(list);
	size_t i;

	if (nr == 0)
		return;

	qsort(blknos, nr, sizeof(blknos[0]), compar_u64);

	for (i = 0; i < nr; i++) {
		blk = get_or_alloc(bdat, blknos[i], 0);
		if (blk) {
			if (!blk->uptodate)
				list_add_tail(&blk->submit_head, &list);
			else
				block_put(&blk);
		}
	}

	(void)submit_and_wait(bdat, &list);

	list_for_each_entry_safe(blk, blk_, &list, submit_head) {
		list_del_init(&blk->submit_head);
		block_put(&blk);
	}

	rebalance_cache(bdat);
}

/*
 * The caller's block changes form a consistent transaction.  If the amount of dirty
 * blocks is large enough we issue a write.
 */
int block_try_commit(bool force)
{
	struct block_data *bdat = &global_bdat;
	struct block *blk;
	struct block *blk_;
	LIST_HEAD(list);
	int ret;

	if (!force && bdat->nr_dirty < bdat->nr_events)
		return 0;

	list_for_each_entry(blk, &bdat->dirty_list, dirty_head) {
		list_add_tail(&blk->submit_head, &list);
		inc_refcount(blk);
	}

	ret = submit_and_wait(bdat, &list);

	list_for_each_entry_safe(blk, blk_, &list, submit_head) {
		list_del_init(&blk->submit_head);
		block_put(&blk);
	}

	if (ret < 0) {
		printf("error writing dirty transaction blocks\n");
		goto out;
	}

	ret = block_get(&blk, SCOUTFS_SUPER_BLKNO, BF_SM | BF_OVERWRITE | BF_DIRTY);
	if (ret == 0) {
		list_add(&blk->submit_head, &list);
		ret = submit_and_wait(bdat, &list);
		list_del_init(&blk->submit_head);
		block_put(&blk);
	} else {
		ret = -ENOMEM;
	}
	if (ret < 0)
		printf("error writing super block to commit transaction\n");

out:
	rebalance_cache(bdat);
	return ret;
}

int block_setup(int meta_fd, size_t max_cached_bytes, size_t max_dirty_bytes)
{
	struct block_data *bdat = &global_bdat;
	size_t i;
	int ret;

	bdat->max_cached = DIV_ROUND_UP(max_cached_bytes, SCOUTFS_BLOCK_LG_SIZE);
	bdat->hash_nr = bdat->max_cached / 4;
	bdat->nr_events = DIV_ROUND_UP(max_dirty_bytes, SCOUTFS_BLOCK_LG_SIZE);

	bdat->iocbs = calloc(bdat->nr_events, sizeof(bdat->iocbs[0]));
	bdat->iocbps = calloc(bdat->nr_events, sizeof(bdat->iocbps[0]));
	bdat->events = calloc(bdat->nr_events, sizeof(bdat->events[0]));
	bdat->hash_lists = calloc(bdat->hash_nr, sizeof(bdat->hash_lists[0]));
	if (!bdat->iocbs || !bdat->iocbps || !bdat->events || !bdat->hash_lists) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&bdat->active_head);
	INIT_LIST_HEAD(&bdat->inactive_head);
	INIT_LIST_HEAD(&bdat->dirty_list);
	bdat->meta_fd = meta_fd;
	list_add(&bdat->inactive_head, &bdat->active_head);

	for (i = 0; i < bdat->hash_nr; i++)
		INIT_LIST_HEAD(&bdat->hash_lists[i]);

	ret = syscall(__NR_io_setup, bdat->nr_events, &bdat->ctx);

out:
	if (ret < 0) {
		free(bdat->iocbs);
		free(bdat->iocbps);
		free(bdat->events);
		free(bdat->hash_lists);
	}

	return ret;
}

void block_shutdown(void)
{
	struct block_data *bdat = &global_bdat;

	syscall(SYS_io_destroy, bdat->ctx);

	free(bdat->iocbs);
	free(bdat->iocbps);
	free(bdat->events);
	free(bdat->hash_lists);
}
