/*
 * Copyright (C) 2019 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/rhashtable.h>
#include <linux/random.h>

#include "format.h"
#include "super.h"
#include "block.h"
#include "counters.h"
#include "msg.h"
#include "scoutfs_trace.h"
#include "alloc.h"
#include "triggers.h"

/*
 * The scoutfs block cache manages metadata blocks that can be larger
 * than the page size.  Callers can have their own contexts for tracking
 * dirty blocks that are written together.  We pin dirty blocks in
 * memory and only checksum them all as they're all written.
 *
 * Memory reclaim is driven by maintaining two very coarse groups of
 * blocks.  As we access blocks we mark them with an increasing counter
 * to discourage them from being reclaimed.  We then define a threshold
 * at the current counter minus half the population.  Recent blocks have
 * a counter greater than the threshold, and all other blocks with
 * counters less than it are considered older and are candidates for
 * reclaim.  This results in access updates rarely modifying an atomic
 * counter as blocks need to be moved into the recent group, and shrink
 * can randomly scan blocks looking for the half of the population that
 * will be in the old group.  It's reasonably effective, but is
 * particularly efficient and avoids contention between concurrent
 * accesses and shrinking.
 */

struct block_info {
	struct super_block *sb;
	atomic_t total_inserted;
	atomic64_t access_counter;
	struct rhashtable ht;
	wait_queue_head_t waitq;
	struct shrinker shrinker;
	struct work_struct free_work;
	struct llist_head free_llist;
};

#define DECLARE_BLOCK_INFO(sb, name) \
	struct block_info *name = SCOUTFS_SB(sb)->block_info

enum block_status_bits {
	BLOCK_BIT_UPTODATE = 0,	/* contents consistent with media */
	BLOCK_BIT_NEW,		/* newly allocated, contents undefined */
	BLOCK_BIT_DIRTY,	/* dirty, writer will write */
	BLOCK_BIT_IO_BUSY,	/* bios are in flight */
	BLOCK_BIT_ERROR,	/* saw IO error */
	BLOCK_BIT_PAGE_ALLOC,	/* page (possibly high order) allocation */
	BLOCK_BIT_VIRT,		/* mapped virt allocation */
	BLOCK_BIT_CRC_VALID,	/* crc has been verified */
};

/*
 * We want to tie atomic changes in refcounts to whether or not the
 * block is still visible in the hash table, so we store the hash
 * table's reference up at a known high bit.  We could naturally set the
 * inserted bit through excessive refcount increments.  We don't do
 * anything about that but at least warn if we get close.
 *
 * We're avoiding the high byte for no real good reason, just out of a
 * historical fear of implementations that don't provide the full
 * precision.
 */
#define BLOCK_REF_INSERTED	(1U << 23)
#define BLOCK_REF_FULL		(BLOCK_REF_INSERTED >> 1)

struct block_private {
	struct scoutfs_block bl;
	struct super_block *sb;
	atomic_t refcount;
	u64 accessed;
	struct rhash_head ht_head;
	struct list_head dirty_entry;
	struct llist_node free_node;
	unsigned long bits;
	atomic_t io_count;
	union {
		struct page *page;
		void *virt;
	};
};

#define TRACE_BLOCK(which, bp)									\
do {												\
	__typeof__(bp) _bp = (bp);								\
	trace_scoutfs_block_##which(_bp->sb, _bp, _bp->bl.blkno, atomic_read(&_bp->refcount),	\
				    atomic_read(&_bp->io_count), _bp->bits, _bp->accessed);	\
} while (0)

#define BLOCK_PRIVATE(_bl) \
	container_of((_bl), struct block_private, bl)

static __le32 block_calc_crc(struct scoutfs_block_header *hdr, u32 size)
{
	int off = offsetof(struct scoutfs_block_header, crc) +
		  FIELD_SIZEOF(struct scoutfs_block_header, crc);
	u32 calc = crc32c(~0, (char *)hdr + off, size - off);

	return cpu_to_le32(calc);
}

static struct block_private *block_alloc(struct super_block *sb, u64 blkno)
{
	struct block_private *bp;
	unsigned int noio_flags;

	/*
	 * If we had multiple blocks per page we'd need to be a little
	 * more careful with a partial page allocator when allocating
	 * blocks.
	 */
	BUILD_BUG_ON(PAGE_SIZE > SCOUTFS_BLOCK_LG_SIZE);

	bp = kzalloc(sizeof(struct block_private), GFP_NOFS);
	if (!bp)
		goto out;

	bp->page = alloc_pages(GFP_NOFS | __GFP_NOWARN,
			       SCOUTFS_BLOCK_LG_PAGE_ORDER);
	if (bp->page) {
		scoutfs_inc_counter(sb, block_cache_alloc_page_order);
		set_bit(BLOCK_BIT_PAGE_ALLOC, &bp->bits);
		bp->bl.data = page_address(bp->page);
	} else {
		/*
		 * __vmalloc doesn't pass the gfp flags down to pte
		 * allocs, they're done with user alloc flags.
		 * Unfortunately, some lockdep doesn't know that
		 * PF_NOMEMALLOC prevents __GFP_FS reclaim and generates
		 * spurious reclaim-on dependencies and warnings.
		 */
		lockdep_off();
		noio_flags = memalloc_noio_save();
		bp->virt = __vmalloc(SCOUTFS_BLOCK_LG_SIZE, GFP_NOFS | __GFP_HIGHMEM, PAGE_KERNEL);
		memalloc_noio_restore(noio_flags);
		lockdep_on();

		if (!bp->virt) {
			kfree(bp);
			bp = NULL;
			goto out;
		}

		scoutfs_inc_counter(sb, block_cache_alloc_virt);
		set_bit(BLOCK_BIT_VIRT, &bp->bits);
		bp->bl.data = bp->virt;
	}

	bp->bl.blkno = blkno;
	bp->sb = sb;
	atomic_set(&bp->refcount, 1);
	INIT_LIST_HEAD(&bp->dirty_entry);
	set_bit(BLOCK_BIT_NEW, &bp->bits);
	atomic_set(&bp->io_count, 0);

	TRACE_BLOCK(allocate, bp);

out:
	if (!bp)
		scoutfs_inc_counter(sb, block_cache_alloc_failure);
	return bp;
}

static void block_free(struct super_block *sb, struct block_private *bp)
{
	scoutfs_inc_counter(sb, block_cache_free);

	TRACE_BLOCK(free, bp);

	if (test_bit(BLOCK_BIT_PAGE_ALLOC, &bp->bits))
		__free_pages(bp->page, SCOUTFS_BLOCK_LG_PAGE_ORDER);
	else if (test_bit(BLOCK_BIT_VIRT, &bp->bits))
		vfree(bp->virt);
	else
		BUG();

	WARN_ON_ONCE(!list_empty(&bp->dirty_entry));
	WARN_ON_ONCE(atomic_read(&bp->refcount));
	WARN_ON_ONCE(atomic_read(&bp->io_count));
	kfree(bp);
}

/*
 * Free all the blocks that were put in the free_llist.  We have to wait
 * for rcu grace periods to expire to ensure that no more rcu hash list
 * lookups can see the blocks.
 */
static void block_free_work(struct work_struct *work)
{
	struct block_info *binf = container_of(work, struct block_info, free_work);
	struct super_block *sb = binf->sb;
	struct block_private *bp;
	struct block_private *tmp;
	struct llist_node *deleted;

	scoutfs_inc_counter(sb, block_cache_free_work);

	deleted = llist_del_all(&binf->free_llist);
	synchronize_rcu();

	llist_for_each_entry_safe(bp, tmp, deleted, free_node) {
		block_free(sb, bp);
	}
}

/*
 * Get a reference to a block while holding an existing reference.
 */
static void block_get(struct block_private *bp)
{
	WARN_ON_ONCE((atomic_read(&bp->refcount) & ~BLOCK_REF_INSERTED) <= 0);

	atomic_inc(&bp->refcount);
}

/*
 * Get a reference to a block as long as it's been inserted in the hash
 * table and hasn't been removed.
 */ 
static struct block_private *block_get_if_inserted(struct block_private *bp)
{
	int cnt;

	do {
		cnt = atomic_read(&bp->refcount);
		WARN_ON_ONCE(cnt & BLOCK_REF_FULL);
		if (!(cnt & BLOCK_REF_INSERTED))
			return NULL;

	} while (atomic_cmpxchg(&bp->refcount, cnt, cnt + 1) != cnt);

	return bp;
}

/*
 * Drop the caller's reference.  If this was the final reference we
 * queue the block to be freed once the rcu period ends.  Readers can be
 * racing to try to get references to these blocks, but they won't get a
 * reference because the block isn't present in the hash table any more.
 */
static void block_put(struct super_block *sb, struct block_private *bp)
{
	DECLARE_BLOCK_INFO(sb, binf);
	int cnt;

	if (!IS_ERR_OR_NULL(bp)) {
		cnt = atomic_dec_return(&bp->refcount);
		if (cnt == 0) {
			llist_add(&bp->free_node, &binf->free_llist);
			schedule_work(&binf->free_work);
		} else {
			WARN_ON_ONCE(cnt < 0);
		}
	}
}

static const struct rhashtable_params block_ht_params = {
        .key_len = member_sizeof(struct block_private, bl.blkno),
        .key_offset = offsetof(struct block_private, bl.blkno),
        .head_offset = offsetof(struct block_private, ht_head),
};

/*
 * Insert a new block into the hash table.  Once it is inserted in the
 * hash table readers can start getting references.  The caller may have
 * multiple refs but the block can't already be inserted.
 */
static int block_insert(struct super_block *sb, struct block_private *bp)
{
	DECLARE_BLOCK_INFO(sb, binf);
	int ret;

	WARN_ON_ONCE(atomic_read(&bp->refcount) & BLOCK_REF_INSERTED);

retry:
	atomic_add(BLOCK_REF_INSERTED, &bp->refcount);
	ret = rhashtable_lookup_insert_fast(&binf->ht, &bp->ht_head, block_ht_params);
	if (ret < 0) {
		atomic_sub(BLOCK_REF_INSERTED, &bp->refcount);
		if (ret == -EBUSY) {
			/* wait for pending rebalance to finish */
			synchronize_rcu();
			goto retry;
		}
	} else {
		atomic_inc(&binf->total_inserted);
		TRACE_BLOCK(insert, bp);
	}

	return ret;
}

static u64 accessed_recently(struct block_info *binf)
{
	return atomic64_read(&binf->access_counter) - (atomic_read(&binf->total_inserted) >> 1);
}

/*
 * Make sure that a block that is being accessed is less likely to be
 * reclaimed if it is seen by the shrinker.   If the block hasn't been
 * accessed recently we update its accessed value.
 */
static void block_accessed(struct super_block *sb, struct block_private *bp)
{
	DECLARE_BLOCK_INFO(sb, binf);

	if (bp->accessed == 0 || bp->accessed < accessed_recently(binf)) {
		scoutfs_inc_counter(sb, block_cache_access_update);
		bp->accessed = atomic64_inc_return(&binf->access_counter);
	}
}

/*
 * The caller wants to remove the block from the hash table and has an
 * idea what the refcount should be.  If the refcount does still
 * indicate that the block is hashed, and we're able to clear that bit,
 * then we can remove it from the hash table.
 *
 * The caller makes sure that it's safe to be referencing this block,
 * either with their own held reference (most everything) or by being in
 * an rcu grace period (shrink).
 */
static bool block_remove_cnt(struct super_block *sb, struct block_private *bp, int cnt)
{
	DECLARE_BLOCK_INFO(sb, binf);
	int ret;

	if ((cnt & BLOCK_REF_INSERTED) &&
	    (atomic_cmpxchg(&bp->refcount, cnt, cnt & ~BLOCK_REF_INSERTED) == cnt)) {

		TRACE_BLOCK(remove, bp);
		ret = rhashtable_remove_fast(&binf->ht, &bp->ht_head, block_ht_params);
		WARN_ON_ONCE(ret); /* must have been inserted */
		atomic_dec(&binf->total_inserted);
		return true;
	}

	return false;
}

/*
 * Try to remove the block from the hash table as long as the refcount
 * indicates that it is still in the hash table.  This can be racing
 * with normal refcount changes so it might have to retry.
 */
static void block_remove(struct super_block *sb, struct block_private *bp)
{
	int cnt;

	do {
		cnt = atomic_read(&bp->refcount);
	} while ((cnt & BLOCK_REF_INSERTED) && !block_remove_cnt(sb, bp, cnt));
}

/*
 * Take one shot at removing the block from the hash table if it's still
 * in the hash table and the caller has the only other reference.
 */
static bool block_remove_solo(struct super_block *sb, struct block_private *bp)
{
	return block_remove_cnt(sb, bp, BLOCK_REF_INSERTED | 1);
}

static bool io_busy(struct block_private *bp)
{
	smp_rmb(); /* test after adding to wait queue */
	return test_bit(BLOCK_BIT_IO_BUSY, &bp->bits);
}

/*
 * Called during shutdown with no other users.
 */
static void block_remove_all(struct super_block *sb)
{
	DECLARE_BLOCK_INFO(sb, binf);
	struct rhashtable_iter iter;
	struct block_private *bp;

	rhashtable_walk_enter(&binf->ht, &iter);
	rhashtable_walk_start(&iter);

	for (;;) {
		bp = rhashtable_walk_next(&iter);
		if (bp == NULL)
			break;
		if (bp == ERR_PTR(-EAGAIN))
			continue;

		if (block_get_if_inserted(bp)) {
			block_remove(sb, bp);
			WARN_ON_ONCE(atomic_read(&bp->refcount) != 1);
			block_put(sb, bp);
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	WARN_ON_ONCE(atomic_read(&binf->total_inserted) != 0);
}

/*
 * XXX The io_count and sb fields in the block_private are only used
 * during IO.  We don't need to have them sitting around for the entire
 * lifetime of each cached block.
 *
 * This is happening in interrupt context so we do as little work as
 * possible.  Final freeing, verifying checksums, and unlinking errored
 * blocks are all done by future users of the blocks.
 */
static void block_end_io(struct super_block *sb, int rw,
			 struct block_private *bp, int err)
{
	DECLARE_BLOCK_INFO(sb, binf);
	bool is_read = !(rw & WRITE);

	if (err) {
		scoutfs_inc_counter(sb, block_cache_end_io_error);
		set_bit(BLOCK_BIT_ERROR, &bp->bits);
	}

	if (!atomic_dec_and_test(&bp->io_count))
		return;

	if (is_read && !test_bit(BLOCK_BIT_ERROR, &bp->bits))
		set_bit(BLOCK_BIT_UPTODATE, &bp->bits);

	clear_bit(BLOCK_BIT_IO_BUSY, &bp->bits);
	block_put(sb, bp);

	/* make sure set and cleared bits are visible to woken */
	smp_mb();

	if (waitqueue_active(&binf->waitq))
		wake_up(&binf->waitq);
}

static void block_bio_end_io(struct bio *bio, int err)
{
	struct block_private *bp = bio->bi_private;
	struct super_block *sb = bp->sb;

	TRACE_BLOCK(end_io, bp);
	block_end_io(sb, bio->bi_rw, bp, err);
	bio_put(bio);
}

/*
 * Kick off IO for a single block.
 */
static int block_submit_bio(struct super_block *sb, struct block_private *bp,
			    int rw)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct bio *bio = NULL;
	struct blk_plug plug;
	struct page *page;
	unsigned long off;
	sector_t sector;
	int ret = 0;

	sector = bp->bl.blkno << (SCOUTFS_BLOCK_LG_SHIFT - 9);

	WARN_ON_ONCE(bp->bl.blkno == U64_MAX);
	WARN_ON_ONCE(sector == U64_MAX || sector == 0);

	/* don't let racing end_io during submission think block is complete */
	atomic_inc(&bp->io_count);
	set_bit(BLOCK_BIT_IO_BUSY, &bp->bits);
	block_get(bp);

	blk_start_plug(&plug);

	for (off = 0; off < SCOUTFS_BLOCK_LG_SIZE; off += PAGE_SIZE) {
		if (!bio) {
			bio = bio_alloc(GFP_NOFS, SCOUTFS_BLOCK_LG_PAGES_PER);
			if (!bio) {
				ret = -ENOMEM;
				break;
			}

			bio->bi_sector = sector + (off >> 9);
			bio->bi_bdev = sbi->meta_bdev;
			bio->bi_end_io = block_bio_end_io;
			bio->bi_private = bp;

			atomic_inc(&bp->io_count);

			TRACE_BLOCK(submit, bp);
		}

		if (test_bit(BLOCK_BIT_PAGE_ALLOC, &bp->bits))
			page = virt_to_page((char *)bp->bl.data + off);
		else if (test_bit(BLOCK_BIT_VIRT, &bp->bits))
			page = vmalloc_to_page((char *)bp->bl.data + off);
		else
			BUG();

		if (!bio_add_page(bio, page, PAGE_SIZE, 0)) {
			submit_bio(rw, bio);
			bio = NULL;
		}
	}

	if (bio)
		submit_bio(rw, bio);

	blk_finish_plug(&plug);

	/* let racing end_io know we're done */
	block_end_io(sb, rw, bp, ret);

	return ret;
}

static struct block_private *block_lookup(struct super_block *sb, u64 blkno)
{
	DECLARE_BLOCK_INFO(sb, binf);
	struct block_private *bp;

	rcu_read_lock();
	bp = rhashtable_lookup(&binf->ht, &blkno, block_ht_params);
	if (bp)
		bp = block_get_if_inserted(bp);
	rcu_read_unlock();

	return bp;
}

/*
 * Return a reference to a cached block found in the hash table.  If one
 * isn't found then we try and allocate and insert a new one.  Its
 * contents are undefined if it's newly allocated.
 *
 * Our hash table lookups during rcu can be racing with shrinking and
 * removal from the hash table.  We only atomically get a reference if
 * the refcount indicates that the block is still present in the hash
 * table.
 */
static struct block_private *block_lookup_create(struct super_block *sb,
						 u64 blkno)
{
	struct block_private *bp;
	int ret;

restart:
	bp = block_lookup(sb, blkno);

	/* drop failed reads that interrupted waiters abandoned */
	if (bp && (test_bit(BLOCK_BIT_ERROR, &bp->bits) &&
	           !test_bit(BLOCK_BIT_DIRTY, &bp->bits))) {
		block_remove(sb, bp);
		block_put(sb, bp);
		bp = NULL;
	}

	if (!bp) {
		bp = block_alloc(sb, blkno);
		if (bp == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		ret = block_insert(sb, bp);
		if (ret < 0) {
			if (ret == -EEXIST) {
				block_put(sb, bp);
				goto restart;
			}
			goto out;
		}
	}

	block_accessed(sb, bp);
	ret = 0;

out:
	if (ret < 0) {
		block_put(sb, bp);
		return ERR_PTR(ret);
	}

	return bp;
}

static bool uptodate_or_error(struct block_private *bp)
{
	smp_rmb(); /* test after adding to wait queue */
	return test_bit(BLOCK_BIT_UPTODATE, &bp->bits) ||
	       test_bit(BLOCK_BIT_ERROR, &bp->bits);
}

static bool block_is_dirty(struct block_private *bp)
{
	return test_bit(BLOCK_BIT_DIRTY, &bp->bits) != 0;
}

static struct block_private *block_read(struct super_block *sb, u64 blkno)
{
	DECLARE_BLOCK_INFO(sb, binf);
	struct block_private *bp = NULL;
	int ret;

	bp = block_lookup_create(sb, blkno);
	if (IS_ERR(bp)) {
		ret = PTR_ERR(bp);
		goto out;
	}

	if (!test_bit(BLOCK_BIT_UPTODATE, &bp->bits) &&
	     test_and_clear_bit(BLOCK_BIT_NEW, &bp->bits)) {
		ret = block_submit_bio(sb, bp, READ);
		if (ret < 0)
			goto out;
	}

	ret = wait_event_interruptible(binf->waitq, uptodate_or_error(bp));
	if (ret == 0 && test_bit(BLOCK_BIT_ERROR, &bp->bits))
		ret = -EIO;

out:
	if (ret < 0) {
		block_put(sb, bp);
		return ERR_PTR(ret);
	}

	return bp;
}

/*
 * Read a referenced metadata block.
 *
 * The caller may be following a stale reference to a block location
 * that has since been rewritten.  We check that destination block
 * header fields match the reference.  If they don't, we return -ESTALE
 * and the caller can chose to retry with newer references or return an
 * error.  -ESTALE can be a sign of block corruption when the refs are
 * current.
 *
 * Once the caller has the cached block it won't be modified.  A writer
 * trying to dirty a block at that location will remove our existing
 * block and insert a new block with modified headers.
 */
int scoutfs_block_read_ref(struct super_block *sb, struct scoutfs_block_ref *ref, u32 magic,
			   struct scoutfs_block **bl_ret)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_block_header *hdr;
	struct block_private *bp = NULL;
	bool retried = false;
	int ret;

retry:
	bp = block_read(sb, le64_to_cpu(ref->blkno));
	if (IS_ERR(bp)) {
		ret = PTR_ERR(bp);
		goto out;
	}
	hdr = bp->bl.data;

	/* corrupted writes might be a sign of a stale reference */
	if (!test_bit(BLOCK_BIT_CRC_VALID, &bp->bits)) {
		if (hdr->crc != block_calc_crc(hdr, SCOUTFS_BLOCK_LG_SIZE)) {
			ret = -ESTALE;
			goto out;
		}

		set_bit(BLOCK_BIT_CRC_VALID, &bp->bits);
	}

	if (hdr->magic != cpu_to_le32(magic) || hdr->fsid != super->hdr.fsid ||
	    hdr->seq != ref->seq || hdr->blkno != ref->blkno) {
		ret = -ESTALE;
		goto out;
	}

	ret = 0;
out:
	if ((ret == -ESTALE || scoutfs_trigger(sb, BLOCK_REMOVE_STALE)) &&
	    !retried && !block_is_dirty(bp)) {
		retried = true;
		scoutfs_inc_counter(sb, block_cache_remove_stale);
		block_remove(sb, bp);
		block_put(sb, bp);
		bp = NULL;
		goto retry;
	}

	if (ret < 0) {
		block_put(sb, bp);
		bp = NULL;
	}

	*bl_ret = bp ? &bp->bl : NULL;
	return ret;
}

void scoutfs_block_put(struct super_block *sb, struct scoutfs_block *bl)
{
	if (!IS_ERR_OR_NULL(bl))
		block_put(sb, BLOCK_PRIVATE(bl));
}

void scoutfs_block_writer_init(struct super_block *sb,
			       struct scoutfs_block_writer *wri)
{
	spin_lock_init(&wri->lock);
	INIT_LIST_HEAD(&wri->dirty_list);
	wri->nr_dirty_blocks = 0;
}

/*
 * Mark a given block dirty.  The caller serializes all dirtying calls
 * with writer write calls.  As it happens we dirty in allocation order
 * and allocate with an advancing cursor so we always dirty in block
 * offset order and can walk our list to submit nice ordered IO.
 */
static void block_mark_dirty(struct super_block *sb, struct scoutfs_block_writer *wri,
			     struct scoutfs_block *bl)
{
	struct block_private *bp = BLOCK_PRIVATE(bl);

	if (!test_and_set_bit(BLOCK_BIT_DIRTY, &bp->bits)) {
		BUG_ON(!list_empty(&bp->dirty_entry));
		block_get(bp);
		spin_lock(&wri->lock);
		list_add_tail(&bp->dirty_entry, &wri->dirty_list);
		wri->nr_dirty_blocks++;
		spin_unlock(&wri->lock);
		TRACE_BLOCK(mark_dirty, bp);
	}
}

/*
 * Give the caller a dirty block that is pointed to by their ref.
 *
 * The ref may already refer to a cached dirty block.  In that case the
 * dirty block is returned.
 *
 * If the ref doesn't refer to a dirty block, then a new block is always
 * allocated and returned.  If the ref refers to an existing block then
 * its contents are copied into the new block.
 *
 * If a new blkno is allocated then the ref is updated and any existing
 * blkno is freed.
 *
 * A newly allocated block that we insert into the cache and return
 * might already have an old stale copy inserted in the cache and it
 * might be actively in use by readers.  Future readers may also try to
 * read their old block from our newly allocated block.  We always
 * remove any existing blocks and insert our new block only after
 * modifying its headers and marking it dirty.  Readers will never have
 * their blocks modified and they can always identify new mismatched
 * cached blocks.
 *
 * The dirty_blkno and ref_blkno arguments are used by the metadata
 * allocator to avoid recursing into itself.  dirty_blkno provides the
 * blkno of the new dirty block to avoid calling _alloc_meta and
 * ref_blkno is set to the old blkno instead of freeing it with
 * _free_meta.
 */
int scoutfs_block_dirty_ref(struct super_block *sb, struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri, struct scoutfs_block_ref *ref,
			    u32 magic, struct scoutfs_block **bl_ret,
			    u64 dirty_blkno, u64 *ref_blkno)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_block *cow_bl = NULL;
	struct scoutfs_block *bl = NULL;
	struct block_private *exist_bp = NULL;
	struct block_private *cow_bp = NULL;
	struct block_private *bp = NULL;
	struct scoutfs_block_header *hdr;
	bool undo_alloc = false;
	u64 blkno;
	int ret;
	int err;

	/* read existing referenced block, if any */
	blkno = le64_to_cpu(ref->blkno);
	if (blkno) {
		ret = scoutfs_block_read_ref(sb, ref, magic, bl_ret);
		if (ret < 0)
			goto out;
		bl = *bl_ret;
		bp = BLOCK_PRIVATE(bl);

		if (block_is_dirty(bp)) {
			ret = 0;
			goto out;
		}
	}

	/* allocate new blkno if caller didn't give us one */
	if (dirty_blkno == 0) {
		ret = scoutfs_alloc_meta(sb, alloc, wri, &dirty_blkno);
		if (ret < 0)
			goto out;
		undo_alloc = true;
	}

	/* allocate new cached block */
	cow_bp = block_alloc(sb, dirty_blkno);
	if (cow_bp == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	cow_bl = &cow_bp->bl;

	set_bit(BLOCK_BIT_UPTODATE, &cow_bp->bits);
	set_bit(BLOCK_BIT_CRC_VALID, &cow_bp->bits);

	/* free original referenced blkno, or give it to the caller to deal with */
	if (ref_blkno) {
		*ref_blkno = blkno;
	} else if (blkno) {
		ret = scoutfs_free_meta(sb, alloc, wri, blkno);
		if (ret < 0)
			goto out;
	}

	/* copy original block contents, or initialize */
	if (bl)
		memcpy(cow_bl->data, bl->data, SCOUTFS_BLOCK_LG_SIZE);
	else
		memset(cow_bl->data, 0, SCOUTFS_BLOCK_LG_SIZE);
	scoutfs_block_put(sb, bl);
	bl = cow_bl;
	cow_bl = NULL;
	bp = cow_bp;
	cow_bp = NULL;

	hdr = bl->data;
	hdr->magic = cpu_to_le32(magic);
	hdr->fsid = super->hdr.fsid;
	hdr->blkno = cpu_to_le64(bl->blkno);
	prandom_bytes(&hdr->seq, sizeof(hdr->seq));

	trace_scoutfs_block_dirty_ref(sb, le64_to_cpu(ref->blkno), le64_to_cpu(ref->seq),
				      le64_to_cpu(hdr->blkno), le64_to_cpu(hdr->seq));

	/* mark the block dirty before it's visible */
	block_mark_dirty(sb, wri, bl);

	/* insert the new block, maybe removing any existing blocks */
	while ((ret = block_insert(sb, bp)) == -EEXIST) {
		exist_bp = block_lookup(sb, dirty_blkno);
		if (exist_bp) {
			block_remove(sb, exist_bp);
			block_put(sb, exist_bp);
		}
	}
	if (ret < 0)
		goto out;

	/* set the ref now that the block is visible */
	ref->blkno = hdr->blkno;
	ref->seq = hdr->seq;

	ret = 0;

out:
	scoutfs_block_put(sb, cow_bl);
	if (ret < 0 && undo_alloc) {
		err = scoutfs_free_meta(sb, alloc, wri, dirty_blkno);
		BUG_ON(err); /* inconsistent */
	}

	if (ret < 0) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}
	*bl_ret = bl;

	return ret;
}

/*
 * Submit writes for all the dirty blocks in the writer's dirty list and
 * wait for them to complete.  The caller must serialize this with
 * attempts to dirty blocks in the writer.  If we return an error then
 * all the blocks will still be considered dirty.  This can be called
 * again to attempt to write all the blocks again.
 */
int scoutfs_block_writer_write(struct super_block *sb,
			       struct scoutfs_block_writer *wri)
{
	DECLARE_BLOCK_INFO(sb, binf);
	struct scoutfs_block_header *hdr;
	struct block_private *bp;
	struct blk_plug plug;
	int ret = 0;

	if (wri->nr_dirty_blocks == 0)
		return 0;

	/* checksum everything to reduce time between io submission merging */
	list_for_each_entry(bp, &wri->dirty_list, dirty_entry) {
		hdr = bp->bl.data;
		hdr->crc = block_calc_crc(hdr, SCOUTFS_BLOCK_LG_SIZE);
	}

        blk_start_plug(&plug);

	list_for_each_entry(bp, &wri->dirty_list, dirty_entry) {
		/* retry previous write errors */
		clear_bit(BLOCK_BIT_ERROR, &bp->bits);

		ret = block_submit_bio(sb, bp, WRITE);
		if (ret < 0)
			break;
	}

	blk_finish_plug(&plug);

	list_for_each_entry(bp, &wri->dirty_list, dirty_entry) {
		/* XXX should this be interruptible? */
		wait_event(binf->waitq, !io_busy(bp));
		if (ret == 0 && test_bit(BLOCK_BIT_ERROR, &bp->bits)) {
			clear_bit(BLOCK_BIT_ERROR, &bp->bits);
			ret = -EIO;
		}
	}

	if (ret == 0)
		scoutfs_block_writer_forget_all(sb, wri);

	return ret;
}

static void block_forget(struct super_block *sb,
			 struct scoutfs_block_writer *wri,
			 struct block_private *bp)
{
	assert_spin_locked(&wri->lock);

	clear_bit(BLOCK_BIT_DIRTY, &bp->bits);
	list_del_init(&bp->dirty_entry);
	wri->nr_dirty_blocks--;
	TRACE_BLOCK(forget, bp);
	block_put(sb, bp);
}

/*
 * Clear the dirty status of all the blocks in the writer.  The blocks
 * remain clean in cache but can be freed by reclaim and then re-read
 * from disk, losing whatever modifications made them dirty.
 */
void scoutfs_block_writer_forget_all(struct super_block *sb,
				     struct scoutfs_block_writer *wri)
{
	struct block_private *tmp;
	struct block_private *bp;

	spin_lock(&wri->lock);

	list_for_each_entry_safe(bp, tmp, &wri->dirty_list, dirty_entry)
		block_forget(sb, wri, bp);

	spin_unlock(&wri->lock);
}

/*
 * Forget that the given block was dirty.  It won't be written in the
 * future.  Its contents remain in the cache.  This is typically used
 * as a block is freed.  If it is allocated and re-used then its contents
 * will be re-initialized.
 *
 * The caller should ensure that we don't try and mark and forget the
 * same block, but this is racing with marking and forgetting other
 * blocks.
 */
void scoutfs_block_writer_forget(struct super_block *sb,
			         struct scoutfs_block_writer *wri,
				 struct scoutfs_block *bl)
{
	struct block_private *bp = BLOCK_PRIVATE(bl);

	if (test_bit(BLOCK_BIT_DIRTY, &bp->bits)) {
		scoutfs_inc_counter(sb, block_cache_forget);
		spin_lock(&wri->lock);
		if (test_bit(BLOCK_BIT_DIRTY, &bp->bits))
			block_forget(sb, wri, bp);
		spin_unlock(&wri->lock);
	}
}

/*
 * The caller has ensured that no more dirtying will take place.  This
 * helps the caller avoid doing a bunch of work before calling into the
 * writer to write dirty blocks that didn't exist.
 */
bool scoutfs_block_writer_has_dirty(struct super_block *sb,
				    struct scoutfs_block_writer *wri)
{
	return wri->nr_dirty_blocks != 0;
}

/*
 * This is a best-effort guess.  It's only used for heuristics so it's OK
 * if it goes a little bonkers sometimes.
 */
u64 scoutfs_block_writer_dirty_bytes(struct super_block *sb,
				     struct scoutfs_block_writer *wri)
{
	return wri->nr_dirty_blocks * SCOUTFS_BLOCK_LG_SIZE;
}

/*
 * Remove a number of cached blocks that haven't been used recently.
 *
 * We don't maintain a strictly ordered LRU to avoid the contention of
 * accesses always moving blocks around in some precise global
 * structure.
 *
 * Instead we use counters to divide the blocks into two roughly equal
 * groups by how recently they were accessed.  We randomly walk all
 * inserted blocks looking for any blocks in the older half to remove
 * and free.  The random walk and there being two groups means that we
 * typically only walk a small multiple of the number we're looking for
 * before we find them all.
 *
 * Our rcu walk of blocks can see blocks in all stages of their life
 * cycle, from dirty blocks to those with 0 references that are queued
 * for freeing.  We only want to free idle inserted blocks so we
 * atomically remove blocks when the only references are ours and the
 * hash table.
 */
static int block_shrink(struct shrinker *shrink, struct shrink_control *sc)
{
	struct block_info *binf = container_of(shrink, struct block_info,
					       shrinker);
	struct super_block *sb = binf->sb;
	struct rhashtable_iter iter;
	struct block_private *bp;
	unsigned long nr;
	u64 recently;

	nr = sc->nr_to_scan;
	if (nr == 0)
		goto out;

	scoutfs_inc_counter(sb, block_cache_shrink);

	nr = DIV_ROUND_UP(nr, SCOUTFS_BLOCK_LG_PAGES_PER);

restart:
	recently = accessed_recently(binf);
	rhashtable_walk_enter(&binf->ht, &iter);
	rhashtable_walk_start(&iter);

	/*
	 * This isn't great but I don't see a better way.  We want to
	 * walk the hash from a random point so that we're not
	 * constantly walking over the same region that we've already
	 * freed old blocks within.  The interface doesn't let us do
	 * this explicitly, but this seems to work?  The difference this
	 * makes is enormous, around a few orders of magnitude fewer
	 * _nexts per shrink.
	 */
	if (iter.walker.tbl)
		iter.slot = prandom_u32_max(iter.walker.tbl->size);

	while (nr > 0) {
		bp = rhashtable_walk_next(&iter);
		if (bp == NULL)
			break;
		if (bp == ERR_PTR(-EAGAIN)) {
			/* hard exit to wait for rcu rebalance to finish */
			rhashtable_walk_stop(&iter);
			rhashtable_walk_exit(&iter);
			scoutfs_inc_counter(sb, block_cache_shrink_restart);
			synchronize_rcu();
			goto restart;
		}

		scoutfs_inc_counter(sb, block_cache_shrink_next);

		if (bp->accessed >= recently) {
			scoutfs_inc_counter(sb, block_cache_shrink_recent);
			continue;
		}

		if (block_get_if_inserted(bp)) {
			if (block_remove_solo(sb, bp)) {
				scoutfs_inc_counter(sb, block_cache_shrink_remove);
				TRACE_BLOCK(shrink, bp);
				nr--;
			}
			block_put(sb, bp);
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
out:
	return min_t(u64, (u64)atomic_read(&binf->total_inserted) * SCOUTFS_BLOCK_LG_PAGES_PER,
		     INT_MAX);
}

struct sm_block_completion {
	struct completion comp;
	int err;
};

static void sm_block_bio_end_io(struct bio *bio, int err)
{
	struct sm_block_completion *sbc = bio->bi_private;

	sbc->err = err;
	complete(&sbc->comp);
	bio_put(bio);
}

/*
 * Perform a private synchronous read or write of a small fixed size 4K
 * block.  We allocate a private page and bio and copy to or from the
 * caller's buffer.
 *
 * The interface is a little weird because our blocks always start with
 * a block header that contains a crc of the entire block.  We're the
 * only layer that sees the full block buffer so we pass the calculated
 * crc to the caller for them to check in their context.
 */
static int sm_block_io(struct block_device *bdev, int rw, u64 blkno,
		       struct scoutfs_block_header *hdr, size_t len,
		       __le32 *blk_crc)
{
	struct scoutfs_block_header *pg_hdr;
	struct sm_block_completion sbc;
	struct page *page;
	struct bio *bio;
	int ret;

	BUILD_BUG_ON(PAGE_SIZE < SCOUTFS_BLOCK_SM_SIZE);

	if (WARN_ON_ONCE(len > SCOUTFS_BLOCK_SM_SIZE) ||
	    WARN_ON_ONCE(!(rw & WRITE) && !blk_crc))
		return -EINVAL;

	page = alloc_page(GFP_NOFS);
	if (!page)
		return -ENOMEM;

	pg_hdr = page_address(page);

	if (rw & WRITE) {
		memcpy(pg_hdr, hdr, len);
		if (len < SCOUTFS_BLOCK_SM_SIZE)
			memset((char *)pg_hdr + len, 0,
			       SCOUTFS_BLOCK_SM_SIZE - len);
		pg_hdr->crc = block_calc_crc(pg_hdr, SCOUTFS_BLOCK_SM_SIZE);
	}

	bio = bio_alloc(GFP_NOFS, 1);
	if (!bio) {
		ret = -ENOMEM;
		goto out;
	}

	bio->bi_sector = blkno << (SCOUTFS_BLOCK_SM_SHIFT - 9);
	bio->bi_bdev = bdev;
	bio->bi_end_io = sm_block_bio_end_io;
	bio->bi_private = &sbc;
	bio_add_page(bio, page, SCOUTFS_BLOCK_SM_SIZE, 0);

	init_completion(&sbc.comp);
	sbc.err = 0;

	submit_bio((rw & WRITE) ? WRITE_SYNC : READ_SYNC, bio);

	wait_for_completion(&sbc.comp);
	ret = sbc.err;

	if (ret == 0 && !(rw & WRITE)) {
		memcpy(hdr, pg_hdr, len);
		*blk_crc = block_calc_crc(pg_hdr, SCOUTFS_BLOCK_SM_SIZE);
	}
out:
	__free_page(page);
	return ret;
}

int scoutfs_block_read_sm(struct super_block *sb,
			  struct block_device *bdev, u64 blkno,
			  struct scoutfs_block_header *hdr, size_t len,
			  __le32 *blk_crc)
{
	return sm_block_io(bdev, READ, blkno, hdr, len, blk_crc);
}

int scoutfs_block_write_sm(struct super_block *sb,
			   struct block_device *bdev, u64 blkno,
			   struct scoutfs_block_header *hdr, size_t len)
{
	return sm_block_io(bdev, WRITE, blkno, hdr, len, NULL);
}

int scoutfs_block_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct block_info *binf;
	int ret;

	binf = kzalloc(sizeof(struct block_info), GFP_KERNEL);
	if (!binf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = rhashtable_init(&binf->ht, &block_ht_params);
	if (ret < 0) {
		kfree(binf);
		goto out;
	}

	binf->sb = sb;
	atomic_set(&binf->total_inserted, 0);
	atomic64_set(&binf->access_counter, 0);
	init_waitqueue_head(&binf->waitq);
	binf->shrinker.shrink = block_shrink;
	binf->shrinker.seeks = DEFAULT_SEEKS;
	register_shrinker(&binf->shrinker);
	INIT_WORK(&binf->free_work, block_free_work);
	init_llist_head(&binf->free_llist);

	sbi->block_info = binf;

	ret = 0;
out:
	if (ret)
		scoutfs_block_destroy(sb);

	return ret;
}

void scoutfs_block_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct block_info *binf = SCOUTFS_SB(sb)->block_info;

	if (binf) {
		unregister_shrinker(&binf->shrinker);
		block_remove_all(sb);
		flush_work(&binf->free_work);
		rhashtable_destroy(&binf->ht);

		kfree(binf);
		sbi->block_info = NULL;
	}
}
