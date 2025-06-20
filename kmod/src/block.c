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
#include <linux/sched/mm.h>
#include <linux/list_lru.h>

#include "format.h"
#include "super.h"
#include "block.h"
#include "counters.h"
#include "msg.h"
#include "scoutfs_trace.h"
#include "alloc.h"
#include "triggers.h"
#include "util.h"

/*
 * The scoutfs block cache manages metadata blocks that can be larger
 * than the page size.  Callers can have their own contexts for tracking
 * dirty blocks that are written together.  We pin dirty blocks in
 * memory and only checksum them all as they're all written.
 */

struct block_info {
	struct super_block *sb;
	struct rhashtable ht;
	struct list_lru lru;
	wait_queue_head_t waitq;
	KC_DEFINE_SHRINKER(shrinker);
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
	BLOCK_BIT_ACCESSED,	/* seen by lookup since last lru add/walk */
};

struct block_private {
	struct scoutfs_block bl;
	struct super_block *sb;
	atomic_t refcount;
	struct rhash_head ht_head;
	struct list_head lru_head;
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
				    atomic_read(&_bp->io_count), _bp->bits);	\
} while (0)

#define BLOCK_PRIVATE(_bl) \
	container_of((_bl), struct block_private, bl)

static __le32 block_calc_crc(struct scoutfs_block_header *hdr, u32 size)
{
	int off = offsetofend(struct scoutfs_block_header, crc);
	u32 calc = crc32c(~0, (char *)hdr + off, size - off);

	return cpu_to_le32(calc);
}

static struct block_private *block_alloc(struct super_block *sb, u64 blkno)
{
	struct block_private *bp;
	unsigned int nofs_flags;

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
		nofs_flags = memalloc_nofs_save();
		bp->virt = kc__vmalloc(SCOUTFS_BLOCK_LG_SIZE, GFP_NOFS | __GFP_HIGHMEM);
		memalloc_nofs_restore(nofs_flags);
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
	INIT_LIST_HEAD(&bp->lru_head);
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

	/* ok to tear down dirty blocks when forcing unmount */
	WARN_ON_ONCE(!scoutfs_forcing_unmount(sb) && !list_empty(&bp->dirty_entry));

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
 * Users of blocks hold a refcount.  If putting a refcount drops to zero
 * then the block is freed.
 *
 * Acquiring new references and claiming the exclusive right to tear
 * down a block is built around this LIVE_REFCOUNT_BASE refcount value.
 * As blocks are initially cached they have the live base added to their
 * refcount.  Lookups will only increment the refcount and return blocks
 * for reference holders while the refcount is >= than the base.
 *
 * To remove a block from the cache and eventually free it, either by
 * the lru walk in the shrinker, or by reference holders, the live base
 * is removed and turned into a normal refcount increment that will be
 * put by the caller.  This can only be done once for a block, and once
 * its done lookup will not return any more references.
 */
#define LIVE_REFCOUNT_BASE (INT_MAX ^ (INT_MAX >> 1))

/*
 * Inc the refcount while holding an incremented refcount.  We can't
 * have so many individual reference holders that they pass the live
 * base.
 */
static void block_get(struct block_private *bp)
{
	int now = atomic_inc_return(&bp->refcount);

	BUG_ON(now <= 1);
	BUG_ON(now == LIVE_REFCOUNT_BASE);
}

/*
 * if (*v >= u) {
 * 	*v += a;
 * 	return true;
 * }
 */
static bool atomic_add_unless_less(atomic_t *v, int a, int u)
{
	int c;

	do {
		c = atomic_read(v);
		if (c < u)
			return false;
	} while (atomic_cmpxchg(v, c, c + a) != c);

	return true;
}

static bool block_get_if_live(struct block_private *bp)
{
	return atomic_add_unless_less(&bp->refcount, 1, LIVE_REFCOUNT_BASE);
}

/*
 * If the refcount still has the live base, subtract it and increment
 * the callers refcount that they'll put.
 */
static bool block_get_remove_live(struct block_private *bp)
{
	return atomic_add_unless_less(&bp->refcount, (1 - LIVE_REFCOUNT_BASE), LIVE_REFCOUNT_BASE);
}

/*
 * Only get the live base refcount if it is the only refcount remaining.
 * This means that there are no active refcount holders and the block
 * can't be dirty or under IO, which both hold references.
 */
static bool block_get_remove_live_only(struct block_private *bp)
{
	int c;

	do {
		c = atomic_read(&bp->refcount);
		if (c != LIVE_REFCOUNT_BASE)
			return false;
	} while (atomic_cmpxchg(&bp->refcount, c, c - LIVE_REFCOUNT_BASE + 1) != c);

	return true;
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
 * Insert the block into the cache so that it's visible for lookups.
 * The caller can hold references (including for a dirty block).
 *
 * We make sure the base is added and the block is in the lru once it's
 * in the hash.  If hash table insertion fails it'll be briefly visible
 * in the lru, but won't be isolated/evicted because we hold an
 * incremented refcount in addition to the live base.
 */
static int block_insert(struct super_block *sb, struct block_private *bp)
{
	DECLARE_BLOCK_INFO(sb, binf);
	int ret;

	BUG_ON(atomic_read(&bp->refcount) >= LIVE_REFCOUNT_BASE);
	atomic_add(LIVE_REFCOUNT_BASE, &bp->refcount);
	smp_mb__after_atomic(); /* make sure live base is visible to list_lru walk */
	list_lru_add_obj(&binf->lru, &bp->lru_head);
retry:
	ret = rhashtable_lookup_insert_fast(&binf->ht, &bp->ht_head, block_ht_params);
	if (ret < 0) {
		if (ret == -EBUSY) {
			/* wait for pending rebalance to finish */
			synchronize_rcu();
			goto retry;
		} else {
			atomic_sub(LIVE_REFCOUNT_BASE, &bp->refcount);
			BUG_ON(atomic_read(&bp->refcount) >= LIVE_REFCOUNT_BASE);
			list_lru_del_obj(&binf->lru, &bp->lru_head);
		}
	} else {
		TRACE_BLOCK(insert, bp);
	}

	return ret;
}

/*
 * Indicate to the lru walker that this block has been accessed since it
 * was added or last walked.
 */
static void block_accessed(struct super_block *sb, struct block_private *bp)
{
	if (!test_and_set_bit(BLOCK_BIT_ACCESSED, &bp->bits))
		scoutfs_inc_counter(sb, block_cache_access_update);
}

/*
 * Remove the block from the cache.  When this returns the block won't
 * be visible for additional references from lookup.
 *
 * We always try and remove from the hash table.  It's safe to remove a
 * block that isn't hashed, it just returns -ENOENT.
 *
 * This is racing with the lru walk in the shrinker also trying to
 * remove idle blocks from the cache.  They both try to remove the live
 * refcount base and perform their removal and put if they get it.
 */
static void block_remove(struct super_block *sb, struct block_private *bp)
{
	DECLARE_BLOCK_INFO(sb, binf);

	rhashtable_remove_fast(&binf->ht, &bp->ht_head, block_ht_params);

	if (block_get_remove_live(bp)) {
		list_lru_del_obj(&binf->lru, &bp->lru_head);
		block_put(sb, bp);
	}
}

static bool io_busy(struct block_private *bp)
{
	smp_rmb(); /* test after adding to wait queue */
	return test_bit(BLOCK_BIT_IO_BUSY, &bp->bits);
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
static void block_end_io(struct super_block *sb, blk_opf_t opf,
			 struct block_private *bp, int err)
{
	DECLARE_BLOCK_INFO(sb, binf);

	if (err) {
		scoutfs_inc_counter(sb, block_cache_end_io_error);
		set_bit(BLOCK_BIT_ERROR, &bp->bits);
	}

	if (!atomic_dec_and_test(&bp->io_count))
		return;

	if (!op_is_write(opf) && !test_bit(BLOCK_BIT_ERROR, &bp->bits))
		set_bit(BLOCK_BIT_UPTODATE, &bp->bits);

	clear_bit(BLOCK_BIT_IO_BUSY, &bp->bits);
	block_put(sb, bp);

	/* make sure set and cleared bits are visible to woken */
	smp_mb();

	if (waitqueue_active(&binf->waitq))
		wake_up(&binf->waitq);
}

static void KC_DECLARE_BIO_END_IO(block_bio_end_io, struct bio *bio)
{
	struct block_private *bp = bio->bi_private;
	struct super_block *sb = bp->sb;

	TRACE_BLOCK(end_io, bp);
	block_end_io(sb, kc_bio_get_opf(bio), bp, kc_bio_get_errno(bio));
	bio_put(bio);
}

/*
 * Kick off IO for a single block.
 */
static int block_submit_bio(struct super_block *sb, struct block_private *bp,
			    blk_opf_t opf)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct bio *bio = NULL;
	struct blk_plug plug;
	struct page *page;
	unsigned long off;
	sector_t sector;
	int ret = 0;

	if (scoutfs_forcing_unmount(sb))
		return -EIO;

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
			bio = kc_bio_alloc(sbi->meta_bdev, SCOUTFS_BLOCK_LG_PAGES_PER, opf, GFP_NOFS);
			if (!bio) {
				ret = -ENOMEM;
				break;
			}

			kc_bio_set_sector(bio, sector + (off >> 9));
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
			kc_submit_bio(bio);
			bio = NULL;
		}
	}

	if (bio)
		kc_submit_bio(bio);

	blk_finish_plug(&plug);

	/* let racing end_io know we're done */
	block_end_io(sb, opf, bp, ret);

	return ret;
}

/*
 * Return a block with an elevated refcount if it was present in the
 * hash table and its refcount didn't indicate that it was being freed.
 */
static struct block_private *block_lookup(struct super_block *sb, u64 blkno)
{
	DECLARE_BLOCK_INFO(sb, binf);
	struct block_private *bp;

	rcu_read_lock();
	bp = rhashtable_lookup(&binf->ht, &blkno, block_ht_params);
	if (bp && !block_get_if_live(bp))
		bp = NULL;
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
		ret = block_submit_bio(sb, bp, REQ_OP_READ);
		if (ret < 0)
			goto out;
	}

	wait_event(binf->waitq, uptodate_or_error(bp));
	if (test_bit(BLOCK_BIT_ERROR, &bp->bits))
		ret = -EIO;
	else
		ret = 0;

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
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_block_header *hdr;
	struct block_private *bp = NULL;
	bool retried = false;
	__le32 crc = 0;
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
		crc = block_calc_crc(hdr, SCOUTFS_BLOCK_LG_SIZE);
		if (hdr->crc != crc) {
			trace_scoutfs_block_stale(sb, ref, hdr, magic, le32_to_cpu(crc));
			ret = -ESTALE;
			goto out;
		}

		set_bit(BLOCK_BIT_CRC_VALID, &bp->bits);
	}

	if (hdr->magic != cpu_to_le32(magic) || hdr->fsid != cpu_to_le64(sbi->fsid) ||
	    hdr->seq != ref->seq || hdr->blkno != ref->blkno) {
		trace_scoutfs_block_stale(sb, ref, hdr, magic, 0);
		ret = -ESTALE;
		goto out;
	}

	ret = 0;
out:
	if (!retried && !IS_ERR_OR_NULL(bp) && !block_is_dirty(bp) &&
	    (ret == -ESTALE || scoutfs_trigger(sb, BLOCK_REMOVE_STALE))) {
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

static bool stale_refs_match(struct scoutfs_block_ref *caller, struct scoutfs_block_ref *saved)
{
	return !caller || (caller->blkno == saved->blkno && caller->seq == saved->seq);
}

/*
 * Check if a read of a reference that gave ESTALE should be retried or
 * should generate a hard error.  If this is the second time we got
 * ESTALE from the same refs then we return EIO and the caller should
 * stop.  As long as we keep seeing different refs we'll return ESTALE
 * and the caller can keep trying.
 */
int scoutfs_block_check_stale(struct super_block *sb, int ret,
			      struct scoutfs_block_saved_refs *saved,
			      struct scoutfs_block_ref *a, struct scoutfs_block_ref *b)
{
	if (ret == -ESTALE) {
		if (stale_refs_match(a, &saved->refs[0]) && stale_refs_match(b, &saved->refs[1])){
			ret = -EIO;
		} else {
			if (a)
				saved->refs[0] = *a;
			if (b)
				saved->refs[1] = *b;
		}
	}

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
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
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
	hdr->fsid = cpu_to_le64(sbi->fsid);
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

		ret = block_submit_bio(sb, bp, REQ_OP_WRITE);
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

static unsigned long block_count_objects(struct shrinker *shrink, struct shrink_control *sc)
{
	struct block_info *binf = KC_SHRINKER_CONTAINER_OF(shrink, struct block_info);
	struct super_block *sb = binf->sb;

	scoutfs_inc_counter(sb, block_cache_count_objects);
	return list_lru_shrink_count(&binf->lru, sc);
}

struct isolate_args {
	struct super_block *sb;
	struct list_head dispose;
};

#define DECLARE_ISOLATE_ARGS(sb_, name_) \
	struct isolate_args name_ = { \
		.sb = sb_, \
		.dispose = LIST_HEAD_INIT(name_.dispose), \
	}

static enum lru_status isolate_lru_block(struct list_head *item, struct list_lru_one *list,
					 void *cb_arg)
{
	struct block_private *bp = container_of(item, struct block_private, lru_head);
	struct isolate_args *ia = cb_arg;

	TRACE_BLOCK(isolate, bp);

	/* rotate accessed blocks to the tail of the list (lazy promotion) */
	if (test_and_clear_bit(BLOCK_BIT_ACCESSED, &bp->bits)) {
		scoutfs_inc_counter(ia->sb, block_cache_isolate_rotate);
		return LRU_ROTATE;
	}

	/* any refs, including dirty/io, stop us from acquiring lru refcount */
	if (!block_get_remove_live_only(bp)) {
		scoutfs_inc_counter(ia->sb, block_cache_isolate_skip);
		return LRU_SKIP;
	}

	scoutfs_inc_counter(ia->sb, block_cache_isolate_removed);
	list_lru_isolate_move(list, &bp->lru_head, &ia->dispose);
	return LRU_REMOVED;
}

static void shrink_dispose_blocks(struct super_block *sb, struct list_head *dispose)
{
	struct block_private *bp;
	struct block_private *bp__;

	list_for_each_entry_safe(bp, bp__, dispose, lru_head) {
		list_del_init(&bp->lru_head);
		block_remove(sb, bp);
		block_put(sb, bp);
	}
}

static unsigned long block_scan_objects(struct shrinker *shrink, struct shrink_control *sc)
{
	struct block_info *binf = KC_SHRINKER_CONTAINER_OF(shrink, struct block_info);
	struct super_block *sb = binf->sb;
	DECLARE_ISOLATE_ARGS(sb, ia);
	unsigned long freed;

	scoutfs_inc_counter(sb, block_cache_scan_objects);

	freed = kc_list_lru_shrink_walk(&binf->lru, sc, isolate_lru_block, &ia);
	shrink_dispose_blocks(sb, &ia.dispose);
	return freed;
}

/*
 * Called during shutdown with no other users.  The isolating walk must
 * find blocks on the lru that only have references for presence on the
 * lru and in the hash table.
 */
static void block_shrink_all(struct super_block *sb)
{
	DECLARE_BLOCK_INFO(sb, binf);
	DECLARE_ISOLATE_ARGS(sb, ia);

	do {
		kc_list_lru_walk(&binf->lru, isolate_lru_block, &ia, 128);
		shrink_dispose_blocks(sb, &ia.dispose);
        } while (list_lru_count(&binf->lru) > 0);
}

struct sm_block_completion {
	struct completion comp;
	int err;
};

static void KC_DECLARE_BIO_END_IO(sm_block_bio_end_io, struct bio *bio)
{
	struct sm_block_completion *sbc = bio->bi_private;

	sbc->err = kc_bio_get_errno(bio);
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
static int sm_block_io(struct super_block *sb, struct block_device *bdev, blk_opf_t opf,
		       u64 blkno, struct scoutfs_block_header *hdr, size_t len, __le32 *blk_crc)
{
	struct scoutfs_block_header *pg_hdr;
	struct sm_block_completion sbc;
	struct page *page;
	struct bio *bio;
	int ret;

	BUILD_BUG_ON(PAGE_SIZE < SCOUTFS_BLOCK_SM_SIZE);

	if (scoutfs_forcing_unmount(sb))
		return -EIO;

	if (WARN_ON_ONCE(len > SCOUTFS_BLOCK_SM_SIZE) ||
	    WARN_ON_ONCE(!op_is_write(opf) && !blk_crc))
		return -EINVAL;

	page = alloc_page(GFP_NOFS);
	if (!page)
		return -ENOMEM;

	pg_hdr = page_address(page);

	if (op_is_write(opf)) {
		memcpy(pg_hdr, hdr, len);
		if (len < SCOUTFS_BLOCK_SM_SIZE)
			memset((char *)pg_hdr + len, 0,
			       SCOUTFS_BLOCK_SM_SIZE - len);
		pg_hdr->crc = block_calc_crc(pg_hdr, SCOUTFS_BLOCK_SM_SIZE);
	}

	bio = kc_bio_alloc(bdev, 1, opf, GFP_NOFS);
	if (!bio) {
		ret = -ENOMEM;
		goto out;
	}

	kc_bio_set_sector(bio, blkno << (SCOUTFS_BLOCK_SM_SHIFT - 9));
	bio->bi_end_io = sm_block_bio_end_io;
	bio->bi_private = &sbc;
	bio_add_page(bio, page, SCOUTFS_BLOCK_SM_SIZE, 0);

	init_completion(&sbc.comp);
	sbc.err = 0;

	kc_submit_bio(bio);

	wait_for_completion(&sbc.comp);
	ret = sbc.err;

	if (ret == 0 && !op_is_write(opf)) {
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
	return sm_block_io(sb, bdev, REQ_OP_READ, blkno, hdr, len, blk_crc);
}

int scoutfs_block_write_sm(struct super_block *sb,
			   struct block_device *bdev, u64 blkno,
			   struct scoutfs_block_header *hdr, size_t len)
{
	return sm_block_io(sb, bdev, REQ_OP_WRITE, blkno, hdr, len, NULL);
}

int scoutfs_block_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct block_info *binf = NULL;
	int ret;

	binf = kzalloc(sizeof(struct block_info), GFP_KERNEL);
	if (!binf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = list_lru_init(&binf->lru);
	if (ret < 0)
		goto out;

	ret = rhashtable_init(&binf->ht, &block_ht_params);
	if (ret < 0)
		goto out;

	binf->sb = sb;
	init_waitqueue_head(&binf->waitq);
	KC_INIT_SHRINKER_FUNCS(&binf->shrinker, block_count_objects,
			       block_scan_objects);
	KC_REGISTER_SHRINKER(&binf->shrinker, "scoutfs-block:" SCSBF, SCSB_ARGS(sb));
	INIT_WORK(&binf->free_work, block_free_work);
	init_llist_head(&binf->free_llist);

	sbi->block_info = binf;

	ret = 0;
out:
	if (ret < 0 && binf) {
		list_lru_destroy(&binf->lru);
		kfree(binf);
	}

	return ret;
}

void scoutfs_block_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct block_info *binf = SCOUTFS_SB(sb)->block_info;

	if (binf) {
		KC_UNREGISTER_SHRINKER(&binf->shrinker);
		block_shrink_all(sb);
		flush_work(&binf->free_work);
		rhashtable_destroy(&binf->ht);
		list_lru_destroy(&binf->lru);

		kfree(binf);
		sbi->block_info = NULL;
	}
}
