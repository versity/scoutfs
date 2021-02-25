/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
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
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/writeback.h>
#include <linux/slab.h>

#include "super.h"
#include "trans.h"
#include "data.h"
#include "forest.h"
#include "counters.h"
#include "client.h"
#include "inode.h"
#include "alloc.h"
#include "block.h"
#include "msg.h"
#include "item.h"
#include "scoutfs_trace.h"

/*
 * scoutfs blocks are written in atomic transactions.
 *
 * Writers hold transactions to dirty blocks.  The transaction can't be
 * written until these active writers release the transaction.  We don't
 * track the relationships between dirty blocks so there's only ever one
 * transaction being built.
 *
 * Committing the current dirty transaction can be triggered by sync, a
 * regular background commit interval, reaching a dirty block threshold,
 * or the transaction running out of its private allocator resources.
 * Once all the current holders release the writing func writes out the
 * dirty blocks while excluding holders until it finishes.
 *
 * Unfortunately writing holders can nest.  We track nested hold callers
 * with the per-task journal_info pointer to avoid deadlocks between
 * holders that might otherwise wait for a pending commit.
 */

/* sync dirty data at least this often */
#define TRANS_SYNC_DELAY (HZ * 10)

/*
 * XXX move the rest of the super trans_ fields here.
 */
struct trans_info {
	atomic_t holders;

	struct scoutfs_log_trees lt;
	struct scoutfs_alloc alloc;
	struct scoutfs_block_writer wri;
};

#define DECLARE_TRANS_INFO(sb, name) \
	struct trans_info *name = SCOUTFS_SB(sb)->trans_info

/* avoid the high sign bit out of an abundance of caution*/
#define TRANS_HOLDERS_WRITE_FUNC_BIT	(1 << 30)
#define TRANS_HOLDERS_COUNT_MASK	(TRANS_HOLDERS_WRITE_FUNC_BIT - 1)

static int commit_btrees(struct super_block *sb)
{
	DECLARE_TRANS_INFO(sb, tri);
	struct scoutfs_log_trees lt;

	lt = tri->lt;
	lt.meta_avail = tri->alloc.avail;
	lt.meta_freed = tri->alloc.freed;
	scoutfs_forest_get_btrees(sb, &lt);
	scoutfs_data_get_btrees(sb, &lt);

	return scoutfs_client_commit_log_trees(sb, &lt);
}

/*
 * This gets all the resources from the server that the client will
 * need during the transaction.
 */
int scoutfs_trans_get_log_trees(struct super_block *sb)
{
	DECLARE_TRANS_INFO(sb, tri);
	struct scoutfs_log_trees lt;
	int ret = 0;

	ret = scoutfs_client_get_log_trees(sb, &lt);
	if (ret == 0) {
		tri->lt = lt;
		scoutfs_alloc_init(&tri->alloc, &lt.meta_avail, &lt.meta_freed);
		scoutfs_block_writer_init(sb, &tri->wri);

		scoutfs_forest_init_btrees(sb, &tri->alloc, &tri->wri, &lt);
		scoutfs_data_init_btrees(sb, &tri->alloc, &tri->wri, &lt);
	}
	return ret;
}

bool scoutfs_trans_has_dirty(struct super_block *sb)
{
	DECLARE_TRANS_INFO(sb, tri);

	return scoutfs_block_writer_has_dirty(sb, &tri->wri);
}

/*
 * This is racing with wait_event conditions, make sure our atomic
 * stores and waitqueue loads are ordered.
 */
static void sub_holders_and_wake(struct super_block *sb, int val)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_TRANS_INFO(sb, tri);

	atomic_sub(val, &tri->holders);
	smp_mb(); /* make sure sub is visible before we wake */
	if (waitqueue_active(&sbi->trans_hold_wq))
		wake_up(&sbi->trans_hold_wq);
}

/*
 * called as a wait_event condition, needs to be careful to not change
 * task state and is racing with waking paths that sub_return, test, and
 * wake.
 */
static bool drained_holders(struct trans_info *tri)
{
	int holders;

	smp_mb(); /* make sure task in wait_event queue before atomic read */
	holders = atomic_read(&tri->holders) & TRANS_HOLDERS_COUNT_MASK;

	return holders == 0;
}

/*
 * This work func is responsible for writing out all the dirty blocks
 * that make up the current dirty transaction.  It prevents writers from
 * holding a transaction so it doesn't have to worry about blocks being
 * dirtied while it is working.
 *
 * In the course of doing its work this task might need to use write
 * functions that would try to hold the transaction.  We record the task
 * whose committing the transaction so that holding won't deadlock.
 *
 * Any dirty block had to have allocated a new blkno which would have
 * created dirty allocator metadata blocks.  We can avoid writing
 * entirely if we don't have any dirty metadata blocks.  This is
 * important because we don't try to serialize this work during
 * unmount.. we can execute as the vfs is shutting down.. we need to
 * decide that nothing is dirty without calling the vfs at all.
 *
 * We first try to sync the dirty inodes and write their dirty data blocks,
 * then we write all our dirty metadata blocks, and only when those succeed
 * do we write the new super that references all of these newly written blocks.
 *
 * If there are write errors then blocks are kept dirty in memory and will
 * be written again at the next sync.
 */
void scoutfs_trans_write_func(struct work_struct *work)
{
	struct scoutfs_sb_info *sbi = container_of(work, struct scoutfs_sb_info,
						   trans_write_work.work);
	struct super_block *sb = sbi->sb;
	DECLARE_TRANS_INFO(sb, tri);
	u64 trans_seq = sbi->trans_seq;
	char *s = NULL;
	int ret = 0;

	sbi->trans_task = current;

	/* mark that we're writing so holders wait for us to finish and clear our bit */
	atomic_add(TRANS_HOLDERS_WRITE_FUNC_BIT, &tri->holders);

	wait_event(sbi->trans_hold_wq, drained_holders(tri));

	if (scoutfs_forcing_unmount(sb)) {
		ret = -EIO;
		goto out;
	}

	trace_scoutfs_trans_write_func(sb,
			scoutfs_block_writer_dirty_bytes(sb, &tri->wri));

	if (!scoutfs_block_writer_has_dirty(sb, &tri->wri) &&
	    !scoutfs_item_dirty_pages(sb)) {
		if (sbi->trans_deadline_expired) {
			/*
			 * If we're not writing data then we only advance the
			 * seq at the sync deadline interval.  This keeps idle
			 * mounts from pinning a seq and stopping readers of the
			 * seq indices but doesn't send a message for every sync
			 * syscall.
			 */
			ret = scoutfs_client_advance_seq(sb, &trans_seq);
			if (ret < 0)
			      s = "clean advance seq";
		}
		goto err;
	}

	if (sbi->trans_deadline_expired)
		scoutfs_inc_counter(sb, trans_commit_timer);

	scoutfs_inc_counter(sb, trans_commit_written);

	/* XXX this all needs serious work for dealing with errors */
	ret = (s = "data submit", scoutfs_inode_walk_writeback(sb, true)) ?:
	      (s = "item dirty", scoutfs_item_write_dirty(sb))  ?:
	      (s = "data prepare", scoutfs_data_prepare_commit(sb))  ?:
	      (s = "alloc prepare", scoutfs_alloc_prepare_commit(sb,
						&tri->alloc, &tri->wri))  ?:
	      (s = "meta write", scoutfs_block_writer_write(sb, &tri->wri))  ?:
	      (s = "data wait", scoutfs_inode_walk_writeback(sb, false)) ?:
	      (s = "commit log trees", commit_btrees(sb)) ?:
	      scoutfs_item_write_done(sb) ?:
	      (s = "advance seq", scoutfs_client_advance_seq(sb, &trans_seq)) ?:
	      (s = "get log trees", scoutfs_trans_get_log_trees(sb));
err:
	if (ret < 0)
		scoutfs_err(sb, "critical transaction commit failure: %s, %d",
			    s, ret);

out:
	spin_lock(&sbi->trans_write_lock);
	sbi->trans_write_count++;
	sbi->trans_write_ret = ret;
	sbi->trans_seq = trans_seq;
	spin_unlock(&sbi->trans_write_lock);
	wake_up(&sbi->trans_write_wq);

	/* we're done, wake waiting holders */
	sub_holders_and_wake(sb, TRANS_HOLDERS_WRITE_FUNC_BIT);

	sbi->trans_task = NULL;

	scoutfs_trans_restart_sync_deadline(sb);
}

struct write_attempt {
	u64 count;
	int ret;
};

/* this is called as a wait_event() condition so it can't change task state */
static int write_attempted(struct scoutfs_sb_info *sbi,
			   struct write_attempt *attempt)
{
	int done = 1;

	spin_lock(&sbi->trans_write_lock);
	if (sbi->trans_write_count > attempt->count)
		attempt->ret = sbi->trans_write_ret;
	else
		done = 0;
	spin_unlock(&sbi->trans_write_lock);

	return done;
}


/*
 * We always have delayed sync work pending but the caller wants it
 * to execute immediately.
 */
static void queue_trans_work(struct scoutfs_sb_info *sbi)
{
	sbi->trans_deadline_expired = false;
	mod_delayed_work(sbi->trans_write_workq, &sbi->trans_write_work, 0);
}

/*
 * Wait for a trans commit to finish and return its error code.  There
 * can already be one in flight that we end up waiting for the
 * completion of.  This is safe because dirtying and trans commits are
 * serialized.  There's no way that there could have been dirty data
 * before the caller got here that wouldn't be covered by a commit
 * that's in flight. 
 */
int scoutfs_trans_sync(struct super_block *sb, int wait)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct write_attempt attempt;
	int ret;


	if (!wait) {
		queue_trans_work(sbi);
		return 0;
	}

	spin_lock(&sbi->trans_write_lock);
	attempt.count = sbi->trans_write_count;
	spin_unlock(&sbi->trans_write_lock);

	queue_trans_work(sbi);

	ret = wait_event_interruptible(sbi->trans_write_wq,
				       write_attempted(sbi, &attempt));
	if (ret == 0)
		ret = attempt.ret;

	return ret;
}

int scoutfs_file_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	struct super_block *sb = file_inode(file)->i_sb;

	scoutfs_inc_counter(sb, trans_commit_fsync);
	return scoutfs_trans_sync(sb, 1);
}

void scoutfs_trans_restart_sync_deadline(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	sbi->trans_deadline_expired = true;
	mod_delayed_work(sbi->trans_write_workq, &sbi->trans_write_work,
			 TRANS_SYNC_DELAY);
}

/*
 * We store nested holders in the lower bits of journal_info.  We use
 * some higher bits as a magic value to detect if something goes
 * horribly wrong and it gets clobbered.
 */
#define TRANS_JI_MAGIC		0xd5700000
#define TRANS_JI_MAGIC_MASK	0xfff00000
#define TRANS_JI_COUNT_MASK	0x000fffff

/* returns true if a caller already had a holder counted in journal_info */
static bool inc_journal_info_holders(void)
{
	unsigned long holders = (unsigned long)current->journal_info;

	WARN_ON_ONCE(holders != 0 && ((holders & TRANS_JI_MAGIC_MASK) != TRANS_JI_MAGIC));

	if (holders == 0)
		holders = TRANS_JI_MAGIC;
	holders++;

	current->journal_info = (void *)holders;
	return (holders > (TRANS_JI_MAGIC | 1));
}

static void dec_journal_info_holders(void)
{
	unsigned long holders = (unsigned long)current->journal_info;

	WARN_ON_ONCE(holders != 0 && ((holders & TRANS_JI_MAGIC_MASK) != TRANS_JI_MAGIC));
	WARN_ON_ONCE((holders & TRANS_JI_COUNT_MASK) == 0);

	holders--;
	if (holders == TRANS_JI_MAGIC)
		holders = 0;

	current->journal_info = (void *)holders;
}

/*
 * This is called as the wait_event condition for holding a transaction.
 * Increment the holder count unless the writer is present.  We return
 * false to wait until the writer finishes and wakes us.
 *
 * This can be racing with itself while there's no waiters.  We retry
 * the cmpxchg instead of returning and waiting.
 */
static bool inc_holders_unless_writer(struct trans_info *tri)
{
	int holders;

	do {
		smp_mb(); /* make sure we read after wait puts task in queue */
		holders = atomic_read(&tri->holders);
		if (holders & TRANS_HOLDERS_WRITE_FUNC_BIT)
			return false;

	} while (atomic_cmpxchg(&tri->holders, holders, holders + 1) != holders);

	return true;
}

/*
 * As we drop the last trans holder we try to wake a writing thread that
 * was waiting for us to finish.
 */
static void release_holders(struct super_block *sb)
{
	dec_journal_info_holders();
	sub_holders_and_wake(sb, 1);
}

/*
 * The caller has incremented holders so it is blocking commits.  We
 * make some quick checks to see if we need to trigger and wait for
 * another commit before proceeding.
 */
static bool commit_before_hold(struct super_block *sb, struct trans_info *tri)
{
	/*
	 * In theory each dirty item page could be straddling two full
	 * blocks, requiring 4 allocations for each item cache page.
	 * That's much too conservative, typically many dirty item cache
	 * pages that are near each other all land in one block.  This
	 * rough estimate is still so far beyond what typically happens
	 * that it accounts for having to dirty parent blocks and
	 * whatever dirtying is done during the transaction hold.
	 */
	if (scoutfs_alloc_meta_low(sb, &tri->alloc, scoutfs_item_dirty_pages(sb) * 2)) {
		scoutfs_inc_counter(sb, trans_commit_dirty_meta_full);
		return true;
	}

	/*
	 * Extent modifications can use meta allocators without creating
	 * dirty items so we have to check the meta alloc specifically.
	 * The size of the client's avail and freed roots are bound so
	 * we're unlikely to need very many block allocations per
	 * transaction hold.  XXX This should be more precisely tuned.
	 */
	if (scoutfs_alloc_meta_low(sb, &tri->alloc, 16)) {
		scoutfs_inc_counter(sb, trans_commit_meta_alloc_low);
		return true;
	}

	/* Try to refill data allocator before premature enospc */
	if (scoutfs_data_alloc_free_bytes(sb) <= SCOUTFS_TRANS_DATA_ALLOC_LWM) {
		scoutfs_inc_counter(sb, trans_commit_data_alloc_low);
		return true;
	}

	return false;
}

static bool acquired_hold(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_TRANS_INFO(sb, tri);
	bool acquired;

	/* if a caller already has a hold we acquire unconditionally */
	if (inc_journal_info_holders()) {
		atomic_inc(&tri->holders);
		acquired = true;
		goto out;
	}

	/* wait if the writer is blocking holds */
	if (!inc_holders_unless_writer(tri)) {
		dec_journal_info_holders();
		acquired = false;
		goto out;
	}

	/* wait if we're triggering another commit */
	if (commit_before_hold(sb, tri)) {
		release_holders(sb);
		queue_trans_work(sbi);
		acquired = false;
		goto out;
	}

	trace_scoutfs_trans_acquired_hold(sb, current->journal_info, atomic_read(&tri->holders));
	acquired = true;
out:
	return acquired;
}

/*
 * Try to hold the transaction.  Holding the transaction prevents it
 * from being committed.  If a transaction is currently being written
 * then we'll block until it's done and our hold can be granted.
 *
 * If a caller already holds the trans then we unconditionally acquire
 * our hold and return to avoid deadlocks with our caller, the writing
 * thread, and us.  We record nested holds in a call stack with the
 * journal_info pointer in the task_struct.
 *
 * The writing thread marks itself as a global trans_task which
 * short-circuits all the hold machinery so it can call code that would
 * otherwise try to hold transactions while it is writing.
 */
int scoutfs_hold_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (current == sbi->trans_task)
		return 0;

	return wait_event_interruptible(sbi->trans_hold_wq, acquired_hold(sb));
}

/*
 * Return true if the current task has a transaction held.  That is,
 * true if the current transaction can't finish and be written out if
 * the current task blocks.
 */
bool scoutfs_trans_held(void)
{
	unsigned long holders = (unsigned long)current->journal_info;

	return (holders != 0 && ((holders & TRANS_JI_MAGIC_MASK) == TRANS_JI_MAGIC));
}

void scoutfs_release_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_TRANS_INFO(sb, tri);

	if (current == sbi->trans_task)
		return;

	release_holders(sb);

	trace_scoutfs_release_trans(sb, current->journal_info, atomic_read(&tri->holders));
}

/*
 * Return the current transaction sequence.  Whether this is racing with
 * the transaction write thread is entirely dependent on the caller's
 * context.
 */
u64 scoutfs_trans_sample_seq(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	u64 ret;

	spin_lock(&sbi->trans_write_lock);
	ret = sbi->trans_seq;
	spin_unlock(&sbi->trans_write_lock);

	return ret;
}

int scoutfs_setup_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct trans_info *tri;

	tri = kzalloc(sizeof(struct trans_info), GFP_KERNEL);
	if (!tri)
		return -ENOMEM;

	atomic_set(&tri->holders, 0);
	scoutfs_block_writer_init(sb, &tri->wri);

	sbi->trans_write_workq = alloc_workqueue("scoutfs_trans",
						 WQ_UNBOUND, 1);
	if (!sbi->trans_write_workq) {
		kfree(tri);
		return -ENOMEM;
	}

	sbi->trans_info = tri;

	return 0;
}

/*
 * While the vfs will have done an fs level sync before calling
 * put_super, we may have done work down in our level after all the fs
 * ops were done.  An example is final inode deletion in iput, that's
 * done in generic_shutdown_super after the sync and before calling our
 * put_super.
 *
 * So we always try to write any remaining dirty transactions before
 * shutting down.  Typically there won't be any dirty data and the
 * worker will just return.
 */
void scoutfs_shutdown_trans(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_TRANS_INFO(sb, tri);

	if (tri) {
		if (sbi->trans_write_workq) {
			/* immediately queues pending timer */
			flush_delayed_work(&sbi->trans_write_work);
			/* prevents re-arming if it has to wait */
			cancel_delayed_work_sync(&sbi->trans_write_work);
			destroy_workqueue(sbi->trans_write_workq);
			/* trans work schedules after shutdown see null */
			sbi->trans_write_workq = NULL;
		}

		scoutfs_block_writer_forget_all(sb, &tri->wri);

		kfree(tri);
		sbi->trans_info = NULL;
	}
}
