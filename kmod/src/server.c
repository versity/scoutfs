/*
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
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
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/log2.h>
#include <asm/unaligned.h>

#include "format.h"
#include "counters.h"
#include "inode.h"
#include "block.h"
#include "btree.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "server.h"
#include "net.h"
#include "lock_server.h"
#include "endian_swap.h"
#include "quorum.h"
#include "trans.h"
#include "srch.h"
#include "alloc.h"
#include "forest.h"
#include "recov.h"
#include "omap.h"
#include "fence.h"

/*
 * Every active mount can act as the server that listens on a net
 * connection and accepts connections from all the other mounts acting
 * as clients.
 *
 * The server is started by the mount that is elected leader by quorum.
 * If it sees errors it shuts down the server in the hopes that another
 * mount will become the leader and have less trouble.
 */

/*
 * Tracks all the holders and commit work that are operating on server
 * commits.  It synchronizes holders modifying the blocks in the commit
 * and the commit work writing dirty blocks that make up a consistent
 * commit.  It limits the number of active holders so that they don't
 * fully consume the allocation resources prepared for a commit.
 */
struct commit_users {
	wait_queue_head_t waitq;
	spinlock_t lock;
	struct list_head holding;
	struct list_head applying;
	unsigned int nr_holders;
	u32 budget;
	u32 avail_before;
	u32 freed_before;
	bool committing;
	bool exceeded;
};

static void init_commit_users(struct commit_users *cusers)
{
	memset(cusers, 0, sizeof(struct commit_users));
	init_waitqueue_head(&cusers->waitq);
	spin_lock_init(&cusers->lock);
	INIT_LIST_HEAD(&cusers->holding);
	INIT_LIST_HEAD(&cusers->applying);
}

#define TRACE_COMMIT_USERS(sb, cusers, which)							\
do {												\
	__typeof__(cusers) _cusers = (cusers);							\
	trace_scoutfs_server_commit_##which(sb, !list_empty(&_cusers->holding),			\
		!list_empty(&_cusers->applying), _cusers->nr_holders, _cusers->budget,		\
		_cusers->avail_before, _cusers->freed_before, _cusers->committing,		\
		_cusers->exceeded);								\
} while (0)

struct server_info {
	struct super_block *sb;
	spinlock_t lock;
	seqlock_t seqlock;
	wait_queue_head_t waitq;

	struct workqueue_struct *wq;
	struct work_struct work;
	int status;
	u64 term;
	struct scoutfs_net_connection *conn;

	/* synced with superblock seq on commits */
	atomic64_t seq_atomic;

	/* request processing coordinates shared commits */
	struct commit_users cusers;
	struct work_struct commit_work;

	struct list_head clients;
	unsigned long nr_clients;

	/* track clients waiting in unmmount for farewell response */
	spinlock_t farewell_lock;
	struct list_head farewell_requests;
	struct work_struct farewell_work;

	struct mutex alloc_mutex;
	/* swap between two fs meta roots to increase time to reuse */
	struct scoutfs_alloc_root *meta_avail;
	struct scoutfs_alloc_root *meta_freed;
	/* server's meta allocators alternate between persistent heads */
	struct scoutfs_alloc alloc;
	int other_ind;
	struct scoutfs_alloc_list_head *other_avail;
	struct scoutfs_alloc_list_head *other_freed;
	struct scoutfs_block_writer wri;

	struct mutex logs_mutex;
	struct work_struct log_merge_free_work;

	struct mutex srch_mutex;
	struct mutex mounted_clients_mutex;

	/* stable super stored from commits, given in locks and rpcs */
	struct scoutfs_super_block stable_super;

	/* serializing and get and set volume options */
	struct mutex volopt_mutex;
	struct scoutfs_volume_options volopt;

	/* recovery timeout fences from work */
	struct work_struct fence_pending_recov_work;
	/* while running we check for fenced mounts to reclaim */
	struct delayed_work reclaim_dwork;

	/* a running server gets a static quorum config from quorum as it starts */
	struct scoutfs_quorum_config qconf;
	/* a running server maintains a private dirty super */
	struct scoutfs_super_block dirty_super;

	u64 finalize_sent_seq;
};

#define DECLARE_SERVER_INFO(sb, name) \
	struct server_info *name = SCOUTFS_SB(sb)->server_info

#define DIRTY_SUPER_SB(sb)	(&SCOUTFS_SB(sb)->server_info->dirty_super)

/*
 * The server tracks each connected client.
 */
struct server_client_info {
	u64 rid;
	struct list_head head;
};

static __le64 *first_valopt(struct scoutfs_volume_options *valopt)
{
	return &valopt->set_bits + 1;
}

/*
 * A server caller wants to know if a volume option is set and wants to
 * know it's value.  This is quite early in the file to make it
 * available to all of the server paths.
 */
static bool get_volopt_val(struct server_info *server, int nr, u64 *val)
{
	u64 bit = 1ULL << nr;
	__le64 *opt = first_valopt(&server->volopt) + nr;
	bool is_set = false;
	unsigned seq;

	do {
		seq = read_seqbegin(&server->seqlock);
		if ((le64_to_cpu(server->volopt.set_bits) & bit)) {
			is_set = true;
			*val = le64_to_cpup(opt);
		} else {
			is_set = false;
			*val = 0;
		};
	} while (read_seqretry(&server->seqlock, seq));

	return is_set;
}

enum {
	SERVER_NOP = 0,
	SERVER_STARTING,
	SERVER_UP,
	SERVER_STOPPING,
	SERVER_DOWN,
};

bool scoutfs_server_is_running(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);
	long was = cmpxchg(&server->status, SERVER_NOP, SERVER_NOP);

	return was == SERVER_STARTING || was == SERVER_UP;
}

bool scoutfs_server_is_up(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	return cmpxchg(&server->status, SERVER_NOP, SERVER_NOP) == SERVER_UP;
}

bool scoutfs_server_is_down(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	return cmpxchg(&server->status, SERVER_NOP, SERVER_NOP) == SERVER_DOWN;
}

static bool server_is_stopping(struct server_info *server)
{
	return cmpxchg(&server->status, SERVER_NOP, SERVER_NOP) == SERVER_STOPPING;
}

static void stop_server(struct server_info *server)
{
	long was = cmpxchg(&server->status, SERVER_NOP, SERVER_NOP);

	if ((was == SERVER_STARTING || was == SERVER_UP) &&
	    cmpxchg(&server->status, was, SERVER_STOPPING) == was)
		wake_up(&server->waitq);
}

static void server_up(struct server_info *server)
{
	cmpxchg(&server->status, SERVER_STARTING, SERVER_UP);
}

static void server_down(struct server_info *server)
{
	long was = cmpxchg(&server->status, SERVER_NOP, SERVER_NOP);

	if (was != SERVER_DOWN)
		cmpxchg(&server->status, was, SERVER_DOWN);
}

/*
 * The per-holder allocation block use budget balances batching
 * efficiency and concurrency.  The larger this gets, the fewer
 * concurrent server operations can be performed in one commit.  Commits
 * are immediately written after being dirtied so this really only
 * limits immediate concurrency under load, not batching over time as
 * one might expect if commits were long lived.
 *
 * The upper bound is determined by the server commit hold path that can
 * dirty the most blocks.
 */
#define COMMIT_HOLD_ALLOC_BUDGET 500

struct commit_hold {
	struct list_head entry;
	ktime_t start;
	u32 avail;
	u32 freed;
	int ret;
	bool exceeded;
};

#define COMMIT_HOLD(name) \
        struct commit_hold name = { .entry = LIST_HEAD_INIT(name.entry) }

/*
 * See if the currently active holders have, all together, consumed more
 * allocation resources than they were allowed.  We don't have
 * per-holder allocation consumption tracking.   The best we can do is
 * flag all the current holders so that as they release we can see
 * everyone involved in crossing the limit.
 *
 * The consumption of space to record freed blocks is tricky.  The
 * freed_before value was the space available as the holder started.
 * But that happens before we actually dirty the first block in the
 * freed list.  If that block is too full then we just allocate a new
 * empty first block.  In that case the current remaining here can be a
 * lot more than the initial freed_before.  We account for that and
 * treat freed_before as the maximum capacity.
 */
static void check_holder_budget(struct super_block *sb, struct server_info *server,
				struct commit_users *cusers)
{
	static bool exceeded_once = false;
	struct commit_hold *hold;
	struct timespec64 ts;
	u32 avail_used;
	u32 freed_used;
	u32 avail_now;
	u32 freed_now;

	assert_spin_locked(&cusers->lock);

	if (cusers->exceeded || cusers->nr_holders == 0 || exceeded_once)
		return;

	scoutfs_alloc_meta_remaining(&server->alloc, &avail_now, &freed_now);

	avail_used = cusers->avail_before - avail_now;
	if (freed_now < cusers->freed_before)
		freed_used = cusers->freed_before - freed_now;
	else
		freed_used = SCOUTFS_ALLOC_LIST_MAX_BLOCKS - freed_now;

	if (avail_used <= cusers->budget && freed_used <= cusers->budget)
		return;

	exceeded_once = true;
	cusers->exceeded = cusers->nr_holders;

	scoutfs_err(sb, "holders exceeded alloc budget %u av: bef %u now %u, fr: bef %u now %u",
		    cusers->budget, cusers->avail_before, avail_now,
		    cusers->freed_before, freed_now);

	list_for_each_entry(hold, &cusers->holding, entry) {
		ts = ktime_to_timespec64(hold->start);
		scoutfs_err(sb, "exceeding hold start %llu.%09llu av %u fr %u",
			    (u64)ts.tv_sec, (u64)ts.tv_nsec, hold->avail, hold->freed);
		hold->exceeded = true;
	}
}

/*
 * We don't have per-holder consumption.   We allow commit holders as
 * long as the total budget of all the holders doesn't exceed the alloc
 * resources that were available.  If a hold is waiting for budget
 * availability in the allocators then we try and kick off a commit to
 * fill and use the next allocators after the current transaction.
 */
static bool hold_commit(struct super_block *sb, struct server_info *server,
			struct commit_users *cusers, struct commit_hold *hold)
{
	bool has_room;
	bool held;
	u32 new_budget;
	u32 av;
	u32 fr;

	spin_lock(&cusers->lock);

	TRACE_COMMIT_USERS(sb, cusers, hold);

	check_holder_budget(sb, server, cusers);

	if (cusers->nr_holders == 0) {
		scoutfs_alloc_meta_remaining(&server->alloc, &av, &fr);
	} else {
		av = cusers->avail_before;
		fr = cusers->freed_before;
	}

	/* +2 for our additional hold and then for the final commit work the server does */
	new_budget = max(cusers->budget, (cusers->nr_holders + 2) * COMMIT_HOLD_ALLOC_BUDGET);
	has_room = av >= new_budget && fr >= new_budget;
	/* checking applying so holders drain once an apply caller starts waiting */
	held = !cusers->committing && has_room && list_empty(&cusers->applying);

	if (held) {
		if (cusers->nr_holders == 0) {
			cusers->avail_before = av;
			cusers->freed_before = fr;
			hold->avail = av;
			hold->freed = fr;
			cusers->exceeded = false;
		} else {
			scoutfs_alloc_meta_remaining(&server->alloc, &hold->avail, &hold->freed);
		}

		hold->exceeded = false;
		hold->start = ktime_get();
		list_add_tail(&hold->entry, &cusers->holding);

		cusers->nr_holders++;
		cusers->budget = new_budget;

	} else if (!has_room && cusers->nr_holders == 0 && !cusers->committing) {
		cusers->committing = true;
		queue_work(server->wq, &server->commit_work);
	}

	spin_unlock(&cusers->lock);

	return held;
}

/*
 * Hold the server commit so that we can make a consistent change to the
 * dirty blocks in the commit.   The commit won't be written while we
 * hold it.
 */
static void server_hold_commit(struct super_block *sb, struct commit_hold *hold)
{
	DECLARE_SERVER_INFO(sb, server);
	struct commit_users *cusers = &server->cusers;

	BUG_ON(!list_empty(&hold->entry));

	scoutfs_inc_counter(sb, server_commit_hold);
	wait_event(cusers->waitq, hold_commit(sb, server, cusers, hold));
}

/*
 * Return the higher of the avail or freed used by the active commit
 * since this holder joined the commit.  This is *not* the amount used
 * by the holder, we don't track per-holder alloc use.
 */
static u32 server_hold_alloc_used_since(struct super_block *sb, struct commit_hold *hold)
{
	DECLARE_SERVER_INFO(sb, server);
	u32 avail_used;
	u32 freed_used;
	u32 avail_now;
	u32 freed_now;

	scoutfs_alloc_meta_remaining(&server->alloc, &avail_now, &freed_now);

	avail_used = hold->avail - avail_now;
	freed_used = hold->freed - freed_now;

	return max(avail_used, freed_used);
}

/*
 * This is called while holding the commit and returns once the commit
 * is successfully written.  Many holders can all wait for all holders
 * to drain before their shared commit is applied and they're all woken.
 */
static int server_apply_commit(struct super_block *sb, struct commit_hold *hold, int err)
{
	DECLARE_SERVER_INFO(sb, server);
	struct commit_users *cusers = &server->cusers;
	struct timespec64 ts;

	spin_lock(&cusers->lock);

	TRACE_COMMIT_USERS(sb, cusers, apply);

	check_holder_budget(sb, server, cusers);

	if (hold->exceeded) {
		ts = ktime_to_timespec64(hold->start);
		scoutfs_err(sb, "exceeding hold start %llu.%09llu stack:",
			    (u64)ts.tv_sec, (u64)ts.tv_nsec);
		dump_stack();
	}

	if (err == 0) {
		list_move_tail(&hold->entry, &cusers->applying);
	} else {
		list_del_init(&hold->entry);
		hold->ret = err;
	}

	cusers->nr_holders--;
	if (cusers->nr_holders == 0 && !cusers->committing && !list_empty(&cusers->applying)) {
		cusers->committing = true;
		queue_work(server->wq, &server->commit_work);
	}

	spin_unlock(&cusers->lock);

	wait_event(cusers->waitq, list_empty_careful(&hold->entry));
	smp_rmb(); /* entry load before ret */
	return hold->ret;
}

/*
 * Start a commit from the commit work.  We should only have been queued
 * while there are no active holders and someone started the commit.
 * There may or may not be blocked apply callers waiting for the result.
 */
static int commit_start(struct super_block *sb, struct commit_users *cusers)
{
	int ret = 0;

	/* make sure holders held off once commit started */
	spin_lock(&cusers->lock);
	TRACE_COMMIT_USERS(sb, cusers, start);
	if (WARN_ON_ONCE(!cusers->committing || cusers->nr_holders != 0))
		ret = -EINVAL;
	spin_unlock(&cusers->lock);

	return ret;
}

/*
 * Finish a commit from the commit work.  Give the result to all the
 * holders who are waiting for the commit to be applied.
 */
static void commit_end(struct super_block *sb, struct commit_users *cusers, int ret)
{
	struct commit_hold *hold;
	struct commit_hold *tmp;

	spin_lock(&cusers->lock);
	TRACE_COMMIT_USERS(sb, cusers, end);
	list_for_each_entry(hold, &cusers->applying, entry)
		hold->ret = ret;
	smp_wmb(); /* ret stores before list updates */
	list_for_each_entry_safe(hold, tmp, &cusers->applying, entry)
		list_del_init(&hold->entry);
	cusers->committing = false;
	cusers->budget = 0;
	spin_unlock(&cusers->lock);

	wake_up(&cusers->waitq);
}

static void get_stable(struct super_block *sb, struct scoutfs_super_block *super,
		       struct scoutfs_net_roots *roots)
{
	DECLARE_SERVER_INFO(sb, server);
	unsigned int seq;

	do {
		seq = read_seqbegin(&server->seqlock);
		if (super)
			*super = server->stable_super;
		if (roots) {
			roots->fs_root = server->stable_super.fs_root;
			roots->logs_root = server->stable_super.logs_root;
			roots->srch_root = server->stable_super.srch_root;
		}
	} while (read_seqretry(&server->seqlock, seq));
}

u64 scoutfs_server_seq(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	return atomic64_read(&server->seq_atomic);
}

u64 scoutfs_server_next_seq(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	return atomic64_inc_return(&server->seq_atomic);
}

void scoutfs_server_set_seq_if_greater(struct super_block *sb, u64 seq)
{
	DECLARE_SERVER_INFO(sb, server);
	u64 expect;
	u64 was;

	expect = atomic64_read(&server->seq_atomic);
	while (seq > expect) {
	       was = atomic64_cmpxchg(&server->seq_atomic, expect, seq);
	       if (was == expect)
		       break;
	       expect = was;
	}
}

static void set_stable_super(struct server_info *server, struct scoutfs_super_block *super)
{
	write_seqlock(&server->seqlock);
	server->stable_super = *super;
	write_sequnlock(&server->seqlock);
}

/*
 * Concurrent request processing dirties blocks in a commit and makes
 * the modifications persistent before replying.  We'd like to batch
 * these commits as much as is reasonable so that we don't degrade to a
 * few synchronous IOs per request.
 *
 * Getting that batching right is bound up in the concurrency of request
 * processing so a clear way to implement the batched commits is to
 * implement commits with a single pending work func.
 *
 * Processing paths hold the commit while they're making multiple
 * dependent changes.  When they're done and want it persistent they
 * queue the commit work.  This work runs, performs the commit, and
 * wakes all the applying waiters with the result.  Readers can run
 * concurrently with these commits.
 */
static void scoutfs_server_commit_func(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  commit_work);
	struct super_block *sb = server->sb;
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct commit_users *cusers = &server->cusers;
	int ret;

	trace_scoutfs_server_commit_work_enter(sb, 0, 0);
	scoutfs_inc_counter(sb, server_commit_worker);

	ret = commit_start(sb, cusers);
	if (ret < 0)
		goto out;

	if (scoutfs_forcing_unmount(sb)) {
		ret = -ENOLINK;
		goto out;
	}

	/* make sure next avail has sufficient blocks */
	ret = scoutfs_alloc_fill_list(sb, &server->alloc, &server->wri,
				      server->other_avail,
				      server->meta_avail,
				      SCOUTFS_SERVER_META_FILL_LO,
				      SCOUTFS_SERVER_META_FILL_TARGET);
	if (ret) {
		scoutfs_err(sb, "server error refilling avail: %d", ret);
		goto out;
	}

	/* merge freed blocks into extents, might be partial */
	ret = scoutfs_alloc_empty_list(sb, &server->alloc, &server->wri,
				       server->meta_freed,
				       server->other_freed);
	if (ret) {
		scoutfs_err(sb, "server error emptying freed: %d", ret);
		goto out;
	}

	ret = scoutfs_alloc_prepare_commit(sb, &server->alloc, &server->wri);
	if (ret < 0) {
		scoutfs_err(sb, "server error prepare alloc commit: %d", ret);
		goto out;
	}

	ret = scoutfs_block_writer_write(sb, &server->wri);
	if (ret) {
		scoutfs_err(sb, "server error writing btree blocks: %d", ret);
		goto out;
	}

	super->seq = cpu_to_le64(atomic64_read(&server->seq_atomic));
	super->server_meta_avail[server->other_ind ^ 1] = server->alloc.avail;
	super->server_meta_freed[server->other_ind ^ 1] = server->alloc.freed;

	ret = scoutfs_write_super(sb, super);
	if (ret) {
		scoutfs_err(sb, "server error writing super block: %d", ret);
		goto out;
	}

	set_stable_super(server, super);

	/* swizzle the active and idle server alloc/freed heads */
	server->other_ind ^= 1;
	server->alloc.avail = super->server_meta_avail[server->other_ind ^ 1];
	server->alloc.freed = super->server_meta_freed[server->other_ind ^ 1];
	server->other_avail = &super->server_meta_avail[server->other_ind];
	server->other_freed = &super->server_meta_freed[server->other_ind];

	/*
	 * get_log_trees sets ALLOC_LOW when its allocator drops below
	 * the reserved blocks after having filled the log trees's avail
	 * allocator during its transaction.  To avoid prematurely
	 * setting the low flag and causing enospc we make sure that the
	 * next transaction's meta_avail has 2x the reserved blocks so
	 * that it can consume a full reserved amount and still have
	 * enough to avoid enospc.  We swap to freed if avail is under
	 * the buffer and freed is larger.
	 */
	if ((le64_to_cpu(server->meta_avail->total_len) <
	     (scoutfs_server_reserved_meta_blocks(sb) * 2)) &&
	    (le64_to_cpu(server->meta_freed->total_len) >
	     le64_to_cpu(server->meta_avail->total_len)))
		swap(server->meta_avail, server->meta_freed);

	ret = 0;
out:
	commit_end(sb, cusers, ret);

	trace_scoutfs_server_commit_work_exit(sb, 0, ret);
}

static int server_alloc_inodes(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_net_inode_alloc ial = { 0, };
	COMMIT_HOLD(hold);
	__le64 lecount;
	u64 ino;
	u64 nr;
	int ret;

	if (arg_len != sizeof(lecount)) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(&lecount, arg, arg_len);

	server_hold_commit(sb, &hold);

	spin_lock(&sbi->next_ino_lock);
	ino = le64_to_cpu(super->next_ino);
	nr = min(le64_to_cpu(lecount), U64_MAX - ino);
	le64_add_cpu(&super->next_ino, nr);
	spin_unlock(&sbi->next_ino_lock);

	ret = server_apply_commit(sb, &hold, 0);
	if (ret == 0) {
		ial.ino = cpu_to_le64(ino);
		ial.nr = cpu_to_le64(nr);
	}
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, &ial, sizeof(ial));
}

/*
 * Refill the destination root if it's fallen below the lo threshold by
 * moving from the src root to bring it up to the target.
 */
static int alloc_move_refill_zoned(struct super_block *sb, struct scoutfs_alloc_root *dst,
				   struct scoutfs_alloc_root *src, u64 lo, u64 target,
				   __le64 *exclusive, __le64 *vacant, u64 zone_blocks)
{
	DECLARE_SERVER_INFO(sb, server);

	if (le64_to_cpu(dst->total_len) >= lo)
		return 0;

	return scoutfs_alloc_move(sb, &server->alloc, &server->wri, dst, src,
				  min(target - le64_to_cpu(dst->total_len),
				      le64_to_cpu(src->total_len)),
				  exclusive, vacant, zone_blocks, 0);
}

static int alloc_move_empty(struct super_block *sb,
			    struct scoutfs_alloc_root *dst,
			    struct scoutfs_alloc_root *src, u64 meta_budget)
{
	DECLARE_SERVER_INFO(sb, server);

	return scoutfs_alloc_move(sb, &server->alloc, &server->wri,
				  dst, src, le64_to_cpu(src->total_len), NULL, NULL, 0,
				  meta_budget);
}

/*
 * Copy on write transactions need to allocate new dirty blocks as they
 * make modifications to delete items and eventually free more blocks.
 * The reserved blocks are meant to keep enough available blocks in
 * flight to allow servers and clients to perform transactions that
 * don't consume additional space.  We have quite a few allocators in
 * flight across the server and various client mechanisms (posix items,
 * srch compaction, and log merging).  We also want to include
 * sufficient blocks for client log btrees to grow tall enough to be
 * finalized and merges.
 *
 * The reserved blocks calculation is a policy of the server but it's
 * exposed to the statfs_more interface so that df isn't misleading.
 * Requiring this synchronization without explicit protocol
 * communication isn't great.
 */
u64 scoutfs_server_reserved_meta_blocks(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);
	u64 server_blocks;
	u64 client_blocks;
	u64 log_blocks;
	u64 nr_clients;

	/* server has two meta_avail lists it swaps between */
	server_blocks = SCOUTFS_SERVER_META_FILL_TARGET * 2;

	/*
	 * Log trees will be compacted once they hit a height of 3.
	 * That'll be the grandparent, two parents resulting from a
	 * split, and all their child blocks (roughly calculated,
	 * overestimating).
	 */
	log_blocks = 3 + (SCOUTFS_BLOCK_LG_SIZE /
		          (sizeof(struct scoutfs_btree_item) + sizeof(struct scoutfs_block_ref)));

	/*
	 * Each client can have a meta_avail list, srch compaction
	 * request, log merge request, and a log btree it's building.
	 */
	client_blocks = SCOUTFS_SERVER_META_FILL_TARGET + SCOUTFS_SERVER_META_FILL_TARGET +
			SCOUTFS_SERVER_MERGE_FILL_TARGET + log_blocks;

	/* we should reserve for voting majority, too */
	spin_lock(&server->lock);
	nr_clients = server->nr_clients;
	spin_unlock(&server->lock);

	return server_blocks + (max(1ULL, nr_clients) * client_blocks);
}

/*
 * Set all the bits in the destination which overlap with the extent.
 */
static void mod_extent_bits(__le64 *bits, u64 zone_blocks, u64 blkno, u64 len, bool set)
{
	u64 nr = div64_u64(blkno, zone_blocks);
	u64 last_nr = div64_u64(blkno + len - 1, zone_blocks);

	if (WARN_ON_ONCE(len == 0))
		return;

	while (nr <= last_nr) {
		if (set)
			set_bit_le(nr, bits);
		else
			clear_bit_le(nr, bits);

		nr++;
	}
}

/*
 * Translate the bits in the source bitmap into extents and modify bits
 * in the destination that map those extents.
 */
static void mod_bitmap_bits(__le64 *dst, u64 dst_zone_blocks,
			    __le64 *src, u64 src_zone_blocks, bool set)
{
	int nr = 0;

	for (;;) {
		nr = find_next_bit_le(src, SCOUTFS_DATA_ALLOC_MAX_ZONES, nr);
		if (nr >= SCOUTFS_DATA_ALLOC_MAX_ZONES)
			break;

		mod_extent_bits(dst, dst_zone_blocks,
				(u64)nr * src_zone_blocks, src_zone_blocks, set);
		nr++;
	}
}

/*
 * Iterate over all the log_tree items and initialize the caller's zone
 * bitmaps.  Exclusive bits are only found in the caller's items.
 * Vacant bits are not found in any items.
 *
 * The log_tree item zone bitmaps could have been stored with different
 * zone_blocks sizes.  We translate the bits into block extents and
 * record overlaps with the current zone size.
 *
 * The caller has the log items locked.
 */
static int get_data_alloc_zone_bits(struct super_block *sb, u64 rid, __le64 *exclusive,
				    __le64 *vacant, u64 zone_blocks)
{
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees *lt;
	struct scoutfs_key key;
	int ret;

	memset(exclusive, 0, SCOUTFS_DATA_ALLOC_ZONE_BYTES);
	memset(vacant, 0, SCOUTFS_DATA_ALLOC_ZONE_BYTES);

	mod_extent_bits(vacant, zone_blocks, 0, le64_to_cpu(super->total_data_blocks), true);

	scoutfs_key_init_log_trees(&key, 0, 0);
	for (;;) {
		ret = scoutfs_btree_next(sb, &super->logs_root, &key, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(struct scoutfs_log_trees)) {
				lt = iref.val;

				/* vacant bits have no bits found in items */
				mod_bitmap_bits(vacant, zone_blocks,
						lt->data_alloc_zones,
						le64_to_cpu(lt->data_alloc_zone_blocks),
						false);

				/* exclusive bits are only found in caller's items */
				if (le64_to_cpu(iref.key->sklt_rid) == rid) {
					mod_bitmap_bits(exclusive, zone_blocks,
							lt->data_alloc_zones,
							le64_to_cpu(lt->data_alloc_zone_blocks),
							true);
				} else {
					mod_bitmap_bits(exclusive, zone_blocks,
							lt->data_alloc_zones,
							le64_to_cpu(lt->data_alloc_zone_blocks),
							false);
				}

				key = *iref.key;
				scoutfs_key_inc(&key);
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}
	}

	return ret;
}

static void zero_data_alloc_zone_bits(struct scoutfs_log_trees *lt)
{
	lt->data_alloc_zone_blocks = 0;
	memset(lt->data_alloc_zones, 0, sizeof(lt->data_alloc_zones));
}

struct alloc_extent_cb_args {
	__le64 *zones;
	u64 zone_blocks;
};

static void set_extent_zone_bits(struct super_block *sb, void *cb_arg, struct scoutfs_extent *ext)
{
	struct alloc_extent_cb_args *cba = cb_arg;

	mod_extent_bits(cba->zones, cba->zone_blocks, ext->start, ext->len, true);
}

static int find_log_trees_item(struct super_block *sb,
			       struct scoutfs_btree_root *logs_root,
			       bool call_next, u64 rid, u64 nr,
			       struct scoutfs_log_trees *lt_ret)
{
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	scoutfs_key_init_log_trees(&key, rid, nr);
	if (call_next)
		ret = scoutfs_btree_next(sb, logs_root, &key, &iref);
	else
		ret = scoutfs_btree_prev(sb, logs_root, &key, &iref);
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees)) {
			if (le64_to_cpu(iref.key->sklt_rid) != rid)
				ret = -ENOENT;
			else
				memcpy(lt_ret, iref.val, iref.val_len);
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
	}

	return ret;
}

/*
 * Find the log_trees item with the greatest nr for each rid.  Fills the
 * caller's log_trees and sets the key before the returned log_trees for
 * the next iteration.  Returns 0 when done, > 0 for each item, and
 * -errno on fatal errors.
 */
static int for_each_rid_last_lt(struct super_block *sb, struct scoutfs_btree_root *root,
				struct scoutfs_key *key, struct scoutfs_log_trees *lt)
{
	SCOUTFS_BTREE_ITEM_REF(iref);
	int ret;

	ret = scoutfs_btree_prev(sb, root, key, &iref);
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees)) {
			memcpy(lt, iref.val, iref.val_len);
			*key = *iref.key;
			key->sklt_nr = 0;
			scoutfs_key_dec(key);
			ret = 1;
		} else {
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
	} else if (ret == -ENOENT) {
		ret = 0;
	}

	return ret;
}

/*
 * Log merge range items are stored at the starting fs key of the range.
 * The only fs key field that doesn't hold information is the zone, so
 * we use the zone to differentiate all types that we store in the log
 * merge tree.
 */
static void init_log_merge_key(struct scoutfs_key *key, u8 zone, u64 first,
			       u64 second)
{
	*key = (struct scoutfs_key) {
		.sk_zone = zone,
		._sk_first = cpu_to_le64(first),
		._sk_second = cpu_to_le64(second),
	};
}

static int next_log_merge_item_key(struct super_block *sb, struct scoutfs_btree_root *root,
				   u8 zone, struct scoutfs_key *key, void *val, size_t val_len)
{
	SCOUTFS_BTREE_ITEM_REF(iref);
	int ret;

	ret = scoutfs_btree_next(sb, root, key, &iref);
	if (ret == 0) {
		if (iref.key->sk_zone != zone)
			ret = -ENOENT;
		else if (iref.val_len != val_len)
			ret = -EIO;
		else
			memcpy(val, iref.val, val_len);
		scoutfs_btree_put_iref(&iref);
	}

	return ret;
}

static int next_log_merge_item(struct super_block *sb,
			       struct scoutfs_btree_root *root,
			       u8 zone, u64 first, u64 second,
			       void *val, size_t val_len)
{
	struct scoutfs_key key;

	init_log_merge_key(&key, zone, first, second);
	return next_log_merge_item_key(sb, root, zone, &key, val, val_len);
}

static int do_finalize_ours(struct super_block *sb,
			    struct scoutfs_log_trees *lt,
			    struct commit_hold *hold)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_key key;
	char *err_str = NULL;
	u64 rid = le64_to_cpu(lt->rid);
	bool more;
	int ret;
	int err;

	mutex_lock(&server->srch_mutex);
	ret = scoutfs_srch_rotate_log(sb, &server->alloc, &server->wri,
				      &super->srch_root, &lt->srch_file, true);
	mutex_unlock(&server->srch_mutex);
	if (ret < 0) {
		scoutfs_err(sb, "error rotating srch log for rid %016llx: %d",
			    rid, ret);
		return ret;
        }

	do {
		more = false;

		/*
		 * All of these can return errors, perhaps indicating successful
		 * partial progress, after having modified the allocator trees.
		 * We always have to update the roots in the log item.
		 */
		mutex_lock(&server->alloc_mutex);
		ret = (err_str = "splice meta_freed to other_freed",
				scoutfs_alloc_splice_list(sb, &server->alloc,
					&server->wri, server->other_freed,
					&lt->meta_freed)) ?:
			(err_str = "splice meta_avail",
			 scoutfs_alloc_splice_list(sb, &server->alloc,
					&server->wri, server->other_freed,
					&lt->meta_avail)) ?:
			(err_str = "empty data_avail",
			 alloc_move_empty(sb, &super->data_alloc,
					  &lt->data_avail,
					  COMMIT_HOLD_ALLOC_BUDGET / 2)) ?:
			(err_str = "empty data_freed",
			 alloc_move_empty(sb, &super->data_alloc,
					  &lt->data_freed,
					  COMMIT_HOLD_ALLOC_BUDGET / 2));
		mutex_unlock(&server->alloc_mutex);

		/*
		 * only finalize, allowing merging, once the allocators are
		 * fully freed
		 */
		if (ret == 0) {
			/* the transaction is no longer open */
			le64_add_cpu(&lt->flags, SCOUTFS_LOG_TREES_FINALIZED);
			lt->finalize_seq = cpu_to_le64(scoutfs_server_next_seq(sb));
		}

		scoutfs_key_init_log_trees(&key, rid, le64_to_cpu(lt->nr));

		err = scoutfs_btree_update(sb, &server->alloc, &server->wri,
					   &super->logs_root, &key, lt,
					   sizeof(*lt));
		BUG_ON(err != 0); /* alloc, log, srch items out of sync */

		if (ret == -EINPROGRESS) {
			more = true;
			mutex_unlock(&server->logs_mutex);
			ret = server_apply_commit(sb, hold, 0);
			if (ret < 0)
				WARN_ON_ONCE(ret < 0);
			server_hold_commit(sb, hold);
			mutex_lock(&server->logs_mutex);
		} else if (ret == 0) {
			memset(&lt->item_root, 0, sizeof(lt->item_root));
			memset(&lt->bloom_ref, 0, sizeof(lt->bloom_ref));
			lt->inode_count_delta = 0;
			lt->max_item_seq = 0;
			lt->finalize_seq = 0;
			le64_add_cpu(&lt->nr, 1);
			lt->flags = 0;
		}
	} while (more);

	if (ret < 0) {
		scoutfs_err(sb,
			    "error %d finalizing log trees for rid %016llx: %s",
			    ret, rid, err_str);
	}

	return ret;
}

/*
 * Finalizing the log btrees for merging needs to be done carefully so
 * that items don't appear to go backwards in time.
 *
 * This can happen if an older version of an item happens to be present
 * in a log btree that is seeing activity without growing.  It will
 * never be merged, while another growing tree with an older version
 * gets finalized and merged.  The older version in the active log btree
 * will take precedent over the new item in the fs root.
 *
 * To avoid this without examining the overlapping of all item key
 * ranges in all log btrees we need to create a strict discontinuity in
 * item versions between all the finalized log btrees and all the active
 * log btrees.  Since active log btrees can get new item versions from
 * new locks, we can't naively finalize individual log btrees as they
 * grow.   It's almost guaranteed that some existing tree will have
 * older items than the finalizing tree, and will get new locks with
 * seqs greater.  Existing log btrees always naturally have seq ranges
 * that overlap with individually finalized log btrees.
 *
 * So we have the server perform a hard coordinated finalization of all
 * client log btrees once any of them is naturally finalized -- either
 * by growing or being cleaned up (via unmount or fencing).  Each
 * client's get_log_trees waits for everyone else to arrive and finalize
 * before any of them return the new next log btree.  This ensures that
 * the trans seq and all lock seqs of all the new log btrees will be
 * greater than all the items in all the previous and finalized log
 * btrees.
 *
 * This creates a bubble in pipeline.  We don't wait forever for an
 * active log btree to be finalized because we could be waiting for a
 * series of timeouts before a missing client is fenced and has its
 * abandoned log btree finalized.  If it takes too long each client has
 * a change to make forward progress before being asked to commit again.
 *
 * This can end up finalizing a new empty log btree if a new mount
 * happens to arrive at just the right time.  That's fine, merging will
 * ignore and tear down the empty input.
 */
#define FINALIZE_POLL_MIN_DELAY_MS	5U
#define FINALIZE_POLL_MAX_DELAY_MS	100U
#define FINALIZE_POLL_DELAY_GROWTH_PCT	150U
static int finalize_and_start_log_merge(struct super_block *sb, struct scoutfs_log_trees *lt,
					u64 rid, struct commit_hold *hold)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_log_merge_status stat;
	struct scoutfs_log_merge_range rng;
	struct scoutfs_mount_options opts;
	struct scoutfs_log_trees each_lt;
	unsigned int delay_ms;
	unsigned long timeo;
	bool saw_finalized;
	bool others_active;
	bool finalize_ours;
	bool ours_visible;
	struct scoutfs_key key;
	char *err_str = NULL;
	ktime_t start;
	int ret;
	int err;

	scoutfs_options_read(sb, &opts);
	timeo = jiffies + msecs_to_jiffies(opts.log_merge_wait_timeout_ms);
	delay_ms = FINALIZE_POLL_MIN_DELAY_MS;
	start = ktime_get_raw();

	for (;;) {
		/* nothing to do if there's already a merge in flight */
		ret = next_log_merge_item(sb, &super->log_merge,
					  SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0,
					  &stat, sizeof(stat));
		if (ret != -ENOENT) {
			if (ret < 0)
				err_str = "checking merge status item to finalize";
			break;
		}

		/* look for finalized and other active log btrees */
		saw_finalized = false;
		others_active = false;
		ours_visible = false;
		scoutfs_key_init_log_trees(&key, U64_MAX, U64_MAX);
		while ((ret = for_each_rid_last_lt(sb, &super->logs_root, &key, &each_lt)) > 0) {

			trace_scoutfs_server_finalize_items(sb, rid, le64_to_cpu(each_lt.rid),
							    le64_to_cpu(each_lt.nr),
							    le64_to_cpu(each_lt.flags),
							    le64_to_cpu(each_lt.get_trans_seq));

			if ((le64_to_cpu(each_lt.flags) & SCOUTFS_LOG_TREES_FINALIZED))
				saw_finalized = true;
			else if (le64_to_cpu(each_lt.rid) != rid)
				others_active = true;
			else if (each_lt.nr == lt->nr)
				ours_visible = true;
		}
		if (ret < 0) {
			err_str = "searching finalized flags in log_trees items";
			break;
		}

		/*
		 * We'll first finalize our log btree when it has enough
		 * leaf blocks to allow some degree of merging
		 * concurrency.  Smaller btrees are also finalized when
		 * meta was low so that deleted items are merged
		 * promptly and freed blocks can bring the client out of
		 * enospc.
		 */
		finalize_ours = (lt->item_root.height > 2) ||
				(le32_to_cpu(lt->meta_avail.flags) & SCOUTFS_ALLOC_FLAG_LOW);

		trace_scoutfs_server_finalize_decision(sb, rid, saw_finalized, others_active,
						       ours_visible, finalize_ours, delay_ms,
						       server->finalize_sent_seq);

		/* done if we're not finalizing and there's no finalized */
		if (!finalize_ours && !saw_finalized) {
			ret = 0;
			scoutfs_inc_counter(sb, log_merge_no_finalized);
			break;
		}

		/* send sync requests soon to give time to commit */
		scoutfs_key_init_log_trees(&key, U64_MAX, U64_MAX);
		while (others_active &&
		       (ret = for_each_rid_last_lt(sb, &super->logs_root, &key, &each_lt)) > 0) {

			if ((le64_to_cpu(each_lt.flags) & SCOUTFS_LOG_TREES_FINALIZED) ||
			    (le64_to_cpu(each_lt.rid) == rid) ||
			    (le64_to_cpu(each_lt.get_trans_seq) <= server->finalize_sent_seq))
				continue;

			ret = scoutfs_net_submit_request_node(sb, server->conn,
							      le64_to_cpu(each_lt.rid),
							      SCOUTFS_NET_CMD_SYNC_LOG_TREES,
							      NULL, 0, NULL, NULL, NULL);
			if (ret < 0) {
				/* fine if they're not here, they'll reconnect or be fenced */
				if (ret == -ENOTCONN)
					ret = 0;
				else
					err_str = "sending sync log tree request";
			}
		}
		if (ret < 0) {
			err_str = "sending sync log tree request";
			break;
		}

		server->finalize_sent_seq = scoutfs_server_seq(sb);

		/* Finalize ours if it's visible to others */
		if (ours_visible) {
			ret = do_finalize_ours(sb, lt, hold);
			if (ret < 0) {
				err_str = "finalizing ours";
				break;
			}
		}

		/* wait a bit for mounts to arrive */
		if (others_active) {
			mutex_unlock(&server->logs_mutex);
			ret = server_apply_commit(sb, hold, 0);
			if (ret < 0)
				err_str = "applying commit before waiting for finalized";

			msleep(delay_ms);
			delay_ms = min(delay_ms * FINALIZE_POLL_DELAY_GROWTH_PCT / 100,
				       FINALIZE_POLL_MAX_DELAY_MS);

			server_hold_commit(sb, hold);
			mutex_lock(&server->logs_mutex);

			/* done if we timed out */
			if (time_after(jiffies, timeo)) {
				scoutfs_inc_counter(sb, log_merge_wait_timeout);
				ret = 0;
				break;
			}

			/* rescan items now that we reacquired lock */
			continue;
		}

		/* we can add the merge item under the lock once everyone's finalized */

		/* add an initial full-range */
		scoutfs_key_set_zeros(&rng.start);
		scoutfs_key_set_ones(&rng.end);
		key = rng.start;
		key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
		ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key, &rng, sizeof(rng));
		if (ret < 0) {
			err_str = "inserting new merge range item";
			break;
		}

		/* and add the merge status item, deleting the range if insertion fails */
		scoutfs_key_set_zeros(&stat.next_range_key);
		stat.nr_requests = 0;
		stat.nr_complete = 0;
		stat.seq = cpu_to_le64(scoutfs_server_next_seq(sb));

		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0);
		ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   &stat, sizeof(stat));
		if (ret < 0) {
			err_str = "inserting new merge status item";
			key = rng.start;
			key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
			err = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
						   &super->log_merge, &key);
			BUG_ON(err); /* inconsistent */
		}

		/* we're done, caller can make forward progress */
		break;
	}

	if (ret < 0)
		scoutfs_err(sb, "error %d finalizing log trees for rid %016llx: %s",
			    ret, rid, err_str);

	return ret;
}

/*
 * The calling get_log_trees ran out of available blocks in its commit's
 * metadata allocator while moving extents from the log tree's
 * data_freed into the core data_avail.  This finishes moving the
 * extents in as many additional commits as it takes.   The logs mutex
 * is nested inside holding commits so we recheck the persistent item
 * each time we commit to make sure it's still what we think.   The
 * caller is still going to send the item to the client so we update the
 * caller's each time we make progress.  If we hit an error applying the
 * changes we make then we can't send the log_trees to the client.
 */
static int try_drain_data_freed(struct super_block *sb, struct scoutfs_log_trees *lt)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	const u64 rid = le64_to_cpu(lt->rid);
	const u64 nr = le64_to_cpu(lt->nr);
	struct scoutfs_log_trees drain;
	struct scoutfs_key key;
	COMMIT_HOLD(hold);
	bool apply = false;
	int ret = 0;
	int err;

	scoutfs_key_init_log_trees(&key, rid, nr);

	while (lt->data_freed.total_len != 0) {
		server_hold_commit(sb, &hold);
		mutex_lock(&server->logs_mutex);
		apply = true;

		ret = find_log_trees_item(sb, &super->logs_root, false, rid, U64_MAX, &drain);
		if (ret < 0) {
			ret = 0;
			break;
		}

		/* careful to only keep draining the caller's specific open trans */
		if (drain.nr != lt->nr || drain.get_trans_seq != lt->get_trans_seq ||
		    drain.commit_trans_seq != lt->commit_trans_seq || drain.flags != lt->flags) {
			ret = 0;
			break;
		}

		ret = scoutfs_btree_dirty(sb, &server->alloc, &server->wri,
					  &super->logs_root, &key);
		if (ret < 0) {
			ret = 0;
			break;
		}

		/* moving can modify and return errors, always update caller and item */
		mutex_lock(&server->alloc_mutex);
		ret = alloc_move_empty(sb, &super->data_alloc, &drain.data_freed,
				       COMMIT_HOLD_ALLOC_BUDGET / 2);
		mutex_unlock(&server->alloc_mutex);
		if (ret == -EINPROGRESS)
			ret = 0;

		*lt = drain;
		err = scoutfs_btree_force(sb, &server->alloc, &server->wri,
					  &super->logs_root, &key, &drain, sizeof(drain));
		BUG_ON(err < 0); /* dirtying must guarantee success */

		mutex_unlock(&server->logs_mutex);
		ret = server_apply_commit(sb, &hold, ret);
		apply = false;

		if (ret < 0)
			break;
	}

	if (apply) {
		mutex_unlock(&server->logs_mutex);
		server_apply_commit(sb, &hold, ret);
	}

	return ret;
}

/*
 * Give the client roots to all the trees that they'll use to build
 * their transaction.
 *
 * We make sure that their alloc trees have sufficient blocks to
 * allocate metadata and data for the transaction.  We merge their freed
 * trees back into the core allocators.  They're were committed with the
 * previous transaction so they're stable and can now be reused, even by
 * the server in this commit.
 *
 * If the committed log trees are large enough we finalize them and make
 * them available to log merging.
 *
 * As we prepare a new transaction we get its get_trans_seq to indicate
 * that it's open.  The client uses this to identify its open
 * transaction and we watch all the log trees to track the sequence
 * numbers of transactions that clients have open.  This limits the
 * transaction sequence numbers that can be returned in the index of
 * inodes by meta and data transaction numbers.  We communicate the
 * largest possible sequence number to clients via an rpc.  The
 * transactions are closed by setting the commit_trans_seq during commit
 * or as the mount is cleaned up.
 */
static int server_get_log_trees(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	u64 rid = scoutfs_net_client_rid(conn);
	DECLARE_SERVER_INFO(sb, server);
	__le64 exclusive[SCOUTFS_DATA_ALLOC_ZONE_LE64S];
	__le64 vacant[SCOUTFS_DATA_ALLOC_ZONE_LE64S];
	struct alloc_extent_cb_args cba;
	struct scoutfs_log_trees lt;
	struct scoutfs_key key;
	bool unlock_alloc = false;
	COMMIT_HOLD(hold);
	u64 data_zone_blocks;
	char *err_str = NULL;
	u64 nr;
	int ret;
	int err;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	server_hold_commit(sb, &hold);

	mutex_lock(&server->logs_mutex);

	/* use the last non-finalized root, or start a new one */
	ret = find_log_trees_item(sb, &super->logs_root, false, rid, U64_MAX, &lt);
	if (ret < 0 && ret != -ENOENT) {
		err_str = "finding last log trees";
		goto unlock;
	}
	if (ret == 0 && le64_to_cpu(lt.flags) & SCOUTFS_LOG_TREES_FINALIZED) {
		ret = -ENOENT;
		nr = le64_to_cpu(lt.nr) + 1;
	} else if (ret == -ENOENT) {
		nr = 1;
	}

	/* initialize a new root if we don't have a non-finalized one */
	if (ret == -ENOENT) {
		memset(&lt, 0, sizeof(lt));
		lt.rid = cpu_to_le64(rid);
		lt.nr = cpu_to_le64(nr);
	}

	/* the commit_trans_seq can never go past the open_trans_seq */
	if (le64_to_cpu(lt.get_trans_seq) < le64_to_cpu(lt.commit_trans_seq)) {
		err_str = "invalid open_trans_seq and commit_trans_seq";
		ret = -EINVAL;
		goto unlock;
	}

	/* transaction's already open, client resent get_ after server failover */
	if (le64_to_cpu(lt.get_trans_seq) > le64_to_cpu(lt.commit_trans_seq)) {
		ret = 0;
		goto unlock;
	}

	if (ret != -ENOENT) {
		/* need to sync lt with respect to changes in other structures */
		scoutfs_key_init_log_trees(&key, le64_to_cpu(lt.rid), le64_to_cpu(lt.nr));
		ret = scoutfs_btree_dirty(sb, &server->alloc, &server->wri,
					  &super->logs_root, &key);
		if (ret < 0) {
			err_str = "dirtying lt btree key";
			goto unlock;
		}
	}

	/* drops and re-acquires the mutex and commit if it has to wait */
	ret = finalize_and_start_log_merge(sb, &lt, rid, &hold);
	if (ret < 0)
		goto update;

	if (get_volopt_val(server, SCOUTFS_VOLOPT_DATA_ALLOC_ZONE_BLOCKS_NR, &data_zone_blocks)) {
		ret = get_data_alloc_zone_bits(sb, rid, exclusive, vacant, data_zone_blocks);
		if (ret < 0) {
			err_str = "getting alloc zone bits";
			goto update;
		}
	} else {
		data_zone_blocks = 0;
	}

	/*
	 * Reclaim the freed meta and data allocators and refill the
	 * avail allocators, setting low flags if they drop too low.
	 */
	mutex_lock(&server->alloc_mutex);
	unlock_alloc = true;

	ret = scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri, server->other_freed,
					&lt.meta_freed);
	if (ret < 0) {
		err_str = "splicing committed meta_freed";
		goto update;
	}

	ret = alloc_move_empty(sb, &super->data_alloc, &lt.data_freed, 100);
	if (ret == -EINPROGRESS)
		ret = 0;
	if (ret < 0) {
		err_str = "emptying committed data_freed";
		goto update;
	}

	ret = scoutfs_alloc_fill_list(sb, &server->alloc, &server->wri,
				      &lt.meta_avail, server->meta_avail,
				      SCOUTFS_SERVER_META_FILL_LO,
				      SCOUTFS_SERVER_META_FILL_TARGET);
	if (ret < 0) {
		err_str = "filling meta_avail";
		goto update;
	}

	if (le64_to_cpu(server->meta_avail->total_len) <= scoutfs_server_reserved_meta_blocks(sb))
		lt.meta_avail.flags |= cpu_to_le32(SCOUTFS_ALLOC_FLAG_LOW);
	else
		lt.meta_avail.flags &= ~cpu_to_le32(SCOUTFS_ALLOC_FLAG_LOW);

	ret = alloc_move_refill_zoned(sb, &lt.data_avail, &super->data_alloc,
				      SCOUTFS_SERVER_DATA_FILL_LO, SCOUTFS_SERVER_DATA_FILL_TARGET,
				      exclusive, vacant, data_zone_blocks);
	if (ret < 0) {
		err_str = "refilling data_avail";
		goto update;
	}

	if (le64_to_cpu(lt.data_avail.total_len) < SCOUTFS_SERVER_DATA_FILL_LO)
		lt.data_avail.flags |= cpu_to_le32(SCOUTFS_ALLOC_FLAG_LOW);
	else
		lt.data_avail.flags &= ~cpu_to_le32(SCOUTFS_ALLOC_FLAG_LOW);

	mutex_unlock(&server->alloc_mutex);
	unlock_alloc = false;

	/* record data alloc zone bits */
	zero_data_alloc_zone_bits(&lt);
	if (data_zone_blocks != 0) {
		cba.zones = lt.data_alloc_zones;
		cba.zone_blocks = data_zone_blocks;
		ret = scoutfs_alloc_extents_cb(sb, &lt.data_avail, set_extent_zone_bits, &cba);
		if (ret < 0) {
			zero_data_alloc_zone_bits(&lt);
			err_str = "setting data_avail zone bits";
			goto update;
		}

		lt.data_alloc_zone_blocks = cpu_to_le64(data_zone_blocks);
	}

	/* give the transaction a new seq (must have been ==) */
	lt.get_trans_seq = cpu_to_le64(scoutfs_server_next_seq(sb));

update:
	/* update client's log tree's item */
	scoutfs_key_init_log_trees(&key, le64_to_cpu(lt.rid), le64_to_cpu(lt.nr));
	err = scoutfs_btree_force(sb, &server->alloc, &server->wri,
				  &super->logs_root, &key, &lt, sizeof(lt));
	BUG_ON(err < 0); /* can duplicate extents.. move dst in super, still in in lt src */
	if (err < 0) {
		if (ret == 0) {
			ret = err;
			err_str = "updating log trees";
		}
	}

unlock:
	if (unlock_alloc)
		mutex_unlock(&server->alloc_mutex);
	mutex_unlock(&server->logs_mutex);

	ret = server_apply_commit(sb, &hold, ret);
out:
	if (ret < 0)
		scoutfs_err(sb, "error %d getting log trees for rid %016llx: %s",
			    ret, rid, err_str);

	/* try to drain excessive data_freed with additional commits, if needed */
	if (ret == 0)
		ret = try_drain_data_freed(sb, &lt);

	return scoutfs_net_response(sb, conn, cmd, id, ret, &lt, sizeof(lt));
}

/*
 * The client is sending the roots of all the btree blocks that they
 * wrote to their free space for their transaction.  Make it persistent
 * by referencing the roots from their log item in the logs root and
 * committing.
 */
static int server_commit_log_trees(struct super_block *sb,
				   struct scoutfs_net_connection *conn,
				   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	const u64 rid = scoutfs_net_client_rid(conn);
	DECLARE_SERVER_INFO(sb, server);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees *exist;
	struct scoutfs_log_trees lt;
	struct scoutfs_key key;
	COMMIT_HOLD(hold);
	char *err_str = NULL;
	bool committed = false;
	int ret;

	if (arg_len != sizeof(struct scoutfs_log_trees)) {
		ret = -EINVAL;
		goto out;
	}

	/* don't modify the caller's log_trees */
	memcpy(&lt, arg, sizeof(struct scoutfs_log_trees));

	if (le64_to_cpu(lt.rid) != rid) {
		err_str = "received rid is not connection rid";
		ret = -EIO;
		goto out;
	}

	server_hold_commit(sb, &hold);

	mutex_lock(&server->logs_mutex);

	/* find the client's existing item */
	scoutfs_key_init_log_trees(&key, le64_to_cpu(lt.rid),
				   le64_to_cpu(lt.nr));
	ret = scoutfs_btree_lookup(sb, &super->logs_root, &key, &iref);
	if (ret < 0)
		err_str = "finding log trees item";
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees)) {
			exist = iref.val;
			if (exist->get_trans_seq != lt.get_trans_seq) {
				ret = -EIO;
				err_str = "invalid log trees item get_trans_seq";
			} else {
				if (exist->commit_trans_seq == lt.get_trans_seq)
					committed = true;
			}
		} else {
			ret = -EIO;
			err_str = "invalid log trees item size";
		}
		scoutfs_btree_put_iref(&iref);
	}
	if (ret < 0 || committed)
		goto unlock;

	/* make sure _update succeeds before we modify srch items */
	ret = scoutfs_btree_dirty(sb, &server->alloc, &server->wri, &super->logs_root, &key);
	if (ret < 0) {
		err_str = "dirtying lt item";
		goto unlock;
	}

	/* try to rotate the srch log when big enough */
	mutex_lock(&server->srch_mutex);
	ret = scoutfs_srch_rotate_log(sb, &server->alloc, &server->wri,
				      &super->srch_root, &lt.srch_file, false);
	mutex_unlock(&server->srch_mutex);
	if (ret < 0) {
		err_str = "rotating srch log file";
		goto unlock;
	}

	lt.commit_trans_seq = lt.get_trans_seq;

	ret = scoutfs_btree_update(sb, &server->alloc, &server->wri,
				   &super->logs_root, &key, &lt, sizeof(lt));
	BUG_ON(ret < 0); /* dirtying should have guaranteed success */
	if (ret < 0)
		err_str = "updating log trees item";

unlock:
	mutex_unlock(&server->logs_mutex);

	ret = server_apply_commit(sb, &hold, ret);
	if (ret < 0)
		scoutfs_err(sb, "server error %d committing client logs for rid %016llx, nr %llu: %s",
			    ret, rid, le64_to_cpu(lt.nr), err_str);
out:
	WARN_ON_ONCE(ret < 0);
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

/*
 * Give the client the most recent version of the fs btrees that are
 * visible in persistent storage.  We don't want to accidentally give
 * them our in-memory dirty version.  This can be racing with commits.
 */
static int server_get_roots(struct super_block *sb,
			    struct scoutfs_net_connection *conn,
			    u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_net_roots roots;
	int ret;

	if (arg_len != 0) {
		memset(&roots, 0, sizeof(roots));
		ret = -EINVAL;
	}  else {
		get_stable(sb, NULL, &roots);
		ret = 0;
	}

	return scoutfs_net_response(sb, conn, cmd, id, 0,
				    &roots, sizeof(roots));
}

/*
 * A client is being evicted so we want to reclaim resources from their
 * open log tree item.  The item tree and bloom ref stay around to be
 * read and we finalize the tree so that it will be merged.  We reclaim
 * all the allocator items.
 *
 * The caller holds the commit rwsem which means we have to do our work
 * in one commit.  The alocator btrees can be very large and very
 * fragmented.  We return -EINPROGRESS if we couldn't fully reclaim the
 * allocators in one commit.   The caller should apply the current
 * commit and call again in a new commit.
 *
 * By the time we're evicting a client they've either synced their data
 * or have been forcefully removed.  The free blocks in the allocator
 * roots are stable and can be merged back into allocator items for use
 * without risking overwriting stable data.
 *
 * We can return an error without fully reclaiming all the log item's
 * referenced data.
 */
static int reclaim_open_log_tree(struct super_block *sb, u64 rid)
{
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	DECLARE_SERVER_INFO(sb, server);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_log_trees lt;
	struct scoutfs_key key;
	char *err_str = NULL;
	int ret;
	int err;

	mutex_lock(&server->logs_mutex);

	/* find the client's last open log_tree */
	scoutfs_key_init_log_trees(&key, rid, U64_MAX);
	ret = scoutfs_btree_prev(sb, &super->logs_root, &key, &iref);
	if (ret < 0)
		err_str = "log trees btree prev";
	if (ret == 0) {
		if (iref.val_len == sizeof(struct scoutfs_log_trees)) {
			key = *iref.key;
			memcpy(&lt, iref.val, iref.val_len);
			if ((le64_to_cpu(key.sklt_rid) != rid) ||
			    (le64_to_cpu(lt.flags) &
			     SCOUTFS_LOG_TREES_FINALIZED))
				ret = -ENOENT;
		} else {
			err_str = "invalid log trees item length";
			ret = -EIO;
		}
		scoutfs_btree_put_iref(&iref);
	}
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	/* for srch log file rotation if it's populated */
	mutex_lock(&server->srch_mutex);
	ret = scoutfs_srch_rotate_log(sb, &server->alloc, &server->wri,
				      &super->srch_root, &lt.srch_file, true);
	mutex_unlock(&server->srch_mutex);
	if (ret < 0) {
		scoutfs_err(sb, "error rotating srch log for rid %016llx: %d", rid, ret);
		err_str = "rotating srch file";
		goto out;
	}

	/*
	 * All of these can return errors, perhaps indicating successful
	 * partial progress, after having modified the allocator trees.
	 * We always have to update the roots in the log item.
	 */
	mutex_lock(&server->alloc_mutex);
	ret = (err_str = "splice meta_freed to other_freed",
	       scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri, server->other_freed,
					 &lt.meta_freed)) ?:
	      (err_str = "splice meta_avail", 
	       scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri, server->other_freed,
					 &lt.meta_avail)) ?:
	      (err_str = "empty data_avail",
	       alloc_move_empty(sb, &super->data_alloc, &lt.data_avail, 100)) ?:
	      (err_str = "empty data_freed",
	       alloc_move_empty(sb, &super->data_alloc, &lt.data_freed, 100));
	mutex_unlock(&server->alloc_mutex);

	/* only finalize, allowing merging, once the allocators are fully freed */
	if (ret == 0) {
		/* the transaction is no longer open */
		lt.commit_trans_seq = lt.get_trans_seq;

		/* the mount is no longer writing to the zones */
		zero_data_alloc_zone_bits(&lt);
		le64_add_cpu(&lt.flags, SCOUTFS_LOG_TREES_FINALIZED);
		lt.finalize_seq = cpu_to_le64(scoutfs_server_next_seq(sb));
	}

	err = scoutfs_btree_update(sb, &server->alloc, &server->wri,
				  &super->logs_root, &key, &lt, sizeof(lt));
	BUG_ON(err != 0); /* alloc, log, srch items out of sync */

out:
	mutex_unlock(&server->logs_mutex);

	if (ret == 0)
		scoutfs_inc_counter(sb, reclaimed_open_logs);

	if (ret < 0 && ret != -EINPROGRESS)
		scoutfs_err(sb, "server error %d reclaiming log trees for rid %016llx: %s",
			    ret, rid, err_str);

	return ret;
}

/*
 * Give the caller the last seq before outstanding client commits.  All
 * seqs up to and including this are stable, new client transactions can
 * only have greater seqs.
 *
 * For each rid, only its greatest log trees nr can be an open commit.
 * We look at the last log_trees item for each client rid and record its
 * trans seq if it hasn't been committed.
 */
static int get_stable_trans_seq(struct super_block *sb, u64 *last_seq_ret)
{
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_log_trees lt;
	struct scoutfs_key key;
	u64 last_seq = 0;
	int ret;

	last_seq = scoutfs_server_seq(sb) - 1;

	mutex_lock(&server->logs_mutex);

	scoutfs_key_init_log_trees(&key, U64_MAX, U64_MAX);
	while ((ret = for_each_rid_last_lt(sb, &super->logs_root, &key, &lt)) > 0) {
		if ((le64_to_cpu(lt.get_trans_seq) > le64_to_cpu(lt.commit_trans_seq)) &&
		     le64_to_cpu(lt.get_trans_seq) <= last_seq) {
			last_seq = le64_to_cpu(lt.get_trans_seq) - 1;
		}
	}

	mutex_unlock(&server->logs_mutex);

	*last_seq_ret = last_seq;
	return ret;
}

/*
 * Give the calling client the last valid trans_seq that it can return
 * in results from the indices of trans seqs to inodes.  These indices
 * promise to only advance so we can't return results past those that
 * are still outstanding and not yet visible in the indices.  If there
 * are no outstanding transactions (what?  how?) we give them the max
 * possible sequence.
 */
static int server_get_last_seq(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	u64 rid = scoutfs_net_client_rid(conn);
	u64 last_seq = 0;
	__le64 leseq;
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = get_stable_trans_seq(sb, &last_seq);
out:
	trace_scoutfs_trans_seq_last(sb, rid, last_seq);
	leseq = cpu_to_le64(last_seq);
	return scoutfs_net_response(sb, conn, cmd, id, ret,
				    &leseq, sizeof(leseq));
}

static int server_lock(struct super_block *sb,
		       struct scoutfs_net_connection *conn,
		       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	u64 rid = scoutfs_net_client_rid(conn);

	if (arg_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	return scoutfs_lock_server_request(sb, rid, id, arg);
}

static int lock_response(struct super_block *sb,
			 struct scoutfs_net_connection *conn,
			 void *resp, unsigned int resp_len,
			 int error, void *data)
{
	u64 rid = scoutfs_net_client_rid(conn);

	if (resp_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	return scoutfs_lock_server_response(sb, rid, resp);
}

int scoutfs_server_lock_request(struct super_block *sb, u64 rid,
				struct scoutfs_net_lock *nl)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_submit_request_node(sb, server->conn, rid,
					      SCOUTFS_NET_CMD_LOCK,
					      nl, sizeof(*nl),
					      lock_response, NULL, NULL);
}

int scoutfs_server_lock_response(struct super_block *sb, u64 rid, u64 id,
				 struct scoutfs_net_lock *nl)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_response_node(sb, server->conn, rid,
					 SCOUTFS_NET_CMD_LOCK, id, 0,
					 nl, sizeof(*nl));
}

static bool invalid_recover(struct scoutfs_net_lock_recover *nlr,
			    unsigned long bytes)
{
	return ((bytes < sizeof(*nlr)) ||
	        (bytes != offsetof(struct scoutfs_net_lock_recover,
			       locks[le16_to_cpu(nlr->nr)])));
}

static int lock_recover_response(struct super_block *sb,
				 struct scoutfs_net_connection *conn,
				 void *resp, unsigned int resp_len,
				 int error, void *data)
{
	u64 rid = scoutfs_net_client_rid(conn);

	if (invalid_recover(resp, resp_len))
		return -EINVAL;

	return scoutfs_lock_server_recover_response(sb, rid, resp);
}

int scoutfs_server_lock_recover_request(struct super_block *sb, u64 rid,
					struct scoutfs_key *key)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;

	return scoutfs_net_submit_request_node(sb, server->conn, rid,
					      SCOUTFS_NET_CMD_LOCK_RECOVER,
					      key, sizeof(*key),
					      lock_recover_response,
					      NULL, NULL);
}

static int server_srch_get_compact(struct super_block *sb,
				   struct scoutfs_net_connection *conn,
				   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	u64 rid = scoutfs_net_client_rid(conn);
	struct scoutfs_srch_compact *sc = NULL;
	COMMIT_HOLD(hold);
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	sc = kzalloc(sizeof(struct scoutfs_srch_compact), GFP_NOFS);
	if (sc == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	server_hold_commit(sb, &hold);

	mutex_lock(&server->srch_mutex);
	ret = scoutfs_srch_get_compact(sb, &server->alloc, &server->wri,
				       &super->srch_root, rid, sc);
	mutex_unlock(&server->srch_mutex);
	if (ret < 0 || (ret == 0 && sc->nr == 0))
		goto apply;

	mutex_lock(&server->alloc_mutex);
	ret = scoutfs_alloc_fill_list(sb, &server->alloc, &server->wri,
				      &sc->meta_avail, server->meta_avail,
				      SCOUTFS_SERVER_META_FILL_LO,
				      SCOUTFS_SERVER_META_FILL_TARGET) ?:
	      scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri,
					server->other_freed, &sc->meta_freed);
	mutex_unlock(&server->alloc_mutex);
	if (ret < 0)
		goto apply;

	mutex_lock(&server->srch_mutex);
	ret = scoutfs_srch_update_compact(sb, &server->alloc, &server->wri,
					  &super->srch_root, rid, sc);
	mutex_unlock(&server->srch_mutex);

apply:
	ret = server_apply_commit(sb, &hold, ret);
	WARN_ON_ONCE(ret < 0 && ret != -ENOENT); /* XXX leaked busy item */
out:
	ret = scoutfs_net_response(sb, conn, cmd, id, ret,
				   sc, sizeof(struct scoutfs_srch_compact));
	kfree(sc);
	return ret;
}

/*
 * Commit the client's compaction.  Their freed allocator contains the
 * source srch files blocks that are currently in use which can't be
 * available for allocation until after the commit.  We move them into
 * freed so they won't satisfy allocations.
 */
static int server_srch_commit_compact(struct super_block *sb,
				      struct scoutfs_net_connection *conn,
				      u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	u64 rid = scoutfs_net_client_rid(conn);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_srch_compact *sc;
	struct scoutfs_alloc_list_head av;
	struct scoutfs_alloc_list_head fr;
	COMMIT_HOLD(hold);
	int ret;

	if (arg_len != sizeof(struct scoutfs_srch_compact)) {
		ret = -EINVAL;
		goto out;
	}
	sc = arg;

	server_hold_commit(sb, &hold);

	mutex_lock(&server->srch_mutex);
	ret = scoutfs_srch_commit_compact(sb, &server->alloc, &server->wri,
					  &super->srch_root, rid, sc,
					  &av, &fr);
	mutex_unlock(&server->srch_mutex);
	if (ret < 0)
		goto apply;

	/* reclaim allocators if they were set by _srch_commit_ */
	mutex_lock(&server->alloc_mutex);
	ret = scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri,
					server->other_freed, &av) ?:
	      scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri,
					server->other_freed, &fr);
	mutex_unlock(&server->alloc_mutex);
	WARN_ON(ret < 0); /* XXX leaks allocators */
apply:
	ret = server_apply_commit(sb, &hold, ret);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

/* Requests drain once we get this many completions to splice */
#define LOG_MERGE_SPLICE_BATCH 8

/*
 * Splice the completed subtrees from the clients back into the fs log
 * tree as parents.  Once they're spliced in, try and rebalance a path
 * through them in case they need to be split or joined before the rest
 * of their range can be processed.
 *
 * It's only safe to splice in merged parents when all the requests have
 * drained and no requests are relying on stable key ranges of parents
 * in the fs root.
 *
 * It doesn't matter that the fs tree produced by these subtree splices
 * itself contains inconsistent items because the subtrees can contain
 * fragments of transactions.  The read-only finalized log btrees that
 * are the source of the spliced items are still preferred by readers.
 * It's only once all the finalized items have been merged, and all
 * transactions are consistent, that we remove the finalized log trees
 * and the fs tree items are used.
 *
 * As we splice in the subtrees we're implicitly allocating all the
 * blocks referenced by the new subtree, and freeing all the blocks
 * referenced by the old subtree that's overwritten.  These allocs and
 * frees were performed by the client as it did cow updates and were
 * stored in the allocators that were sent with the completion.  We
 * merge in those allocators as we splice in the subtree.
 *
 * We can add back any remaining ranges for any partial completions and
 * reset the next range key if there's still work to do.  If the
 * operation is complete then we tear down the input log_trees items and
 * delete the status.
 *
 * Processing all the completions can take more than one transaction.
 * We return -EINPROGRESS if we have to commit a transaction and the
 * caller will apply the commit and immediate call back in so we can
 * perform another commit.  We need to be very careful to leave the
 * status in a state where requests won't be issued at the wrong time
 * (by forcing nr_completions to a batch while we delete them).
 */
static int splice_log_merge_completions(struct super_block *sb,
					struct scoutfs_log_merge_status *stat,
					bool no_ranges)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_log_merge_complete comp;
	struct scoutfs_log_merge_freeing fr;
	struct scoutfs_log_merge_range rng;
	struct scoutfs_log_trees lt = {{{0,}}};
	SCOUTFS_BTREE_ITEM_REF(iref);
	bool upd_stat = true;
	int einprogress = 0;
	struct scoutfs_key key;
	char *err_str = NULL;
	u32 alloc_low;
	u32 tmp;
	u64 seq;
	int ret;
	int err;

	/* musn't rebalance fs tree parents while reqs rely on their key bounds */
	if (WARN_ON_ONCE(le64_to_cpu(stat->nr_requests) > 0))
		return -EIO;

	/*
	 * Be overly conservative about how low the allocator can get
	 * before we commit.  This gives us a lot of work to do in a
	 * commit while also allowing a pretty big smallest allocator to
	 * work with the theoretically unbounded alloc list splicing.
	 */
	scoutfs_alloc_meta_remaining(&server->alloc, &alloc_low, &tmp);
	alloc_low = min(alloc_low, tmp) / 4;

	/*
	 * Splice in all the completed subtrees at the initial parent
	 * blocks in the main fs_tree before rebalancing any of them.
	 */
	for (seq = 0; ; seq++) {

		ret = next_log_merge_item(sb, &super->log_merge,
					  SCOUTFS_LOG_MERGE_COMPLETE_ZONE, seq,
					  0, &comp, sizeof(comp));
		if (ret < 0) {
			if (ret == -ENOENT) {
				ret = 0;
				break;
			} else {
				err_str = "finding next completion for splice";
			}
			goto out;
		}

		seq = le64_to_cpu(comp.seq);

		/*
		 * Use having cleared the lists as an indication that
		 * we've already set the parents and don't need to dirty
		 * the btree blocks to do it all over again.  This is
		 * safe because there is always an fs block that the
		 * merge dirties and frees into the meta_freed list.
		 */
		if (comp.meta_avail.ref.blkno == 0 && comp.meta_freed.ref.blkno == 0)
			continue;

		if (scoutfs_alloc_meta_low(sb, &server->alloc, alloc_low)) {
			einprogress = -EINPROGRESS;
			ret = 0;
			goto out;
		}

		ret = scoutfs_btree_set_parent(sb, &server->alloc, &server->wri,
					       &super->fs_root, &comp.start,
					       &comp.root);
		if (ret < 0) {
			err_str = "btree set parent";
			goto out;
		}

		mutex_lock(&server->alloc_mutex);
		ret = (err_str = "splice meta_avail",
		       scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri,
						 server->other_freed, &comp.meta_avail)) ?:
		      (err_str = "splice other_freed",
		       scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri,
						 server->other_freed, &comp.meta_freed));
		mutex_unlock(&server->alloc_mutex);
		if (ret < 0)
			goto out;

		/* clear allocators */
		memset(&comp.meta_avail, 0, sizeof(comp.meta_avail));
		memset(&comp.meta_freed, 0, sizeof(comp.meta_freed));

		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_COMPLETE_ZONE,
				   seq, 0);
		ret = scoutfs_btree_update(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   &comp, sizeof(comp));
		if (ret < 0) {
			err_str = "updating completion";
			goto out;
		}
	}

	/*
	 * Once we start rebalancing we force the number of completions
	 * to a batch so that requests won't be issued.  Once we're done
	 * we clear the completion count and requests can flow again.
	 */
	if (le64_to_cpu(stat->nr_complete) < LOG_MERGE_SPLICE_BATCH)
		stat->nr_complete = cpu_to_le64(LOG_MERGE_SPLICE_BATCH);

	/*
	 * Now with all the parent blocks spliced in, rebalance items
	 * amongst parents that needed to split/join and delete the
	 * completion items, possibly returning ranges to process.
	 */
	for (seq = 0; ; seq++) {
		ret = next_log_merge_item(sb, &super->log_merge,
					  SCOUTFS_LOG_MERGE_COMPLETE_ZONE, seq,
					  0, &comp, sizeof(comp));
		if (ret < 0) {
			if (ret == -ENOENT) {
				ret = 0;
				break;
			} else {
				err_str = "finding next completion for rebalance";
			}
			goto out;
		}

		seq = le64_to_cpu(comp.seq);

		if (scoutfs_alloc_meta_low(sb, &server->alloc, alloc_low)) {
			einprogress = -EINPROGRESS;
			ret = 0;
			goto out;
		}

		/* balance when there was a remaining key range */
		if (le64_to_cpu(comp.flags) & SCOUTFS_LOG_MERGE_COMP_REMAIN) {
			ret = scoutfs_btree_rebalance(sb, &server->alloc,
						      &server->wri,
						      &super->fs_root,
						      &comp.start);
			if (ret < 0) {
				err_str = "btree rebalance";
				goto out;
			}

			rng.start = comp.remain;
			rng.end = comp.end;

			key = rng.start;
			key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
			ret = scoutfs_btree_insert(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key,
						   &rng, sizeof(rng));
			if (ret < 0) {
				err_str = "insert remaining range";
				goto out;
			}
			no_ranges = false;
		}

		/* delete the completion item */
		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_COMPLETE_ZONE,
				   seq, 0);
		ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
					   &super->log_merge,
					   &key);
		if (ret < 0) {
			err_str = "delete completion item";
			goto out;
		}
	}

	/* update counts and done if there's still ranges to process */
	if (!no_ranges) {
		scoutfs_key_set_zeros(&stat->next_range_key);
		stat->nr_complete = 0;
		ret = 0;
		goto out;
	}

	/* no more ranges, free blooms and add freeing items for free work */
	lt.rid = 0;
	lt.nr = 0;
	for (;;) {
		scoutfs_key_init_log_trees(&key, le64_to_cpu(lt.rid),
					   le64_to_cpu(lt.nr) + 1);
		ret = scoutfs_btree_next(sb, &super->logs_root, &key, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(lt)) {
				key = *iref.key;
				memcpy(&lt, iref.val, sizeof(lt));
			} else {
				err_str = "invalid next log trees val len";
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT) {
				ret = 0;
				break;
			} else {
				err_str = "finding next log trees item";
			}
			goto out;
		}

		/* only free the inputs to the log merge that just finished */
		if (!((le64_to_cpu(lt.flags) & SCOUTFS_LOG_TREES_FINALIZED) &&
		      (le64_to_cpu(lt.finalize_seq) < le64_to_cpu(stat->seq))))
			continue;

		if (scoutfs_alloc_meta_low(sb, &server->alloc, alloc_low)) {
			einprogress = -EINPROGRESS;
			ret = 0;
			goto out;
		}

		fr.root = lt.item_root;
		scoutfs_key_set_zeros(&fr.key);
		fr.seq = cpu_to_le64(scoutfs_server_next_seq(sb));
		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_FREEING_ZONE,
				   le64_to_cpu(fr.seq), 0);
		ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   &fr, sizeof(fr));
		if (ret < 0) {
			err_str = "inserting freeing";
			goto out;
		}

		if (lt.bloom_ref.blkno) {
			ret = scoutfs_free_meta(sb, &server->alloc,
						&server->wri,
					le64_to_cpu(lt.bloom_ref.blkno));
			if (ret < 0) {
				err_str = "freeing bloom block";
				goto out;
			}
		}

		scoutfs_key_init_log_trees(&key, le64_to_cpu(lt.rid),
					   le64_to_cpu(lt.nr));
		ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
					   &super->logs_root, &key);
		if (ret < 0) {
			err_str = "deleting log trees item";
			goto out;
		}

		le64_add_cpu(&super->inode_count, le64_to_cpu(lt.inode_count_delta));
	}

	/* everything's done, remove the merge operation */
	upd_stat = false;
	init_log_merge_key(&key, SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0);
	ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
				   &super->log_merge, &key);
	if (ret == 0)
		queue_work(server->wq, &server->log_merge_free_work);
	else
		err_str = "deleting merge status item";
out:
	if (upd_stat) {
		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0);
		err = scoutfs_btree_update(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   stat, sizeof(struct scoutfs_log_merge_status));
		if (err && !ret) {
			err_str = "updating merge status item";
			ret = err;
		}
	}

	if (ret < 0)
		scoutfs_err(sb, "server error %d splicing log merge completion: %s", ret, err_str);

	BUG_ON(ret); /* inconsistent */

	return ret ?: einprogress;
}

/*
 * Search amongst the finalized log roots within the caller's merge seq looking
 * for the earliest item within the caller's range.  The caller has taken
 * care of locking.
 */
static int next_least_log_item(struct super_block *sb,
			       struct scoutfs_btree_root *logs_root,
			       u64 seq, struct scoutfs_key *start,
			       struct scoutfs_key *end,
			       struct scoutfs_key *next_ret)
{
	struct scoutfs_btree_root item_root;
	struct scoutfs_log_trees *lt;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	scoutfs_key_set_ones(next_ret);

	for (scoutfs_key_init_log_trees(&key, 0, 0); ; scoutfs_key_inc(&key)) {

		/* find the next finalized log root within the merge */
		ret = scoutfs_btree_next(sb, logs_root, &key, &iref);
		if (ret == 0) {
			if (iref.val_len == sizeof(*lt)) {
				key = *iref.key;
				lt = iref.val;
				if ((le64_to_cpu(lt->flags) & SCOUTFS_LOG_TREES_FINALIZED) &&
				    (le64_to_cpu(lt->finalize_seq) < seq))
					item_root = lt->item_root;
				else
					item_root.ref.blkno = 0;
			} else {
				ret = -EIO;
			}
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			goto out;
		}
		if (item_root.ref.blkno == 0)
			continue;

		/* see if populated roots have item keys less than than next */
		ret = scoutfs_btree_next(sb, &item_root, start, &iref);
		if (ret == 0) {
			if (scoutfs_key_compare(iref.key, end) <= 0 &&
			    scoutfs_key_compare(iref.key, next_ret) < 0)
				*next_ret = *iref.key;
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			else
				goto out;
		}
	}

out:
	if (ret == 0 && scoutfs_key_is_ones(next_ret))
		ret = -ENOENT;

	return ret;
}

/*
 * Once a merge is fully completed all of the finalized input log btrees
 * are redundant and can be freed.
 *
 * As merging finishes and the status item is deleted, we also move all
 * the finalized roots from log_trees items over into freeing items.
 * This work is then kicked off which iterates over all the freeing
 * items calling into the btree to free all its referenced blocks, with
 * the key tracking partial progress.
 *
 * The freeing work is reasonably light.  We only read the btree blocks
 * and add freed blocks to merge back into the core allocators.  The
 * server can handle this load and we avoid the io overhead and
 * complexity of farming it out to clients.
 */
static void server_log_merge_free_work(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  log_merge_free_work);
	struct super_block *sb = server->sb;
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_log_merge_freeing fr;
	struct scoutfs_key key;
	COMMIT_HOLD(hold);
	char *err_str = NULL;
	bool commit = false;
	int ret = 0;

	while (!server_is_stopping(server)) {

		if (!commit) {
			server_hold_commit(sb, &hold);
			mutex_lock(&server->logs_mutex);
			commit = true;
		}

		ret = next_log_merge_item(sb, &super->log_merge,
					  SCOUTFS_LOG_MERGE_FREEING_ZONE,
					  0, 0, &fr, sizeof(fr));
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			else
				err_str = "finding next freeing item";
			break;
		}

		/* Dirty the btree before freeing so that we can pin it
		 * so that later touches will succeed.
		 */
		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_FREEING_ZONE,
				   le64_to_cpu(fr.seq), 0);
		ret = scoutfs_btree_dirty(sb, &server->alloc,
						&server->wri, &super->log_merge,
						&key);
		if (ret < 0) {
			err_str = "dirtying log btree";
			break;
		}

		ret = scoutfs_btree_free_blocks(sb, &server->alloc,
						&server->wri, &fr.key,
						&fr.root, COMMIT_HOLD_ALLOC_BUDGET / 8);
		if (ret < 0) {
			err_str = "freeing log btree";
			break;
		}

		/* freed blocks are in allocator, we *have* to update key */
		if (scoutfs_key_is_ones(&fr.key))
			ret = scoutfs_btree_delete(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key);
		else
			ret = scoutfs_btree_update(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key,
						   &fr, sizeof(fr));
		/* freed blocks are in allocator, we *have* to update fr */
		BUG_ON(ret < 0);

		if (server_hold_alloc_used_since(sb, &hold) >= (COMMIT_HOLD_ALLOC_BUDGET * 3) / 4) {
			mutex_unlock(&server->logs_mutex);
			ret = server_apply_commit(sb, &hold, ret);
			commit = false;
			if (ret < 0) {
				err_str = "looping commit del/upd freeing item";
				break;
			}
		}
	}

	if (commit) {
		mutex_unlock(&server->logs_mutex);
		ret = server_apply_commit(sb, &hold, ret);
		if (ret < 0)
			err_str = "final commit del/upd freeing item";
	}

	if (ret < 0) {
		scoutfs_err(sb, "server error %d freeing merged btree blocks: %s", ret, err_str);
		stop_server(server);
	}

	/* not re-arming, regularly queued by the server during merging */
}

/*
 * Clients regularly ask if there is log merge work to do.  We process
 * completions inline before responding so that we don't create large
 * delays between completion processing and the next request.  We don't
 * mind if the client get_log_merge request sees high latency, the
 * blocked caller has nothing else to do.
 *
 * This will return ENOENT to the client if there is no work to do.
 */
static int server_get_log_merge(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	u64 rid = scoutfs_net_client_rid(conn);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_log_merge_status stat;
	struct scoutfs_log_merge_range rng;
	struct scoutfs_log_merge_range remain;
	struct scoutfs_log_merge_request req;
	struct scoutfs_key par_start;
	struct scoutfs_key par_end;
	struct scoutfs_key next_key;
	struct scoutfs_key key;
	COMMIT_HOLD(hold);
	char *err_str = NULL;
	bool ins_rng;
	bool del_remain;
	bool del_req;
	bool upd_stat;
	bool no_ranges;
	bool no_next;
	int ret;
	int err;

	if (arg_len != 0)
		return -EINVAL;

	server_hold_commit(sb, &hold);
	mutex_lock(&server->logs_mutex);

restart:
	memset(&req, 0, sizeof(req));
	ins_rng = false;
	del_remain = false;
	del_req = false;
	upd_stat = false;

	/* get the status item */
	ret = next_log_merge_item(sb, &super->log_merge,
				  SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0,
				  &stat, sizeof(stat));
	if (ret < 0) {
		if (ret != -ENOENT)
			err_str = "finding merge status item";
		goto out;
	}

	trace_scoutfs_get_log_merge_status(sb, rid, &stat.next_range_key,
					   le64_to_cpu(stat.nr_requests),
					   le64_to_cpu(stat.nr_complete),
					   le64_to_cpu(stat.seq));

	/* find the next range, always checking for splicing */
	for (;;) {
		key = stat.next_range_key;
		key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
		ret = next_log_merge_item_key(sb, &super->log_merge, SCOUTFS_LOG_MERGE_RANGE_ZONE,
					      &key, &rng, sizeof(rng));
		if (ret < 0 && ret != -ENOENT) {
			err_str = "finding merge range item";
			goto out;
		}

		/* splice if we have a batch or ran out of ranges */
		no_next = ret == -ENOENT;
		no_ranges = scoutfs_key_is_zeros(&stat.next_range_key) && ret == -ENOENT;
		if (le64_to_cpu(stat.nr_requests) == 0 &&
		    (no_next || le64_to_cpu(stat.nr_complete) >= LOG_MERGE_SPLICE_BATCH)) {
			ret = splice_log_merge_completions(sb, &stat, no_ranges);
			if (ret == -EINPROGRESS) {
				mutex_unlock(&server->logs_mutex);
				ret = server_apply_commit(sb, &hold, 0);
				if (ret < 0)
					goto respond;
				server_hold_commit(sb, &hold);
				mutex_lock(&server->logs_mutex);
			} else if (ret < 0) {
				goto out;
			}
			/* splicing resets key and adds ranges, could finish status */
			goto restart;
		}

		/* no ranges from next for requests, future attempts will create or splice */
		if (no_next) {
			ret = -ENOENT;
			goto out;
		}

		/* see if we should back off after splicing might have deleted completions */
		if ((le64_to_cpu(stat.nr_requests) +
		     le64_to_cpu(stat.nr_complete)) >= LOG_MERGE_SPLICE_BATCH) {
			ret = -ENOENT;
			goto out;
		}

		/* find the next logged item in the next range */
		ret = next_least_log_item(sb, &super->logs_root, le64_to_cpu(stat.seq),
					  &rng.start, &rng.end, &next_key);
		if (ret == 0) {
			break;
		} else if (ret == -ENOENT) {
			/* drop the range if it contained no logged items */
			key = rng.start;
			key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
			ret = scoutfs_btree_delete(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key);
			if (ret < 0) {
				err_str = "deleting unused range item";
				goto out;
			}
		} else {
			err_str = "finding next logged item";
			goto out;
		}
	}

	/* start to build the request that's saved and sent to the client */
	req.logs_root = super->logs_root;
	req.input_seq = stat.seq;
	req.rid = cpu_to_le64(rid);
	req.seq = cpu_to_le64(scoutfs_server_next_seq(sb));
	req.flags = 0;
	if (super->fs_root.height > 2)
		req.flags |= cpu_to_le64(SCOUTFS_LOG_MERGE_REQUEST_SUBTREE);

	/* find the fs_root parent block and its key range */
	ret = scoutfs_btree_get_parent(sb, &super->fs_root, &next_key, &req.root);
	if (ret < 0) {
		err_str = "getting fs root parent";
		goto out;
	}

	ret = scoutfs_btree_parent_range(sb, &super->fs_root, &next_key, &par_start, &par_end);
	if (ret < 0) {
		err_str = "getting fs root parent range";
		goto out;
	}

	/* start from next item, don't exceed parent key range */
	req.start = next_key;
	req.end = rng.end;
	if (scoutfs_key_compare(&par_end, &req.end) < 0)
		req.end = par_end;

	/* delete the old range */
	key = rng.start;
	key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
	ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
				   &super->log_merge, &key);
	if (ret < 0) {
		err_str = "deleting old merge range item";
		goto out;
	}
	ins_rng = true;

	/* add remaining range if we have to */
	if (scoutfs_key_compare(&rng.end, &req.end) > 0) {
		remain.start = req.end;
		scoutfs_key_inc(&remain.start);
		remain.end = rng.end;

		key = remain.start;
		key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
		ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   &remain, sizeof(remain));
		if (ret < 0) {
			err_str = "inserting remaining range item";
			goto out;
		}
		del_remain = true;
	}

	/* give the client an allocation pool to work with */
	mutex_lock(&server->alloc_mutex);
	ret = scoutfs_alloc_fill_list(sb, &server->alloc, &server->wri,
				      &req.meta_avail, server->meta_avail,
				      SCOUTFS_SERVER_MERGE_FILL_LO,
				      SCOUTFS_SERVER_MERGE_FILL_TARGET);
	mutex_unlock(&server->alloc_mutex);
	if (ret < 0) {
		err_str = "filling merge req meta_avail";
		goto out;
	}

	/* save the request that will be sent to the client */
	init_log_merge_key(&key, SCOUTFS_LOG_MERGE_REQUEST_ZONE, rid,
			   le64_to_cpu(req.seq));
	ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
				   &super->log_merge, &key,
				   &req, sizeof(req));
	if (ret < 0) {
		err_str = "inserting merge req item";
		goto out;
	}
	del_req = true;

	trace_scoutfs_get_log_merge_request(sb, rid, &req.root,
					    &req.start, &req.end,
					    le64_to_cpu(req.input_seq),
					    le64_to_cpu(req.seq));

	/* make sure next range avoids ranges for parent in use */
	stat.next_range_key = par_end;
	if (!scoutfs_key_is_ones(&stat.next_range_key))
		scoutfs_key_inc(&stat.next_range_key);

	/* update the status requests count */
	le64_add_cpu(&stat.nr_requests, 1);
	init_log_merge_key(&key, SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0);
	ret = scoutfs_btree_update(sb, &server->alloc, &server->wri,
				   &super->log_merge, &key,
				   &stat, sizeof(stat));
	if (ret < 0) {
		err_str = "updating merge status item";
		goto out;
	}
	upd_stat = true;

out:
	if (ret < 0) {
		/* undo any our partial item changes */
		if (upd_stat) {
			le64_add_cpu(&stat.nr_requests, -1ULL);
			init_log_merge_key(&key, SCOUTFS_LOG_MERGE_STATUS_ZONE,
					   0, 0);
			err = scoutfs_btree_update(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key,
						   &stat, sizeof(stat));
			BUG_ON(err); /* inconsistent */
		}

		if (del_req) {
			init_log_merge_key(&key, SCOUTFS_LOG_MERGE_REQUEST_ZONE,
					   rid, le64_to_cpu(req.seq));
			err = scoutfs_btree_delete(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key);
			BUG_ON(err); /* inconsistent */
		}

		if (del_remain) {
			key = remain.start;
			key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
			err = scoutfs_btree_delete(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key);
			BUG_ON(err); /* inconsistent */
		}

		if (ins_rng) {
			key = rng.start;
			key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
			err = scoutfs_btree_insert(sb, &server->alloc,
						   &server->wri,
						   &super->log_merge, &key,
						   &rng, sizeof(rng));
			BUG_ON(err); /* inconsistent */
		}

		/* reclaim allocation if we failed */
		mutex_lock(&server->alloc_mutex);
		err = scoutfs_alloc_splice_list(sb, &server->alloc,
						&server->wri,
						server->other_freed,
						&req.meta_avail);
		mutex_unlock(&server->alloc_mutex);
		BUG_ON(err); /* inconsistent */

		if (ret < 0 && ret != -ENOENT)
			scoutfs_err(sb, "error %d getting merge req rid %016llx: %s",
				    ret, rid, err_str);
	}

	mutex_unlock(&server->logs_mutex);
	ret = server_apply_commit(sb, &hold, ret);

respond:
	return scoutfs_net_response(sb, conn, cmd, id, ret, &req, sizeof(req));
}

/*
 * Commit the client's leg merge work.  Typically we store the
 * completion so that we can later splice it back into the fs root and
 * reclaim its allocators later in a batch.  If it failed we reclaim it
 * immediately.
 */
static int server_commit_log_merge(struct super_block *sb,
				   struct scoutfs_net_connection *conn,
				   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	u64 rid = scoutfs_net_client_rid(conn);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_log_merge_request orig_req;
	struct scoutfs_log_merge_complete *comp;
	struct scoutfs_log_merge_status stat;
	struct scoutfs_log_merge_range rng;
	struct scoutfs_key key;
	COMMIT_HOLD(hold);
	char *err_str = NULL;
	bool deleted = false;
	int ret = 0;
	int err = 0;

	scoutfs_key_set_zeros(&rng.end);

	if (arg_len != sizeof(struct scoutfs_log_merge_complete))
		return -EINVAL;
	comp = arg;

	trace_scoutfs_get_log_merge_complete(sb, rid, &comp->root,
					     &comp->start, &comp->end,
					     &comp->remain,
					     le64_to_cpu(comp->seq),
					     le64_to_cpu(comp->flags));

	server_hold_commit(sb, &hold);
	mutex_lock(&server->logs_mutex);

	/* find the status of the current log merge */
	ret = next_log_merge_item(sb, &super->log_merge,
				  SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0,
				  &stat, sizeof(stat));
	if (ret < 0) {
		err_str = "getting merge status item";
		goto out;
	}

	/* find the completion's original saved request */
	ret = next_log_merge_item(sb, &super->log_merge, SCOUTFS_LOG_MERGE_REQUEST_ZONE,
				  rid, le64_to_cpu(comp->seq), &orig_req, sizeof(orig_req));
	if (ret == 0 && (comp->rid != orig_req.rid || comp->seq != orig_req.seq))
		ret = -ENOENT;
	if (ret < 0) {
		/* ENOENT is expected for resent processed completion */
		if (ret != -ENOENT)
			err_str = "finding orig request";
		goto out;
	}

	/* delete the original request item */
	init_log_merge_key(&key, SCOUTFS_LOG_MERGE_REQUEST_ZONE, rid,
			   le64_to_cpu(orig_req.seq));
	ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
				   &super->log_merge, &key);
	if (ret < 0) {
		err_str = "deleting orig request";
		goto out;
	}
	deleted = true;

	if (le64_to_cpu(comp->flags) & SCOUTFS_LOG_MERGE_COMP_ERROR) {
		/* restore the range and reclaim the allocator if it failed */
		rng.start = orig_req.start;
		rng.end = orig_req.end;

		key = rng.start;
		key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
		ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   &rng, sizeof(rng));
		if (ret < 0) {
			err_str = "inserting remaining range";
			goto out;
		}

		mutex_lock(&server->alloc_mutex);
		ret = (err_str = "splicing orig meta_avail",
		       scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri,
						 server->other_freed, &orig_req.meta_avail)) ?:
		      (err_str = "splicing orig meta_freed",
		       scoutfs_alloc_splice_list(sb, &server->alloc, &server->wri,
						 server->other_freed, &orig_req.meta_freed));
		mutex_unlock(&server->alloc_mutex);
		if (ret < 0)
			goto out;

	} else {
		/* otherwise store the completion for later splicing */
		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_COMPLETE_ZONE,
				   le64_to_cpu(comp->seq), 0);
		ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   comp, sizeof(*comp));
		if (ret < 0) {
			err_str = "inserting completion";
			goto out;
		}

		le64_add_cpu(&stat.nr_complete, 1ULL);
	}

	/* and update the status counts */
	le64_add_cpu(&stat.nr_requests, -1ULL);
	init_log_merge_key(&key, SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0);
	ret = scoutfs_btree_update(sb, &server->alloc, &server->wri,
				   &super->log_merge, &key,
				   &stat, sizeof(stat));
	if (ret < 0) {
		err_str = "updating status";
		goto out;
	}

out:
	mutex_unlock(&server->logs_mutex);

	if (ret < 0 && err_str)
		scoutfs_err(sb, "error %d committing log merge: %s", ret, err_str);

	err = server_apply_commit(sb, &hold, ret);
	BUG_ON(ret < 0 && deleted); /* inconsistent */

	if (ret == 0)
		ret = err;

	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

/* The server is receiving an omap response from the client */
static int open_ino_map_response(struct super_block *sb, struct scoutfs_net_connection *conn,
				 void *resp, unsigned int resp_len, int error, void *data)
{
	u64 rid = scoutfs_net_client_rid(conn);

	if (resp_len != sizeof(struct scoutfs_open_ino_map))
		return -EINVAL;

	return scoutfs_omap_server_handle_response(sb, rid, resp);
}

/*
 * The server is sending an omap requests to all the clients it thought
 * were connected when it received a request from another client.
 * This send can race with the client's connection being removed.  We
 * can drop those sends on the floor and mask ENOTCONN.  The client's rid
 * will soon be removed from the request which will be correctly handled.
 */
int scoutfs_server_send_omap_request(struct super_block *sb, u64 rid,
				     struct scoutfs_open_ino_map_args *args)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	int ret;

	ret = scoutfs_net_submit_request_node(sb, server->conn, rid, SCOUTFS_NET_CMD_OPEN_INO_MAP,
					      args, sizeof(*args),
					      open_ino_map_response, NULL, NULL);
	if (ret == -ENOTCONN)
		ret = 0;
	return ret;
}

/*
 * The server is sending an omap response to the client that originated
 * the request.  These responses are sent long after the incoming
 * request has pinned the client connection and guaranteed that we'll be
 * able to queue a response.  This can race with the client connection
 * being torn down and it's OK if we drop the response.  Either the
 * client is being evicted and we don't care about them anymore or we're
 * tearing down in unmount and the client will resend to thee next
 * server.
 */
int scoutfs_server_send_omap_response(struct super_block *sb, u64 rid, u64 id,
				      struct scoutfs_open_ino_map *map, int err)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	int ret;

	ret = scoutfs_net_response_node(sb, server->conn, rid, SCOUTFS_NET_CMD_OPEN_INO_MAP,
					id, err, map, sizeof(*map));
	if (ret == -ENOTCONN)
		ret = 0;
	return ret;
}

/* The server is receiving an omap request from the client */
static int server_open_ino_map(struct super_block *sb, struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	u64 rid = scoutfs_net_client_rid(conn);
	int ret;

	if (arg_len != sizeof(struct scoutfs_open_ino_map_args)) {
		ret = -EINVAL;
		goto out;
	}

	ret = scoutfs_omap_server_handle_request(sb, rid, id, arg);
out:
	if (ret < 0)
		return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);

	return 0;
}

/* The server is receiving a request for the current volume options */
static int server_get_volopt(struct super_block *sb, struct scoutfs_net_connection *conn,
			     u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_volume_options volopt;
	unsigned seq;
	int ret = 0;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	do {
		seq = read_seqbegin(&server->seqlock);
		volopt = server->volopt;
	} while (read_seqretry(&server->seqlock, seq));

out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, &volopt, sizeof(volopt));
}

/*
 * The server is receiving a request to update volume options.
 *
 * The in-memory options that readers use is updated only once the
 * updated options are written in the super block.
 */
static int server_set_volopt(struct super_block *sb, struct scoutfs_net_connection *conn,
			     u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_volume_options *volopt;
	COMMIT_HOLD(hold);
	u64 opt;
	u64 nr;
	int ret = 0;

	if (arg_len != sizeof(struct scoutfs_volume_options)) {
		ret = -EINVAL;
		goto out;
	}
	volopt = arg;

	if (le64_to_cpu(volopt->set_bits) & SCOUTFS_VOLOPT_EXPANSION_BITS) {
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&server->volopt_mutex);

	server_hold_commit(sb, &hold);

	if (le64_to_cpu(volopt->set_bits) & SCOUTFS_VOLOPT_DATA_ALLOC_ZONE_BLOCKS_BIT) {
		opt = le64_to_cpu(volopt->data_alloc_zone_blocks);
		if (opt < SCOUTFS_SERVER_DATA_FILL_TARGET) {
			scoutfs_err(sb, "setting data_alloc_zone_blocks to '%llu' failed, must be at least %llu mount data allocation target blocks",
				    opt, SCOUTFS_SERVER_DATA_FILL_TARGET);
			ret = -EINVAL;
			goto apply;
		}

		nr = div_u64(le64_to_cpu(super->total_data_blocks), SCOUTFS_DATA_ALLOC_MAX_ZONES);
		if (opt < nr) {
			scoutfs_err(sb, "setting data_alloc_zone_blocks to '%llu' failed, must be greater than %llu blocks which results in max %u zones",
				    opt, nr, SCOUTFS_DATA_ALLOC_MAX_ZONES);
			ret = -EINVAL;
			goto apply;
		}

		if (opt > le64_to_cpu(super->total_data_blocks)) {
			scoutfs_err(sb, "setting data_alloc_zone_blocks to '%llu' failed, must be at most %llu total data device blocks",
				    opt, le64_to_cpu(super->total_data_blocks));
			ret = -EINVAL;
			goto apply;
		}

		super->volopt.data_alloc_zone_blocks = volopt->data_alloc_zone_blocks;
		super->volopt.set_bits |= cpu_to_le64(SCOUTFS_VOLOPT_DATA_ALLOC_ZONE_BLOCKS_BIT);
	}

apply:
	ret = server_apply_commit(sb, &hold, ret);

	write_seqlock(&server->seqlock);
	if (ret == 0)
		server->volopt = super->volopt;
	else
		super->volopt = server->volopt;
	write_sequnlock(&server->seqlock);

	mutex_unlock(&server->volopt_mutex);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

static int server_clear_volopt(struct super_block *sb, struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_volume_options *volopt;
	COMMIT_HOLD(hold);
	__le64 *opt;
	u64 bit;
	int ret = 0;
	int i;

	if (arg_len != sizeof(struct scoutfs_volume_options)) {
		ret = -EINVAL;
		goto out;
	}
	volopt = arg;

	if (le64_to_cpu(volopt->set_bits) & SCOUTFS_VOLOPT_EXPANSION_BITS) {
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&server->volopt_mutex);

	server_hold_commit(sb, &hold);

	for (i = 0, bit = 1, opt = first_valopt(&super->volopt); i < 64; i++, bit <<= 1, opt++) {
		if (le64_to_cpu(volopt->set_bits) & bit) {
			super->volopt.set_bits &= ~cpu_to_le64(bit);
			*opt = 0;
		}
	}

	ret = server_apply_commit(sb, &hold, ret);

	write_seqlock(&server->seqlock);
	if (ret == 0)
		server->volopt = super->volopt;
	else
		super->volopt = server->volopt;
	write_sequnlock(&server->seqlock);

	mutex_unlock(&server->volopt_mutex);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
}

static u64 device_blocks(struct block_device *bdev, int shift)
{
	return i_size_read(bdev->bd_inode) >> shift;
}

static int server_resize_devices(struct super_block *sb, struct scoutfs_net_connection *conn,
				 u8 cmd, u64 id, void *arg, u16 arg_len)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_net_resize_devices *nrd;
	COMMIT_HOLD(hold);
	u64 meta_tot;
	u64 meta_start;
	u64 meta_len;
	u64 data_tot;
	u64 data_start;
	u64 data_len;
	int ret;
	int err;

	if (arg_len != sizeof(struct scoutfs_net_resize_devices)) {
		ret = -EINVAL;
		goto out;
	}
	nrd = arg;

	meta_tot = le64_to_cpu(nrd->new_total_meta_blocks);
	data_tot = le64_to_cpu(nrd->new_total_data_blocks);

	server_hold_commit(sb, &hold);
	mutex_lock(&server->alloc_mutex);

	if (meta_tot == le64_to_cpu(super->total_meta_blocks))
		meta_tot = 0;
	if (data_tot == le64_to_cpu(super->total_data_blocks))
		data_tot = 0;

	if (!meta_tot && !data_tot) {
		ret = 0;
		goto unlock;
	}

	/* we don't support shrinking */
	if ((meta_tot && (meta_tot < le64_to_cpu(super->total_meta_blocks))) ||
	    (data_tot && (data_tot < le64_to_cpu(super->total_data_blocks)))) {
		ret = -EINVAL;
		goto unlock;
	}

	/* must be within devices */
	if ((meta_tot > device_blocks(sbi->meta_bdev, SCOUTFS_BLOCK_LG_SHIFT)) ||
	    (data_tot > device_blocks(sb->s_bdev, SCOUTFS_BLOCK_SM_SHIFT))) {
		ret = -EINVAL;
		goto unlock;
	}

	/* extents are only used if _tot is set */
	meta_start = le64_to_cpu(super->total_meta_blocks);
	meta_len = meta_tot - meta_start;
	data_start = le64_to_cpu(super->total_data_blocks);
	data_len = data_tot - data_start;

	if (meta_tot) {
		ret = scoutfs_alloc_insert(sb, &server->alloc, &server->wri,
					   server->meta_avail, meta_start, meta_len);
		if (ret < 0)
			goto unlock;
	}

	if (data_tot) {
		ret = scoutfs_alloc_insert(sb, &server->alloc, &server->wri,
					   &super->data_alloc, data_start, data_len);
		if (ret < 0) {
			if (meta_tot) {
				err = scoutfs_alloc_remove(sb, &server->alloc, &server->wri,
							   server->meta_avail, meta_start,
							   meta_len);
				WARN_ON_ONCE(err); /* btree blocks are dirty.. really unlikely? */
			}
			goto unlock;
		}
	}

	if (meta_tot)
		super->total_meta_blocks = cpu_to_le64(meta_tot);
	if (data_tot)
		super->total_data_blocks = cpu_to_le64(data_tot);

	ret = 0;
unlock:
	mutex_unlock(&server->alloc_mutex);
	ret = server_apply_commit(sb, &hold, ret);
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, NULL, 0);
};

struct statfs_free_blocks {
	u64 meta;
	u64 data;
};

static int count_free_blocks(struct super_block *sb, void *arg, int owner,
			     u64 id, bool meta, bool avail, u64 blocks)
{
	struct statfs_free_blocks *sfb = arg;

	if (meta)
		sfb->meta += blocks;
	else
		sfb->data += blocks;

	return 0;
}

/*
 * We calculate the total inode count and free blocks from the last
 * stable super that was written.  Other users also walk stable blocks
 * so by joining them we don't have to worry about ensuring that we've
 * locked all the dirty structures that the summations could reference.
 * We handle stale reads by retrying with the most recent stable super.
 */
static int server_statfs(struct super_block *sb, struct scoutfs_net_connection *conn,
			 u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_super_block super;
	struct scoutfs_net_statfs nst = {{0,}};
	struct statfs_free_blocks sfb = {0,};
	DECLARE_SAVED_REFS(saved);
	u64 inode_count;
	int ret;

	if (arg_len != 0) {
		ret = -EINVAL;
		goto out;
	}

	do {
		get_stable(sb, &super, NULL);

		ret = scoutfs_alloc_foreach_super(sb, &super, count_free_blocks, &sfb) ?:
		      scoutfs_forest_inode_count(sb, &super, &inode_count);
		if (ret < 0 && ret != -ESTALE)
			goto out;

		ret = scoutfs_block_check_stale(sb, ret, &saved, &super.logs_root.ref,
						&super.srch_root.ref);
	} while (ret == -ESTALE);

	BUILD_BUG_ON(sizeof(nst.uuid) != sizeof(super.uuid));
	memcpy(nst.uuid, super.uuid, sizeof(nst.uuid));
	nst.free_meta_blocks = cpu_to_le64(sfb.meta);
	nst.total_meta_blocks = super.total_meta_blocks;
	nst.free_data_blocks = cpu_to_le64(sfb.data);
	nst.total_data_blocks = super.total_data_blocks;
	nst.inode_count = cpu_to_le64(inode_count);

	ret = 0;
out:
	return scoutfs_net_response(sb, conn, cmd, id, ret, &nst, sizeof(nst));
}

static void init_mounted_client_key(struct scoutfs_key *key, u64 rid)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_MOUNTED_CLIENT_ZONE,
		.skmc_rid = cpu_to_le64(rid),
	};
}

static bool invalid_mounted_client_item(struct scoutfs_btree_item_ref *iref)
{
	return (iref->val_len != sizeof(struct scoutfs_mounted_client_btree_val));
}

/*
 * Insert a new mounted client item for a client that is sending us a
 * greeting that hasn't yet seen a response.  The greeting can be
 * retransmitted to a new server after the previous inserted the item so
 * it's acceptable to see -EEXIST.
 */
static int insert_mounted_client(struct super_block *sb, u64 rid, u64 gr_flags,
				 struct sockaddr_in *sin)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_mounted_client_btree_val mcv;
	struct scoutfs_key key;
	int ret;

	init_mounted_client_key(&key, rid);
	scoutfs_sin_to_addr(&mcv.addr, sin);
	mcv.flags = 0;
	if (gr_flags & SCOUTFS_NET_GREETING_FLAG_QUORUM)
		mcv.flags |= SCOUTFS_MOUNTED_CLIENT_QUORUM;

	mutex_lock(&server->mounted_clients_mutex);
	ret = scoutfs_btree_insert(sb, &server->alloc, &server->wri,
				   &super->mounted_clients, &key, &mcv,
				   sizeof(mcv));
	if (ret == -EEXIST)
		ret = 0;
	mutex_unlock(&server->mounted_clients_mutex);

	return ret;
}

static int lookup_mounted_client_addr(struct super_block *sb, u64 rid,
				      union scoutfs_inet_addr *addr)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_mounted_client_btree_val *mcv;
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	int ret;

	init_mounted_client_key(&key, rid);

	mutex_lock(&server->mounted_clients_mutex);
	ret = scoutfs_btree_lookup(sb, &super->mounted_clients, &key, &iref);
	if (ret == 0) {
		if (invalid_mounted_client_item(&iref)) {
			ret = -EIO;
		} else {
			mcv = iref.val;
			*addr = mcv->addr;
		}
		scoutfs_btree_put_iref(&iref);
	}
	mutex_unlock(&server->mounted_clients_mutex);

	return ret;
}

/*
 * Remove the record of a mounted client.  The record can already be
 * removed if we're processing a farewell on behalf of a client that
 * already had a previous server process its farewell.
 *
 * The caller has to serialize with farewell processing.
 */
static int delete_mounted_client(struct super_block *sb, u64 rid)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_key key;
	int ret;

	init_mounted_client_key(&key, rid);

	mutex_lock(&server->mounted_clients_mutex);
	ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
				   &super->mounted_clients, &key);
	mutex_unlock(&server->mounted_clients_mutex);
	if (ret == -ENOENT)
		ret = 0;

	return ret;
}

/*
 * Remove all the busy items for srch compactions that the mount might
 * have been responsible for and reclaim all their allocators.  The freed
 * allocator could still contain stable srch file blknos.
 */
static int cancel_srch_compact(struct super_block *sb, u64 rid)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_alloc_list_head av;
	struct scoutfs_alloc_list_head fr;
	int ret;

	for (;;) {
		mutex_lock(&server->srch_mutex);
		ret = scoutfs_srch_cancel_compact(sb, &server->alloc,
						  &server->wri,
						  &super->srch_root, rid,
						  &av, &fr);
		mutex_unlock(&server->srch_mutex);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		mutex_lock(&server->alloc_mutex);
		ret = scoutfs_alloc_splice_list(sb, &server->alloc,
						&server->wri,
						server->other_freed, &av) ?:
		      scoutfs_alloc_splice_list(sb, &server->alloc,
						&server->wri,
						server->other_freed, &fr);
		mutex_unlock(&server->alloc_mutex);
		if (WARN_ON_ONCE(ret < 0))
			break;
	}

	return ret;
}

/*
 * Clean up any log merge requests which have now been abandoned because
 * their client was evicted.  This is always called on eviction and
 * there may have been no merge in progres or our client had no
 * outstanding requests.  For each pending request, we reclaim its
 * allocators, delte its item, and update the status.
 *
 * The request we cancel might have been the last request which
 * prevented batch processing, but we don't check that here.  This is in
 * the client eviction path and we want that to be as light and
 * responsive as possible so we can get back up and running.  The next
 * client get_log_merge request will see that no more requests are
 * outstanding.
 *
 * The caller holds a commit, but we're responsible for locking.
 */
static int cancel_log_merge(struct super_block *sb, u64 rid)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_log_merge_status stat;
	struct scoutfs_log_merge_request req;
	struct scoutfs_log_merge_range rng;
	struct scoutfs_key key;
	bool update = false;
	u64 seq;
	int ret;

	mutex_lock(&server->logs_mutex);

	ret = next_log_merge_item(sb, &super->log_merge,
				  SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0,
				  &stat, sizeof(stat));
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}

	for (seq = 0; ; seq++) {
		ret = next_log_merge_item(sb, &super->log_merge,
					  SCOUTFS_LOG_MERGE_REQUEST_ZONE, rid,
					  seq, &req, sizeof(req));
		if (ret == 0 && le64_to_cpu(req.rid) != rid)
			ret = -ENOENT;
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		seq = le64_to_cpu(req.seq);

		/* remove request item */
		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_REQUEST_ZONE, rid,
				   le64_to_cpu(req.seq));
		ret = scoutfs_btree_delete(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key);
		if (ret < 0)
			goto out;

		/* restore range */
		rng.start = req.start;
		rng.end = req.end;

		key = rng.start;
		key.sk_zone = SCOUTFS_LOG_MERGE_RANGE_ZONE;
		ret = scoutfs_btree_insert(sb, &server->alloc,
					   &server->wri,
					   &super->log_merge, &key,
					   &rng, sizeof(rng));
		if (ret < 0)
			goto out;

		/* reclaim allocator */
		mutex_lock(&server->alloc_mutex);
		ret = scoutfs_alloc_splice_list(sb, &server->alloc,
						&server->wri,
						server->other_freed,
						&req.meta_avail) ?:
		      scoutfs_alloc_splice_list(sb, &server->alloc,
						&server->wri,
						server->other_freed,
						&req.meta_freed);
		mutex_unlock(&server->alloc_mutex);
		if (ret < 0)
			goto out;

		/* update count */
		le64_add_cpu(&stat.nr_requests, -1ULL);
		update = true;
	}

	if (update) {
		/* and update the status counts */
		init_log_merge_key(&key, SCOUTFS_LOG_MERGE_STATUS_ZONE, 0, 0);
		ret = scoutfs_btree_update(sb, &server->alloc, &server->wri,
					   &super->log_merge, &key,
					   &stat, sizeof(stat));
	}
out:
	mutex_unlock(&server->logs_mutex);

	BUG_ON(ret < 0);  /* XXX inconsistent */
	return ret;
}

/*
 * Farewell processing is async to the request processing work.  Shutdown
 * waits for request processing to finish and then tears down the connection.
 * We don't want to queue farewell processing once we start shutting down
 * so that we don't have farewell processing racing with the connecting
 * being shutdown.  If a mount's farewell message is dropped by a server
 * it will be processed by the next server.
 */
static void queue_farewell_work(struct server_info *server)
{
	if (!server_is_stopping(server))
		queue_work(server->wq, &server->farewell_work);
}

/*
 * Process an incoming greeting request in the server from the client.
 * We try to send responses to failed greetings so that the sender can
 * log some detail before shutting down.  A failure to send a greeting
 * response shuts down the connection.
 *
 * If a client reconnects they'll send their previously received
 * serer_term in their greeting request.
 *
 * XXX The logic of this has gotten convoluted.  The lock server can
 * send a recovery request so it needs to be called after the core net
 * greeting call enables messages.  But we want the greeting reply to be
 * sent first, so we currently queue it on the send queue before
 * enabling messages.  That means that a lot of errors that happen after
 * the reply can't be sent to the client.  They'll just see a disconnect
 * and won't know what's happened.  This all needs to be refactored.
 */
static int server_greeting(struct super_block *sb,
			   struct scoutfs_net_connection *conn,
			   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_net_greeting *gr = arg;
	struct scoutfs_net_greeting greet;
	DECLARE_SERVER_INFO(sb, server);
	COMMIT_HOLD(hold);
	bool reconnecting;
	bool first_contact;
	bool farewell;
	int ret = 0;
	int err;

	if (arg_len != sizeof(struct scoutfs_net_greeting)) {
		ret = -EINVAL;
		goto send_err;
	}

	if (gr->fsid != cpu_to_le64(sbi->fsid)) {
		scoutfs_warn(sb, "client rid %016llx greeting fsid 0x%llx did not match server fsid 0x%llx",
			     le64_to_cpu(gr->rid), le64_to_cpu(gr->fsid), sbi->fsid);
		ret = -EINVAL;
		goto send_err;
	}

	if (le64_to_cpu(gr->fmt_vers) != sbi->fmt_vers) {
		scoutfs_warn(sb, "client rid %016llx greeting format version %llu did not match server format version %llu",
			     le64_to_cpu(gr->rid), le64_to_cpu(gr->fmt_vers), sbi->fmt_vers);
		ret = -EINVAL;
		goto send_err;
	}

	if (gr->server_term == 0) {
		server_hold_commit(sb, &hold);

		ret = insert_mounted_client(sb, le64_to_cpu(gr->rid), le64_to_cpu(gr->flags),
					    &conn->peername);

		ret = server_apply_commit(sb, &hold, ret);
		queue_work(server->wq, &server->farewell_work);
		if (ret < 0)
			goto send_err;
	}

	scoutfs_server_recov_finish(sb, le64_to_cpu(gr->rid), SCOUTFS_RECOV_GREETING);
	ret = 0;

send_err:
	err = ret;

	greet.fsid = super->hdr.fsid;
	greet.fmt_vers = cpu_to_le64(sbi->fmt_vers);
	greet.server_term = cpu_to_le64(server->term);
	greet.rid = gr->rid;
	greet.flags = 0;

	/* queue greeting response to be sent first once messaging enabled */
	ret = scoutfs_net_response(sb, conn, cmd, id, err,
				   &greet, sizeof(greet));
	if (ret == 0 && err)
		ret = err;
	if (ret)
		goto out;

	/* have the net core enable messaging and resend */
	reconnecting = gr->server_term != 0;
	first_contact = le64_to_cpu(gr->server_term) != server->term;
	if (gr->flags & cpu_to_le64(SCOUTFS_NET_GREETING_FLAG_FAREWELL))
		farewell = true;
	else
		farewell = false;

	scoutfs_net_server_greeting(sb, conn, le64_to_cpu(gr->rid), id,
				    reconnecting, first_contact, farewell);

	/* let layers know we have a client connecting for the first time */
	if (le64_to_cpu(gr->server_term) != server->term) {
		ret = scoutfs_lock_server_greeting(sb, le64_to_cpu(gr->rid)) ?:
		      scoutfs_omap_add_rid(sb, le64_to_cpu(gr->rid));
		if (ret)
			goto out;
	}

out:
	return ret;
}

struct farewell_request {
	struct list_head entry;
	u64 net_id;
	u64 rid;
};


/*
 * Reclaim all the resources for a mount which has gone away.  It's sent
 * us a farewell promising to leave or we actively fenced it.
 *
 * This can be called multiple times across different servers for
 * different reclaim attempts.  The existence of the mounted_client item
 * triggers reclaim and must be deleted last.  Each step knows that it
 * can be called multiple times and safely recognizes that its work
 * might have already been done.
 *
 * Some steps (reclaiming large fragmented allocators) may need multiple
 * calls to complete.  They return -EINPROGRESS which tells us to apply
 * the server commit and retry.
 */
static int reclaim_rid(struct super_block *sb, u64 rid)
{
	COMMIT_HOLD(hold);
	int ret;
	int err;

	do {
		server_hold_commit(sb, &hold);

		err = scoutfs_lock_server_farewell(sb, rid) ?:
		      reclaim_open_log_tree(sb, rid) ?:
		      cancel_srch_compact(sb, rid) ?:
		      cancel_log_merge(sb, rid) ?:
		      scoutfs_omap_remove_rid(sb, rid) ?:
		      delete_mounted_client(sb, rid);

		ret = server_apply_commit(sb, &hold, err == -EINPROGRESS ? 0 : err);

	} while (err == -EINPROGRESS && ret == 0);

	return ret;
}

/*
 * This work processes farewell requests asynchronously.  Requests from
 * quorum members can be held until only the final majority remains and
 * they've all sent farewell requests.
 *
 * A client can be disconnected before receiving our farewell response.
 * Before reconnecting they check for their mounted client item, if it's
 * been removed then they know that their farewell has been processed
 * and that they finish unmounting without reconnecting.
 *
 * Responses for clients who aren't quorum members are immediately sent.
 * Clients that don't have a mounted client record have already had
 * their farewell processed by another server and can proceed.
 *
 * Farewell responses are unique in that sending them causes the server
 * to shutdown the connection to the client next time the socket
 * disconnects.  If the socket is destroyed before the client gets the
 * response they'll reconnect and we'll see them as a brand new client
 * who immediately sends a farewell.  It'll be processed and it all
 * works out.
 *
 * If this worker sees an error it assumes that this sever is done for
 * and that another had better take its place.
 */
static void farewell_worker(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  farewell_work);
	struct super_block *sb = server->sb;
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_mounted_client_btree_val *mcv;
	struct farewell_request *tmp;
	struct farewell_request *fw;
	SCOUTFS_BTREE_ITEM_REF(iref);
	unsigned int quo_reqs = 0;
	unsigned int quo_mnts = 0;
	unsigned int non_mnts = 0;
	struct scoutfs_key key;
	LIST_HEAD(reqs);
	LIST_HEAD(send);
	bool more_reqs;
	int ret;

	spin_lock(&server->farewell_lock);
	list_splice_init(&server->farewell_requests, &reqs);
	spin_unlock(&server->farewell_lock);

	/* first count mounted clients who could send requests */
	init_mounted_client_key(&key, 0);
	for (;;) {
		mutex_lock(&server->mounted_clients_mutex);
		ret = scoutfs_btree_next(sb, &super->mounted_clients, &key,
					 &iref);
		mutex_unlock(&server->mounted_clients_mutex);
		if (ret == 0 && invalid_mounted_client_item(&iref)) {
			scoutfs_btree_put_iref(&iref);
			ret = -EIO;
		}
		if (ret != 0) {
			if (ret == -ENOENT)
				break;
			goto out;
		}

		key = *iref.key;
		mcv = iref.val;

		if (mcv->flags & SCOUTFS_MOUNTED_CLIENT_QUORUM)
			quo_mnts++;
		else
			non_mnts++;

		scoutfs_btree_put_iref(&iref);
		scoutfs_key_inc(&key);
	}

	/* walk requests, checking their mounted client items */
	list_for_each_entry_safe(fw, tmp, &reqs, entry) {
		init_mounted_client_key(&key, fw->rid);
		mutex_lock(&server->mounted_clients_mutex);
		ret = scoutfs_btree_lookup(sb, &super->mounted_clients, &key,
					   &iref);
		mutex_unlock(&server->mounted_clients_mutex);
		if (ret == 0 && invalid_mounted_client_item(&iref)) {
			scoutfs_btree_put_iref(&iref);
			ret = -EIO;
		}
		if (ret < 0) {
			/* missing items means we've already processed */
			if (ret == -ENOENT) {
				list_move(&fw->entry, &send);
				continue;
			}
			goto out;
		}

		mcv = iref.val;

		/* count quo reqs, can always send to non-quo clients */
		if (mcv->flags & SCOUTFS_MOUNTED_CLIENT_QUORUM) {
			quo_reqs++;
		} else {
			list_move(&fw->entry, &send);
			non_mnts--;
		}

		scoutfs_btree_put_iref(&iref);
	}

	/*
	 * Only requests from quorum members remain and we've counted
	 * them and remaining mounts.  Send responses as long as enough
	 * quorum clients remain for a majority, or all the requests are
	 * from the final majority of quorum clients they're the only
	 * mounted clients.
	 */
	list_for_each_entry_safe(fw, tmp, &reqs, entry) {
		if ((quo_mnts > scoutfs_quorum_votes_needed(sb)) ||
		    ((quo_reqs == quo_mnts) && (non_mnts == 0))) {
			list_move_tail(&fw->entry, &send);
			quo_mnts--;
			quo_reqs--;
		}
	}

	/*
	 * Responses that are ready to send can be further delayed by
	 * moving them back to the reqs list.
	 */
	list_for_each_entry_safe(fw, tmp, &send, entry) {
		/* finish lock recovery before destroying locks, fenced if too long */
		if (scoutfs_recov_is_pending(sb, fw->rid, SCOUTFS_RECOV_LOCKS)) {
			list_move_tail(&fw->entry, &reqs);
			quo_reqs++;
		}
	}

	/* clean up resources for mounts before sending responses */
	list_for_each_entry_safe(fw, tmp, &send, entry) {
		ret = reclaim_rid(sb, fw->rid);
		if (ret)
			goto out;
	}

	/* and finally send all the responses */
	list_for_each_entry_safe(fw, tmp, &send, entry) {

		ret = scoutfs_net_response_node(sb, server->conn, fw->rid,
						SCOUTFS_NET_CMD_FAREWELL,
						fw->net_id, 0, NULL, 0);
		if (ret)
			break;

		list_del_init(&fw->entry);
		kfree(fw);
	}

	ret = 0;
out:
	spin_lock(&server->farewell_lock);
	more_reqs = !list_empty(&server->farewell_requests);
	list_splice_init(&reqs, &server->farewell_requests);
	list_splice_init(&send, &server->farewell_requests);
	spin_unlock(&server->farewell_lock);

	if (ret < 0)
		stop_server(server);
	else if (more_reqs)
		queue_farewell_work(server);
}

static void free_farewell_requests(struct super_block *sb, u64 rid)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	struct farewell_request *tmp;
	struct farewell_request *fw;
	LIST_HEAD(rid_list);

	spin_lock(&server->farewell_lock);
	list_for_each_entry_safe(fw, tmp, &server->farewell_requests, entry) {
		if (rid == 0 || fw->rid == rid)
			list_move_tail(&fw->entry, &rid_list);
	}
	spin_unlock(&server->farewell_lock);

	list_for_each_entry_safe(fw, tmp, &rid_list, entry)
		kfree(fw);
}

/*
 * The server is receiving a farewell message from a client that is
 * unmounting.  It won't send any more requests and once it receives our
 * response it will not reconnect.
 *
 * XXX we should make sure that all our requests to the client have finished
 * before we respond.  Locking will have its own messaging for orderly
 * shutdown.  That leaves compaction which will be addressed as part of
 * the larger work of recovering compactions that were in flight when
 * a client crashed.
 */
static int server_farewell(struct super_block *sb,
			   struct scoutfs_net_connection *conn,
			   u8 cmd, u64 id, void *arg, u16 arg_len)
{
	struct server_info *server = SCOUTFS_SB(sb)->server_info;
	u64 rid = scoutfs_net_client_rid(conn);
	struct farewell_request *fw;

	if (arg_len != 0)
		return -EINVAL;

	/* XXX tear down if we fence, or if we shut down */

	fw = kmalloc(sizeof(struct farewell_request), GFP_NOFS);
	if (fw == NULL)
		return -ENOMEM;

	fw->rid = rid;
	fw->net_id = id;

	spin_lock(&server->farewell_lock);
	list_add_tail(&fw->entry, &server->farewell_requests);
	spin_unlock(&server->farewell_lock);

	queue_farewell_work(server);

	/* response will be sent later */
	return 0;
}

static scoutfs_net_request_t server_req_funcs[] = {
	[SCOUTFS_NET_CMD_GREETING]		= server_greeting,
	[SCOUTFS_NET_CMD_ALLOC_INODES]		= server_alloc_inodes,
	[SCOUTFS_NET_CMD_GET_LOG_TREES]		= server_get_log_trees,
	[SCOUTFS_NET_CMD_COMMIT_LOG_TREES]	= server_commit_log_trees,
	[SCOUTFS_NET_CMD_GET_ROOTS]		= server_get_roots,
	[SCOUTFS_NET_CMD_GET_LAST_SEQ]		= server_get_last_seq,
	[SCOUTFS_NET_CMD_LOCK]			= server_lock,
	[SCOUTFS_NET_CMD_SRCH_GET_COMPACT]	= server_srch_get_compact,
	[SCOUTFS_NET_CMD_SRCH_COMMIT_COMPACT]	= server_srch_commit_compact,
	[SCOUTFS_NET_CMD_GET_LOG_MERGE]		= server_get_log_merge,
	[SCOUTFS_NET_CMD_COMMIT_LOG_MERGE]	= server_commit_log_merge,
	[SCOUTFS_NET_CMD_OPEN_INO_MAP]		= server_open_ino_map,
	[SCOUTFS_NET_CMD_GET_VOLOPT]		= server_get_volopt,
	[SCOUTFS_NET_CMD_SET_VOLOPT]		= server_set_volopt,
	[SCOUTFS_NET_CMD_CLEAR_VOLOPT]		= server_clear_volopt,
	[SCOUTFS_NET_CMD_RESIZE_DEVICES]	= server_resize_devices,
	[SCOUTFS_NET_CMD_STATFS]		= server_statfs,
	[SCOUTFS_NET_CMD_FAREWELL]		= server_farewell,
};

static void server_notify_up(struct super_block *sb,
			     struct scoutfs_net_connection *conn,
			     void *info, u64 rid)
{
	struct server_client_info *sci = info;
	DECLARE_SERVER_INFO(sb, server);

	if (rid != 0) {
		sci->rid = rid;
		spin_lock(&server->lock);
		list_add_tail(&sci->head, &server->clients);
		server->nr_clients++;
		trace_scoutfs_server_client_up(sb, rid, server->nr_clients);
		spin_unlock(&server->lock);
	}
}

static void server_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       void *info, u64 rid)
{
	struct server_client_info *sci = info;
	DECLARE_SERVER_INFO(sb, server);

	if (rid != 0) {
		spin_lock(&server->lock);
		list_del_init(&sci->head);
		server->nr_clients--;
		trace_scoutfs_server_client_down(sb, rid,
						 server->nr_clients);
		spin_unlock(&server->lock);

		free_farewell_requests(sb, rid);
	} else {
		stop_server(server);
	}
}

/*
 * All clients have recovered all state.  Now we can kick all the work
 * that was waiting on recovery.
 *
 * It's a bit of a false dependency to have all work wait for completion
 * before any work can make progress, but recovery is naturally
 * concerned about in-memory state.  It should all be quick to recover
 * once a client arrives.
 */
static void finished_recovery(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);
	int ret = 0;

	scoutfs_info(sb, "all clients recovered");

	ret = scoutfs_omap_finished_recovery(sb) ?:
	      scoutfs_lock_server_finished_recovery(sb);
	if (ret < 0) {
		scoutfs_err(sb, "error %d resuming after recovery finished, shutting down", ret);
		stop_server(server);
	}
}

void scoutfs_server_recov_finish(struct super_block *sb, u64 rid, int which)
{
	DECLARE_SERVER_INFO(sb, server);

	if (scoutfs_recov_finish(sb, rid, which) > 0)
		finished_recovery(sb);

	/* rid's farewell response might be sent after it finishes lock recov */
	if (which & SCOUTFS_RECOV_LOCKS)
		queue_farewell_work(server);
}

/*
 * If the recovery timeout is too short we'll prematurely evict mounts
 * that would have recovered.  They need time to have their sockets
 * timeout, reconnect to the current server, and fully recover their
 * state.
 *
 * If it's too long we'll needlessly delay resuming operations after
 * clients crash and will never recover.
 */
#define SERVER_RECOV_TIMEOUT_MS (30 * MSEC_PER_SEC)

/*
 * Not all clients recovered in time.  We fence them and reclaim
 * whatever resources they were using.  If we see a rid here then we're
 * going to fence it, regardless of if it manages to finish recovery
 * while we're fencing it.
 */
static void fence_pending_recov_worker(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  fence_pending_recov_work);
	struct super_block *sb = server->sb;
	union scoutfs_inet_addr addr = {{0,}};
	u64 rid = 0;
	int ret = 0;

	while ((rid = scoutfs_recov_next_pending(sb, rid, SCOUTFS_RECOV_ALL)) > 0) {
		scoutfs_err(sb, "%lu ms recovery timeout expired for client rid %016llx, fencing",
			    SERVER_RECOV_TIMEOUT_MS, rid);

		ret = lookup_mounted_client_addr(sb, rid, &addr);
		if (ret < 0) {
			scoutfs_err(sb, "client rid addr lookup err %d, shutting down server", ret);
			break;
		}

		ret = scoutfs_fence_start(sb, rid, le32_to_be32(addr.v4.addr),
					  SCOUTFS_FENCE_CLIENT_RECOVERY);
		if (ret < 0) {
			scoutfs_err(sb, "fence returned err %d, shutting down server", ret);
			break;
		}
	}

	if (ret < 0)
		stop_server(server);
}

static void recovery_timeout(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	if (!server_is_stopping(server))
		queue_work(server->wq, &server->fence_pending_recov_work);
}

/*
 * As the server starts up it needs to start waiting for recovery from
 * any clients which were previously still mounted in the last running
 * server.  This is done before networking is started so we won't
 * receive any messages from clients until we've prepared them all.  If
 * the clients don't recover in time then they'll be fenced.
 */
static int start_recovery(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	SCOUTFS_BTREE_ITEM_REF(iref);
	struct scoutfs_key key;
	unsigned int nr = 0;
	u64 rid;
	int ret;

	for (rid = 0; ; rid++) {
		init_mounted_client_key(&key, rid);
		ret = scoutfs_btree_next(sb, &super->mounted_clients, &key, &iref);
		if (ret == -ENOENT) {
			ret = 0;
			break;
		}
		if (ret == 0) {
			rid = le64_to_cpu(iref.key->skmc_rid);
			scoutfs_btree_put_iref(&iref);
		}
		if (ret < 0)
			goto out;

		ret = scoutfs_recov_prepare(sb, rid, SCOUTFS_RECOV_ALL);
		if (ret < 0) {
			scoutfs_err(sb, "error %d preparing recovery for client rid %016llx, shutting down",
				     ret, rid);
			goto out;
		}

		nr++;
	}

	if (nr > 0) {
		scoutfs_info(sb, "waiting for %u clients to recover", nr);

		ret = scoutfs_recov_begin(sb, recovery_timeout, SERVER_RECOV_TIMEOUT_MS);
		if (ret > 0) {
			finished_recovery(sb);
			ret = 0;
		}
	}

out:
	if (ret < 0) {
		scoutfs_err(sb, "error %d starting recovery, shutting down", ret);
		stop_server(server);
	}
	return ret;
}

static void queue_reclaim_work(struct server_info *server, unsigned long delay)
{
	if (!server_is_stopping(server))
		queue_delayed_work(server->wq, &server->reclaim_dwork, delay);
}

#define RECLAIM_WORK_DELAY_MS	MSEC_PER_SEC

/*
 * Fencing is performed by userspace and can happen as we're elected
 * leader before the server is running.  Once we're running we want to
 * reclaim resources from any mounts that may have been fenced.
 *
 * The reclaim worker runs regularly in the background and reclaims the
 * resources for mounts that have been fenced.  Once the fenced rid has
 * been reclaimed the fence request can be removed.
 *
 * This is queued by the server work as it starts up, requeues itself
 * until shutdown, and is then canceled by the server work as it shuts
 * down.
 */
static void reclaim_worker(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info, reclaim_dwork.work);
	struct super_block *sb = server->sb;
	bool error;
	int reason;
	u64 rid;
	int ret;

	ret = scoutfs_fence_next(sb, &rid, &reason, &error);
	if (ret < 0)
		goto out;

	if (error == true) {
		scoutfs_err(sb, "saw error indicator on fence request for rid %016llx, shutting down server",
			    rid);
		stop_server(server);
		ret = -ESHUTDOWN;
		goto out;
	}

	ret = reclaim_rid(sb, rid);
	if (ret < 0) {
		scoutfs_err(sb, "failure to reclaim fenced rid %016llx: err %d, shutting down server",
			    rid, ret);
		stop_server(server);
		goto out;
	}

	scoutfs_info(sb, "successfully reclaimed resources for fenced rid %016llx", rid);
	scoutfs_fence_free(sb, rid);
	scoutfs_server_recov_finish(sb, rid, SCOUTFS_RECOV_ALL);

	ret = 0;
out:
	/* queue next reclaim immediately if we're making progress */
	if (ret == 0)
		queue_reclaim_work(server, 0);
	else
		queue_reclaim_work(server, msecs_to_jiffies(RECLAIM_WORK_DELAY_MS));
}

static void scoutfs_server_worker(struct work_struct *work)
{
	struct server_info *server = container_of(work, struct server_info,
						  work);
	struct super_block *sb = server->sb;
	struct scoutfs_super_block *super = DIRTY_SUPER_SB(sb);
	struct scoutfs_net_connection *conn = NULL;
	struct scoutfs_mount_options opts;
	DECLARE_WAIT_QUEUE_HEAD(waitq);
	struct sockaddr_in sin;
	bool alloc_init = false;
	u64 max_seq;
	int ret;

	trace_scoutfs_server_work_enter(sb, 0, 0);

	scoutfs_options_read(sb, &opts);
	scoutfs_quorum_slot_sin(&server->qconf, opts.quorum_slot_nr, &sin);
	scoutfs_info(sb, "server starting at "SIN_FMT, SIN_ARG(&sin));

	scoutfs_block_writer_init(sb, &server->wri);
	server->finalize_sent_seq = 0;

	/* first make sure no other servers are still running */
	ret = scoutfs_quorum_fence_leaders(sb, &server->qconf, server->term);
	if (ret < 0) {
		scoutfs_err(sb, "server error %d attempting to fence previous leaders", ret);
		goto out;
	}

	conn = scoutfs_net_alloc_conn(sb, server_notify_up, server_notify_down,
				      sizeof(struct server_client_info),
				      server_req_funcs, "server");
	if (!conn) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_net_bind(sb, conn, &sin);
	if (ret) {
		scoutfs_err(sb, "server failed to bind to "SIN_FMT", err %d%s",
			    SIN_ARG(&sin), ret,
			    ret == -EADDRNOTAVAIL ? " (Bad address?)"
						  : "");
		goto out;
	}

	/* start up the server subsystems before accepting */
	ret = scoutfs_read_super(sb, super);
	if (ret < 0) {
		scoutfs_err(sb, "server error %d reading super block", ret);
		goto shutdown;
	}

	/* update volume options early, possibly for use during startup */
	write_seqlock(&server->seqlock);
	server->volopt = super->volopt;
	write_sequnlock(&server->seqlock);

	atomic64_set(&server->seq_atomic, le64_to_cpu(super->seq));
	set_stable_super(server, super);

	/* prepare server alloc for this transaction, larger first */
	if (le64_to_cpu(super->server_meta_avail[0].total_nr) <
	    le64_to_cpu(super->server_meta_avail[1].total_nr))
		server->other_ind = 0;
	else
		server->other_ind = 1;
	scoutfs_alloc_init(&server->alloc,
			   &super->server_meta_avail[server->other_ind ^ 1],
			   &super->server_meta_freed[server->other_ind ^ 1]);
	alloc_init = true;
	server->other_avail = &super->server_meta_avail[server->other_ind];
	server->other_freed = &super->server_meta_freed[server->other_ind];

	/* use largest meta_alloc to start */
	server->meta_avail = &super->meta_alloc[0];
	server->meta_freed = &super->meta_alloc[1];
	if (le64_to_cpu(server->meta_freed->total_len) >
	    le64_to_cpu(server->meta_avail->total_len))
		swap(server->meta_avail, server->meta_freed);

	ret = scoutfs_forest_get_max_seq(sb, super, &max_seq);
	if (ret) {
		scoutfs_err(sb, "server couldn't find max item seq: %d", ret);
		goto shutdown;
	}
	scoutfs_server_set_seq_if_greater(sb, max_seq);

	ret = scoutfs_lock_server_setup(sb);
	if (ret) {
		scoutfs_err(sb, "server error %d starting lock server", ret);
		goto shutdown;
	}

	ret = start_recovery(sb);
	if (ret) {
		scoutfs_err(sb, "server error %d starting client recovery", ret);
		goto shutdown;
	}

	/* start accepting connections and processing work */
	server->conn = conn;
	scoutfs_net_listen(sb, conn);

	scoutfs_info(sb, "server ready at "SIN_FMT, SIN_ARG(&sin));
	server_up(server);

	queue_reclaim_work(server, 0);

	/* interruptible mostly to avoid stuck messages */
	wait_event_interruptible(server->waitq, server_is_stopping(server));

shutdown:
	scoutfs_info(sb, "server shutting down at "SIN_FMT, SIN_ARG(&sin));

	/* wait for farewell to finish sending messages */
	flush_work(&server->farewell_work);
	cancel_delayed_work_sync(&server->reclaim_dwork);

	/* wait for requests to finish, no more requests */
	scoutfs_net_shutdown(sb, conn);
	server->conn = NULL;

	flush_work(&server->log_merge_free_work);

	/* stop tracking recovery, cancel timer, flush any fencing */
	scoutfs_recov_shutdown(sb);
	flush_work(&server->fence_pending_recov_work);

	/* wait for extra queues by requests, won't find waiters */
	flush_work(&server->commit_work);

	if (alloc_init)
		scoutfs_alloc_prepare_commit(sb, &server->alloc, &server->wri);

	scoutfs_block_writer_forget_all(sb, &server->wri);

	scoutfs_lock_server_destroy(sb);
	scoutfs_omap_server_shutdown(sb);

out:
	scoutfs_fence_stop(sb);
	scoutfs_net_free_conn(sb, conn);

	server_down(server);

	scoutfs_info(sb, "server stopped at "SIN_FMT, SIN_ARG(&sin));
	trace_scoutfs_server_work_exit(sb, 0, ret);
}

/*
 * Start the server but don't wait for it to complete.
 */
void scoutfs_server_start(struct super_block *sb, struct scoutfs_quorum_config *qconf, u64 term)
{
	DECLARE_SERVER_INFO(sb, server);

	if (cmpxchg(&server->status, SERVER_DOWN, SERVER_STARTING) == SERVER_DOWN) {
		server->qconf = *qconf;
		server->term = term;
		queue_work(server->wq, &server->work);
	}
}

/*
 * Start shutdown on the server but don't want for it to finish.
 */
void scoutfs_server_stop(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	stop_server(server);
}

/*
 * Start shutdown on the server and wait for it to finish.
 */
void scoutfs_server_stop_wait(struct super_block *sb)
{
	DECLARE_SERVER_INFO(sb, server);

	stop_server(server);
	flush_work(&server->work);
}

int scoutfs_server_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct server_info *server = NULL;

	server = kzalloc(sizeof(struct server_info), GFP_KERNEL);
	if (!server)
		return -ENOMEM;

	server->sb = sb;
	spin_lock_init(&server->lock);
	seqlock_init(&server->seqlock);
	init_waitqueue_head(&server->waitq);
	INIT_WORK(&server->work, scoutfs_server_worker);
	server->status = SERVER_DOWN;
	init_commit_users(&server->cusers);
	INIT_WORK(&server->commit_work, scoutfs_server_commit_func);
	INIT_LIST_HEAD(&server->clients);
	spin_lock_init(&server->farewell_lock);
	INIT_LIST_HEAD(&server->farewell_requests);
	INIT_WORK(&server->farewell_work, farewell_worker);
	mutex_init(&server->alloc_mutex);
	mutex_init(&server->logs_mutex);
	INIT_WORK(&server->log_merge_free_work, server_log_merge_free_work);
	mutex_init(&server->srch_mutex);
	mutex_init(&server->mounted_clients_mutex);
	mutex_init(&server->volopt_mutex);
	INIT_WORK(&server->fence_pending_recov_work, fence_pending_recov_worker);
	INIT_DELAYED_WORK(&server->reclaim_dwork, reclaim_worker);

	server->wq = alloc_workqueue("scoutfs_server",
				     WQ_UNBOUND | WQ_NON_REENTRANT, 0);
	if (!server->wq) {
		kfree(server);
		return -ENOMEM;
	}

	sbi->server_info = server;
	return 0;
}

/*
 * The caller should have already stopped but we do the same just in
 * case.
 */
void scoutfs_server_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct server_info *server = sbi->server_info;

	if (server) {
		stop_server(server);

		/* wait for server work to wait for everything to shut down */
		cancel_work_sync(&server->work);
		/* farewell work triggers commits */
		cancel_work_sync(&server->farewell_work);
		/* recv work/compaction could have left commit_work queued */
		cancel_work_sync(&server->commit_work);

		/* pending farewell requests are another server's problem */
		free_farewell_requests(sb, 0);

		trace_scoutfs_server_workqueue_destroy(sb, 0, 0);
		destroy_workqueue(server->wq);

		kfree(server);
		sbi->server_info = NULL;
	}
}
