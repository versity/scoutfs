/*
 * Copyright (C) 2021 Versity Software, Inc.  All rights reserved.
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
#include <linux/sched.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>
#include <linux/list_sort.h>

#include "super.h"
#include "recov.h"
#include "cmp.h"

/*
 * There are a few server messages which can't be processed until they
 * know that they have state for all possibly active clients.  These
 * little helpers track which clients have recovered what state and give
 * those message handlers a call to check if recovery has completed.  We
 * track the timeout here, but all we do is call back into the server to
 * take steps to evict timed out clients and then let us know that their
 * recovery has finished.
 */

struct recov_info {
	struct super_block *sb;
	spinlock_t lock;
	struct list_head pending;
	struct timer_list timer;
	void (*timeout_fn)(struct super_block *);
};

#define DECLARE_RECOV_INFO(sb, name) \
	struct recov_info *name = SCOUTFS_SB(sb)->recov_info

struct recov_pending {
	struct list_head head;
	u64 rid;
	int which;
};

static struct recov_pending *next_pending(struct recov_info *recinf, u64 rid, int which)
{
	struct recov_pending *pend;

	list_for_each_entry(pend, &recinf->pending, head) {
		if (pend->rid > rid && pend->which & which)
			return pend;
	}

	return NULL;
}

static struct recov_pending *lookup_pending(struct recov_info *recinf, u64 rid, int which)
{
	struct recov_pending *pend;

	pend = next_pending(recinf, rid - 1, which);
	if (pend && pend->rid == rid)
		return pend;

	return NULL;
}

/*
 * We keep the pending list sorted by rid so that we can iterate over
 * them.  The list should be small and shouldn't be used often.
 */
static int cmp_pending_rid(void *priv, struct list_head *A, struct list_head *B)
{
	struct recov_pending *a = list_entry(A, struct recov_pending, head);
	struct recov_pending *b = list_entry(B, struct recov_pending, head);

	return scoutfs_cmp_u64s(a->rid, b->rid);
}

/*
 * Record that we'll be waiting for a client to recover something.
 * _finished will eventually be called for every _prepare, either
 * because recovery naturally finished or because it timed out and the
 * server evicted the client. 
 */
int scoutfs_recov_prepare(struct super_block *sb, u64 rid, int which)
{
	DECLARE_RECOV_INFO(sb, recinf);
	struct recov_pending *alloc;
	struct recov_pending *pend;

	if (WARN_ON_ONCE(which & SCOUTFS_RECOV_INVALID))
		return -EINVAL;

	alloc = kmalloc(sizeof(*pend), GFP_NOFS);
	if (!alloc)
		return -ENOMEM;

	spin_lock(&recinf->lock);

	pend = lookup_pending(recinf, rid, SCOUTFS_RECOV_ALL);
	if (pend) {
		pend->which |= which;
	} else {
		swap(pend, alloc);
		pend->rid = rid;
		pend->which = which;
		list_add_tail(&pend->head, &recinf->pending);
		list_sort(NULL, &recinf->pending, cmp_pending_rid);
	}

	spin_unlock(&recinf->lock);

	kfree(alloc);
	return 0;
}

/*
 * Recovery is only finished once we've begun (which sets the timer) and
 * all clients have finished.  If we didn't test the timer we could
 * claim it finished prematurely as clients are being prepared.
 */
static int recov_finished(struct recov_info *recinf)
{
	return !!(recinf->timeout_fn != NULL && list_empty(&recinf->pending));
}

static void timer_callback(struct timer_list *timer)
{
	struct recov_info *recinf = from_timer(recinf, timer, timer);

	recinf->timeout_fn(recinf->sb);
}

/*
 * Begin waiting for recovery once we've prepared all the clients.  If
 * the timeout period elapses before _finish is called on all prepared
 * clients then the timer will call the callback.
 *
 * Returns > 0 if all the prepared clients finish recovery before begin
 * is called.
 */
int scoutfs_recov_begin(struct super_block *sb, void (*timeout_fn)(struct super_block *),
			unsigned int timeout_ms)
{
	DECLARE_RECOV_INFO(sb, recinf);
	int ret;

	spin_lock(&recinf->lock);

	recinf->timeout_fn = timeout_fn;
	recinf->timer.expires = jiffies + msecs_to_jiffies(timeout_ms);
	add_timer(&recinf->timer);

	ret = recov_finished(recinf);

	spin_unlock(&recinf->lock);

	if (ret > 0)
		del_timer_sync(&recinf->timer);

	return ret;
}

/*
 * A given client has recovered the given state.  If it's finished all
 * recovery then we free it, and if all clients have finished recovery
 * then we cancel the timeout timer.
 *
 * Returns > 0 if _begin has been called and all clients have finished.
 * The caller will only see > 0 returned once.
 */
int scoutfs_recov_finish(struct super_block *sb, u64 rid, int which)
{
	DECLARE_RECOV_INFO(sb, recinf);
	struct recov_pending *pend;
	int ret = 0;

	spin_lock(&recinf->lock);

	pend = lookup_pending(recinf, rid, which);
	if (pend) {
		pend->which &= ~which;
		if (pend->which) {
			pend = NULL;
		} else {
			list_del(&pend->head);
			ret = recov_finished(recinf);
		}
	}

	spin_unlock(&recinf->lock);

	if (ret > 0)
		del_timer_sync(&recinf->timer);

	kfree(pend);

	return ret;
}

/*
 * Returns true if the given client is still trying to recover
 * the given state.
 */
bool scoutfs_recov_is_pending(struct super_block *sb, u64 rid, int which)
{
	DECLARE_RECOV_INFO(sb, recinf);
	bool is_pending;

	spin_lock(&recinf->lock);
	is_pending = lookup_pending(recinf, rid, which) != NULL;
	spin_unlock(&recinf->lock);

	return is_pending;
}

/*
 * Return the next rid after the given rid of a client waiting for the
 * given state to be recovered.  Start with rid 0, returns 0 when there
 * are no more clients waiting for recovery.
 *
 * This is inherently racey.  Callers are responsible for resolving any
 * actions taken based on pending with the recovery finishing, perhaps
 * before we return.
 */
u64 scoutfs_recov_next_pending(struct super_block *sb, u64 rid, int which)
{
	DECLARE_RECOV_INFO(sb, recinf);
	struct recov_pending *pend;

	spin_lock(&recinf->lock);
	pend = next_pending(recinf, rid, which);
	rid = pend ? pend->rid : 0;
	spin_unlock(&recinf->lock);

	return rid;
}

/*
 * The server is shutting down and doesn't need to worry about recovery
 * anymore.  It'll be built up again by the next server, if needed.
 */
void scoutfs_recov_shutdown(struct super_block *sb)
{
	DECLARE_RECOV_INFO(sb, recinf);
	struct recov_pending *pend;
	struct recov_pending *tmp;
	LIST_HEAD(list);

	del_timer_sync(&recinf->timer);

	spin_lock(&recinf->lock);
	list_splice_init(&recinf->pending, &list);
	recinf->timeout_fn = NULL;
	spin_unlock(&recinf->lock);

	list_for_each_entry_safe(pend, tmp, &recinf->pending, head) {
		list_del(&pend->head);
		kfree(pend);
	}
}

int scoutfs_recov_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct recov_info *recinf;
	int ret;

	recinf = kzalloc(sizeof(struct recov_info), GFP_KERNEL);
	if (!recinf) {
		ret = -ENOMEM;
		goto out;
	}

	recinf->sb = sb;
	spin_lock_init(&recinf->lock);
	INIT_LIST_HEAD(&recinf->pending);
	timer_setup(&recinf->timer, timer_callback, 0);

	sbi->recov_info = recinf;
	ret = 0;
out:
	return ret;
}

void scoutfs_recov_destroy(struct super_block *sb)
{
	DECLARE_RECOV_INFO(sb, recinf);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (recinf) {
		scoutfs_recov_shutdown(sb);

		kfree(recinf);
		sbi->recov_info = NULL;
	}
}
