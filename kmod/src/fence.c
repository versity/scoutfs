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
#include <linux/sched.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/timer.h>
#include <asm/barrier.h>

#include "super.h"
#include "msg.h"
#include "sysfs.h"
#include "server.h"
#include "fence.h"

/*
 * Fencing ensures that a given mount can no longer write to the
 * metadata or data devices.  It's necessary to ensure that it's safe to
 * give another mount access to a resource that is currently owned by a
 * mount that has stopped responding.
 *
 * Fencing is performed in collaboration between the currently elected
 * quorum leader mount and userspace running on its host.  The kernel
 * creates fencing requests as it notices that mounts have stopped
 * participating.  The fence requests are published as directories in
 * sysfs.  Userspace agents watch for directories, take action, and
 * write to files in the directory to indicate that the mount has been
 * fenced.  Once the mount is fenced the server can reclaim the
 * resources previously held by the fenced mount.
 *
 * The fence requests contain metadata identifying the specific instance
 * of the mount that needs to be fenced.  This lets a fencing agent
 * ensure that a specific mount has been fenced without necessarily
 * destroying the node that was hosting it.  Maybe the node had rebooted
 * and the mount is no longer there, maybe the mount can be force
 * unmounted, maybe the node can be configured to isolate the mount from
 * the devices.
 *
 * The fencing mechanism is asynchronous and can fail but the server
 * cannot make progress until it completes.  If a fence request times
 * out the server shuts down in the hope that another instance of a
 * server might have more luck fencing a non-responsive mount.
 *
 * Sources of fencing are fundamentally anchored in shared persistent
 * state.  It is possible, though unlikely, that servers can fence a
 * node and then themselves fail, leaving the next server to try and
 * fence the mount again.
 */

struct fence_info {
	struct kset *kset;
	struct kobject fence_dir_kobj;
	struct workqueue_struct *wq;
	wait_queue_head_t waitq;
	spinlock_t lock;
	struct list_head list;
};

#define DECLARE_FENCE_INFO(sb, name) \
	struct fence_info *name = SCOUTFS_SB(sb)->fence_info

struct pending_fence {
	struct super_block *sb;
	struct scoutfs_sysfs_attrs ssa;
	struct list_head entry;
	struct timer_list timer;

	ktime_t start_kt;
	__be32 ipv4_addr;
	bool fenced;
	bool error;
	int reason;
	u64 rid;
};

#define FENCE_FROM_KOBJ(kobj)					\
	container_of(SCOUTFS_SYSFS_ATTRS(kobj), struct pending_fence, ssa)
#define DECLARE_FENCE_FROM_KOBJ(name, kobj)				\
	struct pending_fence *name = FENCE_FROM_KOBJ(kobj)

static void destroy_fence(struct pending_fence *fence)
{
	struct super_block *sb = fence->sb;

	scoutfs_sysfs_destroy_attrs(sb, &fence->ssa);
	del_timer_sync(&fence->timer);
	kfree(fence);
}

static ssize_t elapsed_secs_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);
	ktime_t now = ktime_get();
	struct timeval tv = { 0, };

	if (ktime_after(now, fence->start_kt))
		tv = ktime_to_timeval(ktime_sub(now, fence->start_kt));

	return snprintf(buf, PAGE_SIZE, "%llu", (long long)tv.tv_sec);
}
SCOUTFS_ATTR_RO(elapsed_secs);

static ssize_t fenced_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);

	return snprintf(buf, PAGE_SIZE, "%u", !!fence->fenced);
}

/*
 * any write to the fenced file from userspace indicates that the mount
 * has been safely fenced and can no longer write to the shared device.
 */
static ssize_t fenced_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);
	DECLARE_FENCE_INFO(fence->sb, fi);

	if (!fence->fenced) {
		del_timer_sync(&fence->timer);
		fence->fenced = true;
		wake_up(&fi->waitq);
	}

	return count;
}
SCOUTFS_ATTR_RW(fenced);

static ssize_t error_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);

	return snprintf(buf, PAGE_SIZE, "%u", !!fence->error);
}

/*
 * Fencing can tell us that they were unable to fence the given mount.
 * We can't continue if the mount can't be isolated so we shut down the
 * server.
 */
static ssize_t error_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf,
			   size_t count)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);
	struct super_block *sb = fence->sb;
	DECLARE_FENCE_INFO(fence->sb, fi);

	if (!fence->error) {
		fence->error = true;
		scoutfs_err(sb, "error indicated by fence action for rid %016llx", fence->rid);
		wake_up(&fi->waitq);
	}

	return count;
}
SCOUTFS_ATTR_RW(error);

static ssize_t ipv4_addr_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);

	return snprintf(buf, PAGE_SIZE, "%pI4", &fence->ipv4_addr);
}
SCOUTFS_ATTR_RO(ipv4_addr);

static ssize_t reason_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);
	unsigned r = fence->reason;
	char *str = "unknown";
	static char *reasons[] = {
		[SCOUTFS_FENCE_CLIENT_RECOVERY] = "client_recovery",
		[SCOUTFS_FENCE_CLIENT_RECONNECT] = "client_reconnect",
		[SCOUTFS_FENCE_QUORUM_BLOCK_LEADER] = "quorum_block_leader",
	};

	if (r < ARRAY_SIZE(reasons) && reasons[r])
		str = reasons[r];

	return snprintf(buf, PAGE_SIZE, "%s", str);
}
SCOUTFS_ATTR_RO(reason);

static ssize_t rid_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	DECLARE_FENCE_FROM_KOBJ(fence, kobj);

	return snprintf(buf, PAGE_SIZE, "%016llx", fence->rid);
}
SCOUTFS_ATTR_RO(rid);

static struct attribute *fence_attrs[] = {
	SCOUTFS_ATTR_PTR(elapsed_secs),
	SCOUTFS_ATTR_PTR(fenced),
	SCOUTFS_ATTR_PTR(error),
	SCOUTFS_ATTR_PTR(ipv4_addr),
	SCOUTFS_ATTR_PTR(reason),
	SCOUTFS_ATTR_PTR(rid),
	NULL,
};

#define FENCE_TIMEOUT_MS (MSEC_PER_SEC * 30)

static void fence_timeout(struct timer_list *timer)
{
	struct pending_fence *fence = from_timer(fence, timer, timer);
	struct super_block *sb = fence->sb;
	DECLARE_FENCE_INFO(sb, fi);

	fence->error = true;
	scoutfs_err(sb, "fence request for rid %016llx was not serviced in %lums, raising error",
		    fence->rid, FENCE_TIMEOUT_MS);
	wake_up(&fi->waitq);
}

int scoutfs_fence_start(struct super_block *sb, u64 rid, __be32 ipv4_addr, int reason)
{
	DECLARE_FENCE_INFO(sb, fi);
	struct pending_fence *fence;
	int ret;

	fence = kzalloc(sizeof(struct pending_fence), GFP_NOFS);
	if (!fence) {
		ret = -ENOMEM;
		goto out;
	}

	fence->sb = sb;
	scoutfs_sysfs_init_attrs(sb, &fence->ssa);

	fence->start_kt = ktime_get();
	fence->ipv4_addr = ipv4_addr;
	fence->fenced = false;
	fence->error = false;
	fence->reason = reason;
	fence->rid = rid;

	ret = scoutfs_sysfs_create_attrs_parent(sb, &fi->kset->kobj,
						&fence->ssa, fence_attrs,
						"%016llx", rid);
	if (ret < 0) {
		kfree(fence);
		goto out;
	}

	timer_setup(&fence->timer, fence_timeout, 0);
	fence->timer.expires = jiffies + msecs_to_jiffies(FENCE_TIMEOUT_MS);
	add_timer(&fence->timer);

	spin_lock(&fi->lock);
	list_add_tail(&fence->entry, &fi->list);
	spin_unlock(&fi->lock);
out:
	return ret;
}

/*
 * Give the caller the rid of the next fence request which has been
 * fenced.  This doesn't have a position from which to return the next
 * because the caller either frees the fence request it's given or shuts
 * down.
 */
int scoutfs_fence_next(struct super_block *sb, u64 *rid, int *reason, bool *error)
{
	DECLARE_FENCE_INFO(sb, fi);
	struct pending_fence *fence;
	int ret = -ENOENT;

	spin_lock(&fi->lock);
	list_for_each_entry(fence, &fi->list, entry) {
		if (fence->fenced || fence->error) {
			*rid = fence->rid;
			*reason = fence->reason;
			*error = fence->error;
			ret = 0;
			break;
		}
	}
	spin_unlock(&fi->lock);

	return ret;
}

int scoutfs_fence_reason_pending(struct super_block *sb, int reason)
{
	DECLARE_FENCE_INFO(sb, fi);
	struct pending_fence *fence;
	bool pending = false;

	spin_lock(&fi->lock);
	list_for_each_entry(fence, &fi->list, entry) {
		if (fence->reason == reason) {
			pending = true;
			break;
		}
	}
	spin_unlock(&fi->lock);

	return pending;
}

int scoutfs_fence_free(struct super_block *sb, u64 rid)
{
	DECLARE_FENCE_INFO(sb, fi);
	struct pending_fence *fence;
	int ret = -ENOENT;

	spin_lock(&fi->lock);
	list_for_each_entry(fence, &fi->list, entry) {
		if (fence->rid == rid) {
			list_del_init(&fence->entry);
			ret = 0;
			break;
		}
	}
	spin_unlock(&fi->lock);

	if (ret == 0) {
		destroy_fence(fence);
		wake_up(&fi->waitq);
	}

	return ret;
}

static bool all_fenced(struct fence_info *fi, bool *error)
{
	struct pending_fence *fence;
	bool all = true;

	*error = false;

	spin_lock(&fi->lock);
	list_for_each_entry(fence, &fi->list, entry) {
		if (fence->error) {
			*error = true;
			all = true;
			break;
		}
		if (!fence->fenced) {
			all = false;
			break;
		}
	}
	spin_unlock(&fi->lock);

	return all;
}

/*
 * The caller waits for all the current requests to be fenced, but not
 * necessarily reclaimed.
 */
int scoutfs_fence_wait_fenced(struct super_block *sb, long timeout_jiffies)
{
	DECLARE_FENCE_INFO(sb, fi);
	bool error;
	long ret;

	ret = wait_event_timeout(fi->waitq, all_fenced(fi, &error), timeout_jiffies);
	if (ret == 0)
		ret = -ETIMEDOUT;
	else if (ret > 0)
		ret = 0;
	else if (error)
		ret = -EIO;

	return ret;
}

/*
 * This must be called early during startup so that it is guaranteed that
 * no other subsystems will try and call fence_start while we're waiting
 * for testing fence requests to complete.
 */
int scoutfs_fence_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct mount_options *opts = &sbi->opts;
	struct fence_info *fi;
	int ret;

	/* can only fence if we can be elected by quorum */
	if (opts->quorum_slot_nr == -1) {
		ret = 0;
		goto out;
	}

	fi = kzalloc(sizeof(struct fence_info), GFP_KERNEL);
	if (!fi) {
		ret = -ENOMEM;
		goto out;
	}

	init_waitqueue_head(&fi->waitq);
	spin_lock_init(&fi->lock);
	INIT_LIST_HEAD(&fi->list);

	sbi->fence_info = fi;

	fi->kset = kset_create_and_add("fence", NULL, scoutfs_sysfs_sb_dir(sb));
	if (!fi->kset) {
		ret = -ENOMEM;
		goto out;
	}

	fi->wq = alloc_workqueue("scoutfs_fence",
				 WQ_UNBOUND | WQ_NON_REENTRANT, 0);
	if (!fi->wq) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;
out:
	if (ret)
		scoutfs_fence_destroy(sb);

	return ret;
}

/*
 * Tear down all pending fence requests because the server is shutting down.
 */
void scoutfs_fence_stop(struct super_block *sb)
{
	DECLARE_FENCE_INFO(sb, fi);
	struct pending_fence *fence;

	do {
		spin_lock(&fi->lock);
		fence = list_first_entry_or_null(&fi->list, struct pending_fence, entry);
		if (fence)
			list_del_init(&fence->entry);
		spin_unlock(&fi->lock);

		if (fence) {
			destroy_fence(fence);
			wake_up(&fi->waitq);
		}
	} while (fence);
}

void scoutfs_fence_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct fence_info *fi = SCOUTFS_SB(sb)->fence_info;
	struct pending_fence *fence;
	struct pending_fence *tmp;

	if (fi) {
		if (fi->wq)
			destroy_workqueue(fi->wq);
		list_for_each_entry_safe(fence, tmp, &fi->list, entry)
			destroy_fence(fence);
		if (fi->kset)
			kset_unregister(fi->kset);
		kfree(fi);
		sbi->fence_info = NULL;
	}
}
