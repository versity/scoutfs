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

#include "format.h"
#include "counters.h"
#include "cmp.h"
#include "inode.h"
#include "client.h"
#include "server.h"
#include "omap.h"
#include "recov.h"
#include "scoutfs_trace.h"

/*
 * As a client removes an inode from its cache with an nlink of 0 it
 * needs to decide if it is the last client using the inode and should
 * fully delete all its items.  It needs to know if other mounts still
 * have the inode in use.
 *
 * We need a way to communicate between mounts that an inode is open.
 * We don't want to pay the synchronous per-file locking round trip
 * costs associated with per-inode open locks that you'd typically see
 * in systems to solve this problem.
 *
 * Instead clients maintain open bitmaps that cover groups of inodes.
 * As inodes enter the cache their bit is set, and as the inode is
 * evicted the bit is cleared.  As an inode is evicted messages are sent
 * around the cluster to get the current bitmaps for that inode's group
 * from all active mounts.  If the inode's bit is clear then it can be
 * deleted.
 *
 * We associate the open bitmaps with our cluster locking of inode
 * groups to cache these open bitmaps.  As long as we have the lock then
 * nlink can't be changed on any remote mounts.  Specifically, it can't
 * increase from 0 so any clear bits can gain references on remote
 * mounts.  As long as we have the lock, all clear bits in the group for
 * inodes with 0 nlink can be deleted.
 *
 * This layer maintains a list of client rids to send messages to.  The
 * server calls us as clients enter and leave the cluster.    We can't
 * process requests until all clients are present as a server starts up
 * so we hook into recovery and delay processing until all previously
 * existing clients are recovered or fenced.
 */

struct omap_rid_list {
	int nr_rids;
	struct list_head head;
};

struct omap_rid_entry {
	struct list_head head;
	u64 rid;
};

struct omap_info {
	/* client */
	struct rhashtable group_ht;

	/* server */
	struct rhashtable req_ht;
	struct llist_head requests;
	spinlock_t lock;
	struct omap_rid_list rids;
	atomic64_t next_req_id;
};

#define DECLARE_OMAP_INFO(sb, name) \
	struct omap_info *name = SCOUTFS_SB(sb)->omap_info

/*
 * The presence of an inode in the inode cache increases the count of
 * its inode number's position within its lock group.  These structs
 * track the counts for all the inodes in a lock group and maintain a
 * bitmap whose bits are set for each non-zero count.
 *
 * We don't want to add additional global synchronization of inode cache
 * maintenance so these are tracked in an rcu hash table.  Once their
 * total count reaches zero they're removed from the hash and queued for
 * freeing and readers should ignore them.
 */
struct omap_group {
	struct super_block *sb;
	struct rhash_head ht_head;
	struct rcu_head rcu;
	u64 nr;
	spinlock_t lock;
	unsigned int total;
	unsigned int *counts;
	__le64 bits[SCOUTFS_OPEN_INO_MAP_LE64S];
};

#define trace_group(sb, which, group, bit_nr)						\
do {											\
	__typeof__(group) _grp = (group);						\
	__typeof__(bit_nr) _nr = (bit_nr);						\
											\
	trace_scoutfs_omap_group_##which(sb, _grp, _grp->nr, _grp->total, _nr,		\
				        _nr < 0 ? -1 : _grp->counts[_nr]);		\
} while (0)

/*
 * Each request is initialized with the rids of currently mounted
 * clients.  As each responds we remove their rid and send the response
 * once everyone has contributed.
 *
 * The request frequency will typically be low, but in a mass rm -rf
 * load we will see O(groups * clients) messages flying around.
 */
struct omap_request {
	struct llist_node llnode;
	struct rhash_head ht_head;
	struct rcu_head rcu;
	spinlock_t lock;
	u64 client_rid;
	u64 client_id;
	struct omap_rid_list rids;
	struct scoutfs_open_ino_map map;
};

/*
 * In each inode group cluster lock we store data to track the open ino
 * map which tracks all the inodes that the cluster lock covers.  When
 * the seq shows that the map is stale we send a request to update it.
 */
struct scoutfs_omap_lock_data {
	u64 seq;
	bool req_in_flight;
	wait_queue_head_t waitq;
	struct scoutfs_open_ino_map map;
};

static inline void init_rid_list(struct omap_rid_list *list)
{
	INIT_LIST_HEAD(&list->head);
	list->nr_rids = 0;
}

/*
 * Negative searches almost never happen.
 */
static struct omap_rid_entry *find_rid(struct omap_rid_list *list, u64 rid)
{
	struct omap_rid_entry *entry;

	list_for_each_entry(entry, &list->head, head) {
		if (rid == entry->rid)
			return entry;
	}

	return NULL;
}

static int free_rid(struct omap_rid_list *list, struct omap_rid_entry *entry)
{
	int nr;

	list_del(&entry->head);
	nr = --list->nr_rids;

	kfree(entry);
	return nr;
}

static int copy_rids(struct omap_rid_list *to, struct omap_rid_list *from, spinlock_t *from_lock)
{
	struct omap_rid_entry *entry;
	struct omap_rid_entry *src;
	struct omap_rid_entry *dst;
	int nr;

	spin_lock(from_lock);

	while (to->nr_rids != from->nr_rids) {
		nr = from->nr_rids;
		spin_unlock(from_lock);

		while (to->nr_rids < nr) {
			entry = kmalloc(sizeof(struct omap_rid_entry), GFP_NOFS);
			if (!entry)
				return -ENOMEM;

			list_add_tail(&entry->head, &to->head);
			to->nr_rids++;
		}

		while (to->nr_rids > nr) {
			entry = list_first_entry(&to->head, struct omap_rid_entry, head);
			list_del(&entry->head);
			kfree(entry);
			to->nr_rids--;
		}

		spin_lock(from_lock);
	}

	dst = list_first_entry(&to->head, struct omap_rid_entry, head);
	list_for_each_entry(src, &from->head, head) {
		dst->rid = src->rid;
		dst = list_next_entry(dst, head);
	}

	spin_unlock(from_lock);

	return 0;
}

static void free_rids(struct omap_rid_list *list)
{
	struct omap_rid_entry *entry;
	struct omap_rid_entry *tmp;

	list_for_each_entry_safe(entry, tmp, &list->head, head) {
		list_del(&entry->head);
		kfree(entry);
	}
}

static void calc_group_nrs(u64 ino, u64 *group_nr, int *bit_nr)
{
	*group_nr = ino >> SCOUTFS_OPEN_INO_MAP_SHIFT;
	*bit_nr = ino & SCOUTFS_OPEN_INO_MAP_MASK;
}

static struct omap_group *alloc_group(struct super_block *sb, u64 group_nr)
{
	struct omap_group *group;

	BUILD_BUG_ON((sizeof(group->counts[0]) * SCOUTFS_OPEN_INO_MAP_BITS) > PAGE_SIZE);

	group = kzalloc(sizeof(struct omap_group), GFP_NOFS);
	if (group) {
		group->sb = sb;
		group->nr = group_nr;
		spin_lock_init(&group->lock);

		group->counts = (void *)get_zeroed_page(GFP_NOFS);
		if (!group->counts) {
			kfree(group);
			group = NULL;
		} else {
			trace_group(sb, alloc, group, -1);
		}
	}

	return group;
}

static void free_group(struct super_block *sb, struct omap_group *group)
{
	trace_group(sb, free, group, -1);
	free_page((unsigned long)group->counts);
	kfree(group);
}

static void free_group_rcu(struct rcu_head *rcu)
{
	struct omap_group *group = container_of(rcu, struct omap_group, rcu);

	free_group(group->sb, group);
}

static const struct rhashtable_params group_ht_params = {
        .key_len = member_sizeof(struct omap_group, nr),
        .key_offset = offsetof(struct omap_group, nr),
        .head_offset = offsetof(struct omap_group, ht_head),
};

/*
 * Track an cached inode in its group.  Our increment can be racing with
 * a final decrement that removes the group from the hash, sets total to
 * UINT_MAX, and calls rcu free.  We can retry until the dead group is
 * no longer visible in the hash table and we can insert a new allocated
 * group.
 */
int scoutfs_omap_inc(struct super_block *sb, u64 ino)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct omap_group *group;
	u64 group_nr;
	int bit_nr;
	bool found;
	int ret = 0;

	calc_group_nrs(ino, &group_nr, &bit_nr);

retry:
	found = false;
	rcu_read_lock();
	group = rhashtable_lookup(&ominf->group_ht, &group_nr, group_ht_params);
	if (group) {
		spin_lock(&group->lock);
		if (group->total < UINT_MAX) {
			found = true;
			if (group->counts[bit_nr]++ == 0) {
				set_bit_le(bit_nr, group->bits);
				group->total++;
			}
		}
		trace_group(sb, inc, group, bit_nr);
		spin_unlock(&group->lock);
	}
	rcu_read_unlock();

	if (!found) {
		group = alloc_group(sb, group_nr);
		if (group) {
			ret = rhashtable_lookup_insert_fast(&ominf->group_ht, &group->ht_head,
							    group_ht_params);
			if (ret < 0)
				free_group(sb, group);
			if (ret == -EEXIST)
				ret = 0;
			if (ret == -EBUSY) {
				/* wait for rehash to finish */
				synchronize_rcu();
				ret = 0;
			}
			if (ret == 0)
				goto retry;
		} else {
			ret = -ENOMEM;
		}
	}

	return ret;
}

/*
 * Decrement a previously incremented ino count.  Not finding a count
 * implies imbalanced inc/dec or bugs freeing groups.  We only free
 * groups here as the last dec drops the group's total count to 0.
 */
void scoutfs_omap_dec(struct super_block *sb, u64 ino)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct omap_group *group;
	u64 group_nr;
	int bit_nr;

	calc_group_nrs(ino, &group_nr, &bit_nr);

	rcu_read_lock();
	group = rhashtable_lookup(&ominf->group_ht, &group_nr, group_ht_params);
	if (group) {
		spin_lock(&group->lock);
		WARN_ON_ONCE(group->counts[bit_nr] == 0);
		WARN_ON_ONCE(group->total == 0);
		WARN_ON_ONCE(group->total == UINT_MAX);
		if (--group->counts[bit_nr] == 0) {
			clear_bit_le(bit_nr, group->bits);
			if (--group->total == 0) {
				group->total = UINT_MAX;
				rhashtable_remove_fast(&ominf->group_ht, &group->ht_head,
						       group_ht_params);
				call_rcu(&group->rcu, free_group_rcu);
			}
		}
		trace_group(sb, dec, group, bit_nr);
		spin_unlock(&group->lock);
	}
	rcu_read_unlock();

	WARN_ON_ONCE(!group);
}

/*
 * The server adds rids as it discovers clients.  We add them to the
 * list of rids to send map requests to.
 */
int scoutfs_omap_add_rid(struct super_block *sb, u64 rid)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct omap_rid_entry *entry;
	struct omap_rid_entry *found;

	entry = kmalloc(sizeof(struct omap_rid_entry), GFP_NOFS);
	if (!entry)
		return -ENOMEM;

	spin_lock(&ominf->lock);
	found = find_rid(&ominf->rids, rid);
	if (!found) {
		entry->rid = rid;
		list_add_tail(&entry->head, &ominf->rids.head);
		ominf->rids.nr_rids++;
	}
	spin_unlock(&ominf->lock);

	if (found)
		kfree(entry);

	return 0;
}

static void free_req(struct omap_request *req)
{
	free_rids(&req->rids);
	kfree(req);
}

static void free_req_rcu(struct rcu_head *rcu)
{
	struct omap_request *req = container_of(rcu, struct omap_request, rcu);

	free_req(req);
}

static const struct rhashtable_params req_ht_params = {
        .key_len = member_sizeof(struct omap_request, map.args.req_id),
        .key_offset = offsetof(struct omap_request, map.args.req_id),
        .head_offset = offsetof(struct omap_request, ht_head),
};

/*
 * Remove a rid from all the pending requests.  If it's the last rid we
 * give the caller the details to send a response, they'll call back to
 * keep removing.  If their send fails they're going to shutdown the
 * server so we can queue freeing the request as we give it to them.
 */
static int remove_rid_from_reqs(struct omap_info *ominf, u64 rid, u64 *resp_rid, u64 *resp_id,
				struct scoutfs_open_ino_map *map)
{
	struct omap_rid_entry *entry;
	struct rhashtable_iter iter;
	struct omap_request *req;
	int ret = 0;

	rhashtable_walk_enter(&ominf->req_ht, &iter);
	rhashtable_walk_start(&iter);

	for (;;) {
		req = rhashtable_walk_next(&iter);
		if (req == NULL)
			break;
		if (req == ERR_PTR(-EAGAIN))
			continue;

		spin_lock(&req->lock);
		entry = find_rid(&req->rids, rid);
		if (entry && free_rid(&req->rids, entry) == 0) {
			*resp_rid = req->client_rid;
			*resp_id = req->client_id;
			memcpy(map, &req->map, sizeof(struct scoutfs_open_ino_map));
			rhashtable_remove_fast(&ominf->req_ht, &req->ht_head, req_ht_params);
			call_rcu(&req->rcu, free_req_rcu);
			ret = 1;
		}
		spin_unlock(&req->lock);
		if (ret > 0)
			break;
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	if (ret <= 0) {
		*resp_rid = 0;
		*resp_id = 0;
	}

	return ret;
}

/*
 * A client has been evicted.  Remove its rid from the list and walk
 * through all the pending requests and remove its rids, sending the
 * response if it was the last rid waiting for a response.
 *
 * If this returns an error then the server will shut down.
 *
 * This can be called multiple times by different servers if there are
 * errors reclaiming an evicted mount, so we allow asking to remove a
 * rid that hasn't been added.
 */
int scoutfs_omap_remove_rid(struct super_block *sb, u64 rid)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct scoutfs_open_ino_map *map = NULL;
	struct omap_rid_entry *entry;
	u64 resp_rid = 0;
	u64 resp_id = 0;
	int ret;

	spin_lock(&ominf->lock);
	entry = find_rid(&ominf->rids, rid);
	if (entry)
		free_rid(&ominf->rids, entry);
	spin_unlock(&ominf->lock);

	if (!entry) {
		ret = 0;
		goto out;
	}

	map = kmalloc(sizeof(struct scoutfs_open_ino_map), GFP_NOFS);
	if (!map) {
		ret = -ENOMEM;
		goto out;
	}

	/* remove the rid from all pending requests, sending responses if it was final */
	for (;;) {
		ret = remove_rid_from_reqs(ominf, rid, &resp_rid, &resp_id, map);
		if (ret <= 0)
			break;
		ret = scoutfs_server_send_omap_response(sb, resp_rid, resp_id, map, 0);
		if (ret < 0)
			break;
	}

out:
	kfree(map);
	return ret;
}

/*
 * Handle a single incoming request in the server.  This could have been
 * delayed by recovery.  This only returns an error if we couldn't send
 * a processing error response to the client.
 */
static int handle_request(struct super_block *sb, struct omap_request *req)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct omap_rid_list priv_rids;
	struct omap_rid_entry *entry;
	int ret;

	init_rid_list(&priv_rids);

	ret = copy_rids(&priv_rids, &ominf->rids, &ominf->lock);
	if (ret < 0)
		goto out;

	/* don't send a request to the client who originated this request */
	entry = find_rid(&priv_rids, req->client_rid);
	if (entry && free_rid(&priv_rids, entry) == 0) {
		ret = scoutfs_server_send_omap_response(sb, req->client_rid, req->client_id,
							&req->map, 0);
		kfree(req);
		req = NULL;
		goto out;
	}

	/* this lock isn't needed but sparse gave warnings with conditional locking */
	ret = copy_rids(&req->rids, &priv_rids, &ominf->lock);
	if (ret < 0)
		goto out;

	do {
		ret = rhashtable_insert_fast(&ominf->req_ht, &req->ht_head, req_ht_params);
		if (ret == -EBUSY)
			synchronize_rcu(); /* wait for rehash to finish */
	} while (ret == -EBUSY);

	if (ret < 0)
		goto out;

	/*
	 * We can start getting responses the moment we send the first response.  After
	 * we send the last request the req can be freed.
	 */
	while ((entry = list_first_entry_or_null(&priv_rids.head, struct omap_rid_entry, head))) {
		ret = scoutfs_server_send_omap_request(sb, entry->rid, &req->map.args);
		if (ret < 0) {
			rhashtable_remove_fast(&ominf->req_ht, &req->ht_head, req_ht_params);
			goto out;
		}

		free_rid(&priv_rids, entry);
	}

	ret = 0;
out:
	free_rids(&priv_rids);
	if (ret < 0) {
		ret = scoutfs_server_send_omap_response(sb, req->client_rid, req->client_id,
							NULL, ret);
		free_req(req);
	}

	/* it's fine if we couldn't send to a client that left */
	if (ret == -ENOTCONN)
		ret = 0;

	return ret;
}

/*
 * Handle all previously received omap requests from clients.  Once
 * we've finished recovery and can send requests to all clients we can
 * handle all pending requests.  The handling function frees the request
 * and only returns an error if it couldn't send a response to the
 * client.
 */
static int handle_requests(struct super_block *sb)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct llist_node *requests;
	struct omap_request *req;
	struct omap_request *tmp;
	int ret;
	int err;

	if (scoutfs_recov_next_pending(sb, 0, SCOUTFS_RECOV_GREETING))
		return 0;

	ret = 0;
	requests = llist_del_all(&ominf->requests);

	llist_for_each_entry_safe(req, tmp, requests, llnode) {
		err = handle_request(sb, req);
		if (err < 0 && ret == 0)
			ret = err;
	}

	return ret;
}

int scoutfs_omap_finished_recovery(struct super_block *sb)
{
	return handle_requests(sb);
}

/*
 * The server is receiving a request from a client for the bitmap of all
 * open inodes around their ino.  Queue it for processing which is
 * typically immediate and inline but which can be deferred by recovery
 * as the server first starts up.
 */
int scoutfs_omap_server_handle_request(struct super_block *sb, u64 rid, u64 id,
				       struct scoutfs_open_ino_map_args *args)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct omap_request *req;

	req = kzalloc(sizeof(struct omap_request), GFP_NOFS);
	if (req == NULL)
		return -ENOMEM;

	spin_lock_init(&req->lock);
	req->client_rid = rid;
	req->client_id = id;
	init_rid_list(&req->rids);
	req->map.args.group_nr = args->group_nr;
	req->map.args.req_id = cpu_to_le64(atomic64_inc_return(&ominf->next_req_id));

	llist_add(&req->llnode, &ominf->requests);

	return handle_requests(sb);
}

/*
 * The client is receiving a request from the server for its map for the
 * given group.  Look up the group and copy the bits to the map for
 * non-zero open counts.
 *
 * The mount originating the request for this bitmap has the inode group
 * write locked.  We can't be adding links to any inodes in the group
 * because that requires the lock.  Inodes bits can be set and cleared
 * while we're sampling the bitmap.  These races are fine, they can't be
 * adding cached inodes if nlink is 0 and we don't have the lock.  If
 * the caller is removing a set bit then they're about to try and delete
 * the inode themselves and will first have to acquire the cluster lock
 * themselves.
 */
int scoutfs_omap_client_handle_request(struct super_block *sb, u64 id,
				       struct scoutfs_open_ino_map_args *args)
{
	DECLARE_OMAP_INFO(sb, ominf);
	u64 group_nr = le64_to_cpu(args->group_nr);
	struct scoutfs_open_ino_map *map;
	struct omap_group *group;
	bool copied = false;
	int ret;

	map = kmalloc(sizeof(struct scoutfs_open_ino_map), GFP_NOFS);
	if (!map)
		return -ENOMEM;

	map->args = *args;

	rcu_read_lock();
	group = rhashtable_lookup(&ominf->group_ht, &group_nr, group_ht_params);
	if (group) {
		spin_lock(&group->lock);
		trace_group(sb, request, group, -1);
		if (group->total > 0 && group->total < UINT_MAX) {
			memcpy(map->bits, group->bits, sizeof(map->bits));
			copied = true;
		}
		spin_unlock(&group->lock);
	}
	rcu_read_unlock();

	if (!copied)
		memset(map->bits, 0, sizeof(map->bits));

	ret = scoutfs_client_send_omap_response(sb, id, map);
	kfree(map);
	return ret;
}

/*
 * The server has received an open ino map response from a client.  Find
 * the original request that it's serving, or in the response's map, and
 * send a reply if this was the last response from a client we were
 * waiting for.
 *
 * We can get responses for requests we're no longer tracking if, for
 * example, sending to a client gets an error.  We'll have already sent
 * the response to the requesting client so we drop these responses on
 * the floor.
 */
int scoutfs_omap_server_handle_response(struct super_block *sb, u64 rid,
					struct scoutfs_open_ino_map *resp_map)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct scoutfs_open_ino_map *map;
	struct omap_rid_entry *entry;
	bool send_response = false;
	struct omap_request *req;
	u64 resp_rid;
	u64 resp_id;
	int ret;

	map = kmalloc(sizeof(struct scoutfs_open_ino_map), GFP_NOFS);
	if (!map) {
		ret = -ENOMEM;
		goto out;
	}

	rcu_read_lock();
	req = rhashtable_lookup(&ominf->req_ht, &resp_map->args.req_id, req_ht_params);
	if (req) {
		spin_lock(&req->lock);
		entry = find_rid(&req->rids, rid);
		if (entry) {
			bitmap_or((unsigned long *)req->map.bits, (unsigned long *)req->map.bits,
				  (unsigned long *)resp_map->bits, SCOUTFS_OPEN_INO_MAP_BITS);
			if (free_rid(&req->rids, entry) == 0)
				send_response = true;
		}
		spin_unlock(&req->lock);

		if (send_response) {
			resp_rid = req->client_rid;
			resp_id = req->client_id;
			memcpy(map, &req->map, sizeof(struct scoutfs_open_ino_map));
			rhashtable_remove_fast(&ominf->req_ht, &req->ht_head, req_ht_params);
			call_rcu(&req->rcu, free_req_rcu);
		}
	}
	rcu_read_unlock();

	if (send_response)
		ret = scoutfs_server_send_omap_response(sb, resp_rid, resp_id, map, 0);
	else
		ret = 0;
	kfree(map);
out:
	return ret;
}

/*
 * The server is shutting down.  Free all the server state associated
 * with ongoing request processing.  Clients who still have requests
 * pending will resend them to the next server.
 */
void scoutfs_omap_server_shutdown(struct super_block *sb)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct rhashtable_iter iter;
	struct llist_node *requests;
	struct omap_request *req;
	struct omap_request *tmp;

	rhashtable_walk_enter(&ominf->req_ht, &iter);
	rhashtable_walk_start(&iter);

	for (;;) {
		req = rhashtable_walk_next(&iter);
		if (req == NULL)
			break;
		if (req == ERR_PTR(-EAGAIN))
			continue;

		if (req->rids.nr_rids != 0) {
			free_rids(&req->rids);
			rhashtable_remove_fast(&ominf->req_ht, &req->ht_head, req_ht_params);
			call_rcu(&req->rcu, free_req_rcu);
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	requests = llist_del_all(&ominf->requests);
	llist_for_each_entry_safe(req, tmp, requests, llnode)
		kfree(req);

	synchronize_rcu();
}

static bool omap_req_in_flight(struct scoutfs_lock *lock, struct scoutfs_omap_lock_data *ldata)
{
	bool in_flight;

	spin_lock(&lock->omap_spinlock);
	in_flight = ldata->req_in_flight;
	spin_unlock(&lock->omap_spinlock);

	return in_flight;
}

/*
 * Make sure the map covered by the cluster lock is current.  The caller
 * holds the cluster lock so once we store lock_data on the cluster lock
 * it won't be freed and the write_seq in the cluster lock won't change.
 *
 * The omap_spinlock protects the omap_data in the cluster lock.  We
 * have to drop it if we have to block to allocate lock_data, send a
 * request for a new map, or wait for a request in flight to finish.
 */
static int get_current_lock_data(struct super_block *sb, struct scoutfs_lock *lock,
				 struct scoutfs_omap_lock_data **ldata_ret, u64 group_nr)
{
	struct scoutfs_omap_lock_data *ldata;
	bool send_req;
	int ret = 0;

	spin_lock(&lock->omap_spinlock);

	ldata = lock->omap_data;
	if (ldata == NULL) {
		spin_unlock(&lock->omap_spinlock);
		ldata = kzalloc(sizeof(struct scoutfs_omap_lock_data), GFP_NOFS);
		spin_lock(&lock->omap_spinlock);

		if (!ldata) {
			ret = -ENOMEM;
			goto out;
		}

		if (lock->omap_data == NULL) {
			ldata->seq = lock->write_seq - 1; /* ensure refresh */
			init_waitqueue_head(&ldata->waitq);

			lock->omap_data = ldata;
		} else {
			kfree(ldata);
			ldata = lock->omap_data;
		}
	}

	while (ldata->seq != lock->write_seq) {
		/* only one waiter sends a request at a time */
		if (!ldata->req_in_flight) {
			ldata->req_in_flight = true;
			send_req = true;
		} else {
			send_req = false;
		}

		spin_unlock(&lock->omap_spinlock);
		if (send_req)
			ret = scoutfs_client_open_ino_map(sb, group_nr, &ldata->map);
		else
			wait_event(ldata->waitq, !omap_req_in_flight(lock, ldata));
		spin_lock(&lock->omap_spinlock);

		/* only sender can return error, other waiters retry */
		if (send_req) {
			ldata->req_in_flight = false;
			if (ret == 0)
				ldata->seq = lock->write_seq;
			wake_up(&ldata->waitq);
			if (ret < 0)
				goto out;
		}
	}

out:
	spin_unlock(&lock->omap_spinlock);

	if (ret == 0)
		*ldata_ret = ldata;
	else
		*ldata_ret = NULL;

	return ret;
}

/*
 * Return 1 and give the caller a write inode lock if it is safe to be
 * deleted.  It's safe to be deleted when it is no longer reachable and
 * nothing is referencing it.
 *
 * The inode is unreachable when nlink hits zero.  Cluster locks protect
 * modification and testing of nlink.  We use the ino_lock_cov covrage
 * to short circuit the common case of having a locked inode that hasn't
 * been deleted.  If it isn't locked, we have to acquire the lock to
 * refresh the inode to see its current nlink. 
 *
 * Then we use an open inode bitmap that covers all the inodes in the
 * lock group to determine if the inode is present in any other mount's
 * caches.  We refresh it by asking the server for all clients' maps and
 * then store it in the lock.  As long as we hold the lock nothing can
 * increase nlink from zero and let people get a reference to the inode.
 */
int scoutfs_omap_should_delete(struct super_block *sb, struct inode *inode,
			       struct scoutfs_lock **lock_ret)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct scoutfs_lock *lock = NULL;
	const u64 ino = scoutfs_ino(inode);
	struct scoutfs_omap_lock_data *ldata;
	u64 group_nr;
	int bit_nr;
	int ret;

	/* lock group and omap constants are defined independently */
	BUILD_BUG_ON(SCOUTFS_OPEN_INO_MAP_BITS != SCOUTFS_LOCK_INODE_GROUP_NR);

	if (scoutfs_lock_is_covered(sb, &si->ino_lock_cov) && inode->i_nlink > 0) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE, SCOUTFS_LKF_REFRESH_INODE, inode, &lock);
	if (ret < 0)
		goto out;

	if (inode->i_nlink > 0) {
		ret = 0;
		goto out;
	}

	calc_group_nrs(ino, &group_nr, &bit_nr);

	/* only one request to refresh the map at a time */
	ret = get_current_lock_data(sb, lock, &ldata, group_nr);
	if (ret < 0)
		goto out;

	/* can delete caller's zero nlink inode if it's not cached in other mounts */
	ret = !test_bit_le(bit_nr, ldata->map.bits);
out:
	trace_scoutfs_omap_should_delete(sb, ino, inode->i_nlink, ret);

	if (ret <= 0) {
		scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);
		lock = NULL;
	}

	*lock_ret = lock;
	return ret;
}

void scoutfs_omap_free_lock_data(struct scoutfs_omap_lock_data *ldata)
{
	if (ldata) {
		WARN_ON_ONCE(ldata->req_in_flight);
		WARN_ON_ONCE(waitqueue_active(&ldata->waitq));
		kfree(ldata);
	}
}

int scoutfs_omap_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct omap_info *ominf;
	int ret;

	ominf = kzalloc(sizeof(struct omap_info), GFP_KERNEL);
	if (!ominf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = rhashtable_init(&ominf->group_ht, &group_ht_params);
	if (ret < 0) {
		kfree(ominf);
		goto out;
	}

	ret = rhashtable_init(&ominf->req_ht, &req_ht_params);
	if (ret < 0) {
		rhashtable_destroy(&ominf->group_ht);
		kfree(ominf);
		goto out;
	}

	init_llist_head(&ominf->requests);
	spin_lock_init(&ominf->lock);
	init_rid_list(&ominf->rids);
	atomic64_set(&ominf->next_req_id, 0);

	sbi->omap_info = ominf;
	ret = 0;
out:
	return ret;
}

/*
 * To get here the server must have shut down, freeing requests, and
 * evict must have been called on all cached inodes so we can just
 * synchronize all the pending group frees.
 */
void scoutfs_omap_destroy(struct super_block *sb)
{
	DECLARE_OMAP_INFO(sb, ominf);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct rhashtable_iter iter;

	if (ominf) {
		synchronize_rcu();

		/* double check that all the groups deced to 0 and were freed */
		rhashtable_walk_enter(&ominf->group_ht, &iter);
		rhashtable_walk_start(&iter);
		WARN_ON_ONCE(rhashtable_walk_peek(&iter) != NULL);
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);

		rhashtable_destroy(&ominf->group_ht);
		rhashtable_destroy(&ominf->req_ht);
		kfree(ominf);
		sbi->omap_info = NULL;
	}
}
