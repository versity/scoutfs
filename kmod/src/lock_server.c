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

#include "format.h"
#include "counters.h"
#include "net.h"
#include "tseq.h"
#include "spbm.h"
#include "block.h"
#include "msg.h"
#include "scoutfs_trace.h"
#include "lock_server.h"
#include "recov.h"

/*
 * The scoutfs server implements a simple lock service.  Client mounts
 * request access to locks identified by a key.  The server ensures that
 * access mode exclusion is properly enforced.
 *
 * The server processing paths are implemented in network message
 * receive processing callbacks.  We're receiving either a grant request
 * or an invalidation response.  These processing callbacks are fully
 * concurrent.  Our grant responses and invalidation requests are sent
 * from these contexts.
 *
 * We separate the locking of the global index of tracked locks from the
 * locking of a lock's state.  This allows concurrent work on unrelated
 * locks and lets processing block sending responses to unresponsive
 * clients without affecting other locks.
 *
 * Correctness of the protocol relies on the client and server each only
 * sending one request at a time for a given lock.  The server won't
 * process a request from a client until its outstanding invalidation
 * requests for the lock to other clients have been completed.  The
 * server specifies both the old mode and new mode when sending messages
 * to the client.  This lets the client resolve possible reordering when
 * processing incoming grant responses and invalidation requests.  The
 * server doesn't use the modes specified by the clients but they're
 * provided to add context.
 *
 * The server relies on the client's static rid and on reliable
 * messaging.  Each client has a rid that is unique for its life time.
 * Message requests and responses are reliably delivered in order across
 * reconnection.
 *
 * As a new server comes up it recovers lock state from existing clients
 * which were connected to a previous lock server.  Recover requests are
 * sent to clients as they connect and they respond with all there
 * locks.  Once all clients and locks are accounted for normal
 * processing can resume.
 *
 * The lock server doesn't respond to memory pressure.  The only way
 * locks are freed is if they are invalidated to null on behalf of a
 * conflicting request, clients specifically request a null mode, or the
 * server shuts down.
 */

#define LOCK_SERVER_RECOVERY_MS	(10 * MSEC_PER_SEC)

struct lock_server_info {
	struct super_block *sb;

	spinlock_t lock;
	struct rb_root locks_root;

	struct scoutfs_tseq_tree tseq_tree;
	struct dentry *tseq_dentry;
	struct scoutfs_tseq_tree stats_tseq_tree;
	struct dentry *stats_tseq_dentry;
};

#define DECLARE_LOCK_SERVER_INFO(sb, name) \
	struct lock_server_info *name = SCOUTFS_SB(sb)->lock_server_info

/*
 * The state of a lock on the server is a function of the state of the
 * locks on all clients.
 *
 * @granted:
 * granted or trigger invalidation of previously granted.
 * The state of a lock on the server is a function of messages that have
 * been sent and received from clients on behalf of a given lock.
 *
 * While the invalidated list has entries, which means invalidation
 * messages are still in flight, no more requests will be processed.
 */
struct server_lock_node {
	atomic_t refcount;
	struct mutex mutex;
	struct rb_node node;
	struct scoutfs_key key;

	struct list_head granted;
	struct list_head requested;
	struct list_head invalidated;

	struct scoutfs_tseq_entry stats_tseq_entry;
	u64 stats[SLT_NR];
};

/*
 * Interactions with the client are tracked with these little mode
 * wrappers.
 *
 * @entry: The client mode's entry on one of the server lock lists indicating
 * that the mode is actively granted, a pending request from the client,
 * or a pending invalidation sent to the client.
 *
 * @rid: The client's rid used to send messages and tear down
 * state as client's exit.
 *
 * @net_id: The id of a client's request used to send grant responses.  The
 * id of invalidation requests sent to clients that could be used to cancel
 * the message.
 *
 * @mode: the mode that is granted to the client, that the client
 * requested, or that the server is asserting with a pending
 * invalidation request message.
 */
struct client_lock_entry {
	struct list_head head;
	u64 rid;
	u64 net_id;
	u8 mode;

	struct server_lock_node *snode;
	struct scoutfs_tseq_entry tseq_entry;
	u8 on_list;
};

enum {
	OL_GRANTED = 0,
	OL_REQUESTED,
	OL_INVALIDATED,
};

/*
 * Put an entry on a server lock's list while being careful to move or
 * add the list head and while maintaining debugging info.
 */
static void add_client_entry(struct server_lock_node *snode,
			     struct list_head *list,
			     struct client_lock_entry *c_ent)
{
	WARN_ON_ONCE(!mutex_is_locked(&snode->mutex));

	if (list_empty(&c_ent->head))
		list_add_tail(&c_ent->head, list);
	else
		list_move_tail(&c_ent->head, list);

	c_ent->on_list = list == &snode->granted ? OL_GRANTED :
			 list == &snode->requested ? OL_REQUESTED :
			 OL_INVALIDATED;
}

static void free_client_entry(struct lock_server_info *inf,
			      struct server_lock_node *snode,
			      struct client_lock_entry *c_ent)
{
	WARN_ON_ONCE(!mutex_is_locked(&snode->mutex));

	if (!list_empty(&c_ent->head))
		list_del_init(&c_ent->head);
	scoutfs_tseq_del(&inf->tseq_tree, &c_ent->tseq_entry);
	kfree(c_ent);
}

static bool invalid_mode(u8 mode)
{
	return mode >= SCOUTFS_LOCK_INVALID;
}

/*
 * Return the mode that we should invalidate a granted lock down to
 * given an incompatible requested mode.  Usually we completely
 * invalidate the items because incompatible requests have to be writers
 * and our cache will then be stale, but the single exception is
 * invalidating down to a read lock having held a write lock because the
 * cache is still valid for reads after being written out.
 */
static u8 invalidation_mode(u8 granted, u8 requested)
{
	if (granted == SCOUTFS_LOCK_WRITE && requested == SCOUTFS_LOCK_READ)
		return SCOUTFS_LOCK_READ;

	return SCOUTFS_LOCK_NULL;
}

/*
 * Return true of the client lock instances described by the entries can
 * be granted at the same time.  There's only three cases where this is
 * true.
 *
 * First, the two locks are both of the same mode that allows full
 * sharing -- read and write only.  The only point of these modes is
 * that everyone can share them.
 *
 * Second, a write lock gives the client permission to read as well.
 * This means that a client can upgrade its read lock to a write lock
 * without having to invalidate the existing read and drop caches.
 *
 * Third, null locks are always compatible between clients.  It's as
 * though the client with the null lock has no lock at all.  But it's
 * never compatible with all locks on the client requesting null.
 * Sending invalidations for existing locks on a client when we get a
 * null request is how we resolve races in shrinking locks -- we turn it
 * into the unsolicited remote invalidation case.
 *
 * All other mode and client combinations can not be shared, most
 * typically a write lock invalidating all other non-write holders to
 * drop caches and force a read after the write has completed.
 */
static bool client_entries_compatible(struct client_lock_entry *granted,
				      struct client_lock_entry *requested)
{
	/* only read and write_only can be full shared */
	if ((granted->mode == requested->mode) &&
	    (granted->mode == SCOUTFS_LOCK_READ || granted->mode == SCOUTFS_LOCK_WRITE_ONLY))
		return true;

	/* _write includes reading, so a client can upgrade its read to write */
	if (granted->rid == requested->rid &&
	    granted->mode == SCOUTFS_LOCK_READ &&
	    requested->mode == SCOUTFS_LOCK_WRITE)
		return true;

	/* null is always compatible across clients, never within a client */
	if ((granted->rid != requested->rid) &&
	    (granted->mode == SCOUTFS_LOCK_NULL || requested->mode == SCOUTFS_LOCK_NULL))
		return true;

	return false;
}

/*
 * Get a locked server lock, possibly inserting the caller's allocated
 * lock if we don't find one for the given key.  The server lock's mutex
 * is held on return and the caller must put the lock when they're done.
 */
static struct server_lock_node *get_server_lock(struct lock_server_info *inf,
						struct scoutfs_key *key,
						struct server_lock_node *ins,
						bool or_next)
{
	struct rb_root *root = &inf->locks_root;
	struct server_lock_node *ret = NULL;
	struct server_lock_node *next = NULL;
	struct server_lock_node *snode;
	struct rb_node *parent = NULL;
	struct rb_node **node;
	int cmp;

	spin_lock(&inf->lock);

	node = &root->rb_node;
	while (*node) {
		parent = *node;
		snode = container_of(*node, struct server_lock_node, node);

		cmp = scoutfs_key_compare(key, &snode->key);
		if (cmp < 0) {
			if (or_next)
				next = snode;
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			ret = snode;
			break;
		}
	}

	if (ret == NULL && ins) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, root);
		ret = ins;
	}

	if (ret == NULL && or_next && next)
		ret = next;

	if (ret)
		atomic_inc(&ret->refcount);

	spin_unlock(&inf->lock);

	if (ret)
		mutex_lock(&ret->mutex);

	return ret;
}

/* Get a server lock node, allocating if one doesn't exist.  Caller must put. */
static struct server_lock_node *alloc_server_lock(struct lock_server_info *inf,
						  struct scoutfs_key *key)
{
	struct server_lock_node *snode;
	struct server_lock_node *ins;

	snode = get_server_lock(inf, key, NULL, false);
	if (snode == NULL) {
		ins = kzalloc(sizeof(struct server_lock_node), GFP_NOFS);
		if (ins) {
			atomic_set(&ins->refcount, 0);
			mutex_init(&ins->mutex);
			ins->key = *key;
			INIT_LIST_HEAD(&ins->granted);
			INIT_LIST_HEAD(&ins->requested);
			INIT_LIST_HEAD(&ins->invalidated);

			snode = get_server_lock(inf, key, ins, false);
			if (snode != ins)
				kfree(ins);
			else
				scoutfs_tseq_add(&inf->stats_tseq_tree, &snode->stats_tseq_entry);
		}
	}

	return snode;
}

/*
 * Finish with a server lock which has the mutex held, freeing it if
 * it's empty and unused.
 */
static void put_server_lock(struct lock_server_info *inf,
			    struct server_lock_node *snode)
{
	bool should_free = false;

	BUG_ON(!mutex_is_locked(&snode->mutex));

	spin_lock(&inf->lock);

	if (atomic_dec_and_test(&snode->refcount) &&
	    list_empty(&snode->granted) &&
	    list_empty(&snode->requested) &&
	    list_empty(&snode->invalidated)) {
		rb_erase(&snode->node, &inf->locks_root);
		should_free = true;
	}

	spin_unlock(&inf->lock);

	mutex_unlock(&snode->mutex);

	if (should_free) {
		scoutfs_tseq_del(&inf->stats_tseq_tree, &snode->stats_tseq_entry);
		kfree(snode);
	}
}

static struct client_lock_entry *find_entry(struct server_lock_node *snode,
					    struct list_head *list,
					    u64 rid)
{
	struct client_lock_entry *c_ent;

	WARN_ON_ONCE(!mutex_is_locked(&snode->mutex));

	list_for_each_entry(c_ent, list, head) {
		if (c_ent->rid == rid)
			return c_ent;
	}

	return NULL;
}

static int process_waiting_requests(struct super_block *sb,
				    struct server_lock_node *snode);

/*
 * The server is receiving an incoming request from a client.  We queue
 * it on the lock and process it.
 *
 * XXX shut down if we get enomem?
 */
int scoutfs_lock_server_request(struct super_block *sb, u64 rid,
				u64 net_id, struct scoutfs_net_lock *nl)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct client_lock_entry *c_ent;
	struct server_lock_node *snode;
	int ret;

	trace_scoutfs_lock_message(sb, SLT_SERVER, SLT_GRANT, SLT_REQUEST,
				   rid, net_id, nl);

	if (invalid_mode(nl->old_mode) || invalid_mode(nl->new_mode)) {
		ret = -EINVAL;
		goto out;
	}

	c_ent = kzalloc(sizeof(struct client_lock_entry), GFP_NOFS);
	if (!c_ent) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&c_ent->head);
	c_ent->rid = rid;
	c_ent->net_id = net_id;
	c_ent->mode = nl->new_mode;

	snode = alloc_server_lock(inf, &nl->key);
	if (snode == NULL) {
		kfree(c_ent);
		ret = -ENOMEM;
		goto out;
	}

	snode->stats[SLT_REQUEST]++;

	c_ent->snode = snode;
	add_client_entry(snode, &snode->requested, c_ent);
	scoutfs_tseq_add(&inf->tseq_tree, &c_ent->tseq_entry);

	ret = process_waiting_requests(sb, snode);
out:
	return ret;
}

/*
 * The server is receiving an invalidation response from the client.
 * Find the client's entry on the server lock's invalidation list and
 * free it so that request processing might be able to make forward
 * progress.
 *
 * XXX what to do with errors?  kick the client?
 */
int scoutfs_lock_server_response(struct super_block *sb, u64 rid,
				 struct scoutfs_net_lock *nl)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct client_lock_entry *c_ent;
	struct server_lock_node *snode;
	int ret;

	trace_scoutfs_lock_message(sb, SLT_SERVER, SLT_INVALIDATE, SLT_RESPONSE,
				   rid, 0, nl);

	if (invalid_mode(nl->old_mode) || invalid_mode(nl->new_mode)) {
		ret = -EINVAL;
		goto out;
	}

	/* XXX should always have a server lock here? */
	snode = get_server_lock(inf, &nl->key, NULL, false);
	if (!snode) {
		ret = -EINVAL;
		goto out;
	}

	snode->stats[SLT_RESPONSE]++;

	c_ent = find_entry(snode, &snode->invalidated, rid);
	if (!c_ent) {
		put_server_lock(inf, snode);
		ret = -EINVAL;
		goto out;
	}

	if (nl->new_mode == SCOUTFS_LOCK_NULL) {
		free_client_entry(inf, snode, c_ent);
	} else {
		c_ent->mode = nl->new_mode;
		add_client_entry(snode, &snode->granted, c_ent);
	}

	ret = process_waiting_requests(sb, snode);
out:
	return ret;
}

/*
 * Make forward progress on a lock by checking each waiting request in
 * the order that they were received.  If the next request is compatible
 * with all the clients' grants then the request is granted and a
 * response is sent.
 *
 * Invalidation requests are sent for every client grant that is
 * incompatible with the next request.  We won't process the next
 * request again until we receive all the invalidation responses.  Once
 * they're all received then the request can be processed and will be
 * compatible with the remaining grants.
 *
 * This is called with the snode mutex held.  This can free the snode if
 * it's empty.  The caller can't reference the snode once this returns
 * so we unlock the snode mutex.
 *
 * All progress must wait for all clients to finish with recovery
 * because we don't know which locks they'll hold.  Once recover
 * finishes the server calls us to kick all the locks that were waiting
 * during recovery.
 */
static int process_waiting_requests(struct super_block *sb,
				    struct server_lock_node *snode)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct scoutfs_net_lock nl;
	struct client_lock_entry *req;
	struct client_lock_entry *req_tmp;
	struct client_lock_entry *gr;
	struct client_lock_entry *gr_tmp;
	u64 seq;
	int ret;

	BUG_ON(!mutex_is_locked(&snode->mutex));

	/* processing waits for all invalidation responses or recovery */
	if (!list_empty(&snode->invalidated) ||
	    scoutfs_recov_next_pending(sb, 0, SCOUTFS_RECOV_LOCKS) != 0) {
		ret = 0;
		goto out;
	}

	/* walk through pending requests in order received */
	list_for_each_entry_safe(req, req_tmp, &snode->requested, head) {

		/* send invalidation to any incompatible grants */
		list_for_each_entry_safe(gr, gr_tmp, &snode->granted, head) {
			if (client_entries_compatible(gr, req))
				continue;

			nl.key = snode->key;
			nl.old_mode = gr->mode;
			nl.new_mode = invalidation_mode(gr->mode, req->mode);

			ret = scoutfs_server_lock_request(sb, gr->rid, &nl);
			if (ret)
				goto out;

			trace_scoutfs_lock_message(sb, SLT_SERVER,
						   SLT_INVALIDATE, SLT_REQUEST,
						   gr->rid, 0, &nl);
			snode->stats[SLT_INVALIDATE]++;

			add_client_entry(snode, &snode->invalidated, gr);
		}

		/* wait for any newly sent invalidations */
		if (!list_empty(&snode->invalidated))
			break;

		nl.key = snode->key;
		nl.new_mode = req->mode;
		nl.write_seq = 0;

		/* see if there's an existing compatible grant to replace */
		gr = find_entry(snode, &snode->granted, req->rid);
		if (gr) {
			nl.old_mode = gr->mode;
			free_client_entry(inf, snode, gr);
		} else {
			nl.old_mode = SCOUTFS_LOCK_NULL;
		}

		if (nl.new_mode == SCOUTFS_LOCK_WRITE ||
		    nl.new_mode == SCOUTFS_LOCK_WRITE_ONLY) {
			/* doesn't commit seq update, recovered with locks */
			seq = scoutfs_server_next_seq(sb);
			nl.write_seq = cpu_to_le64(seq);
		}

		ret = scoutfs_server_lock_response(sb, req->rid,
						   req->net_id, &nl);
		if (ret)
			goto out;

		trace_scoutfs_lock_message(sb, SLT_SERVER, SLT_GRANT,
					   SLT_RESPONSE, req->rid,
					   req->net_id, &nl);
		snode->stats[SLT_GRANT]++;

		/* don't track null client locks, track all else */ 
		if (req->mode == SCOUTFS_LOCK_NULL)
			free_client_entry(inf, snode, req);
		else
			add_client_entry(snode, &snode->granted, req);
	}

	ret = 0;
out:
	put_server_lock(inf, snode);

	return ret;
}

/*
 * The server received a greeting from a client for the first time.  If
 * the client is in lock recovery then we send the initial lock request.
 *
 * This is running in concurrent client greeting processing contexts.
 */
int scoutfs_lock_server_greeting(struct super_block *sb, u64 rid)
{
	struct scoutfs_key key;
	int ret;

	if (scoutfs_recov_is_pending(sb, rid, SCOUTFS_RECOV_LOCKS)) {
		scoutfs_key_set_zeros(&key);
		ret = scoutfs_server_lock_recover_request(sb, rid, &key);
	} else {
		ret = 0;
	}

	return ret;
}

/*
 * All clients have finished lock recovery, we can make forward process
 * on all the queued requests that were waiting on recovery.
 */
int scoutfs_lock_server_finished_recovery(struct super_block *sb)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct server_lock_node *snode;
	struct scoutfs_key key;
	int ret = 0;

	scoutfs_key_set_zeros(&key);
	while ((snode = get_server_lock(inf, &key, NULL, true))) {

		key = snode->key;
		scoutfs_key_inc(&key);

		if (!list_empty(&snode->requested)) {
			ret = process_waiting_requests(sb, snode);
			if (ret)
				break;
		} else {
			put_server_lock(inf, snode);
		}
	}

	return ret;
}

/*
 * We sent a lock recover request to the client when we received its
 * greeting while in recovery.  Here we instantiate all the locks it
 * gave us in response and send another request from the next key.
 * We're done once we receive an empty response.
 */
int scoutfs_lock_server_recover_response(struct super_block *sb, u64 rid,
					 struct scoutfs_net_lock_recover *nlr)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct client_lock_entry *existing;
	struct client_lock_entry *c_ent;
	struct server_lock_node *snode;
	struct scoutfs_key key;
	int ret = 0;
	int i;

	/* client must be in recovery */
	if (!scoutfs_recov_is_pending(sb, rid, SCOUTFS_RECOV_LOCKS)) {
		ret = -EINVAL;
		goto out;
	}

	/* client has sent us all their locks */
	if (nlr->nr == 0) {
		scoutfs_server_recov_finish(sb, rid, SCOUTFS_RECOV_LOCKS);
		ret = 0;
		goto out;
	}

	for (i = 0; i < le16_to_cpu(nlr->nr); i++) {
		c_ent = kzalloc(sizeof(struct client_lock_entry), GFP_NOFS);
		if (!c_ent) {
			ret = -ENOMEM;
			goto out;
		}

		INIT_LIST_HEAD(&c_ent->head);
		c_ent->rid = rid;
		c_ent->net_id = 0;
		c_ent->mode = nlr->locks[i].new_mode;

		snode = alloc_server_lock(inf, &nlr->locks[i].key);
		if (snode == NULL) {
			kfree(c_ent);
			ret = -ENOMEM;
			goto out;
		}

		existing = find_entry(snode, &snode->granted, rid);
		if (existing) {
			kfree(c_ent);
			put_server_lock(inf, snode);
			ret = -EEXIST;
			goto out;
		}

		c_ent->snode = snode;
		add_client_entry(snode, &snode->granted, c_ent);
		scoutfs_tseq_add(&inf->tseq_tree, &c_ent->tseq_entry);

		put_server_lock(inf, snode);

		/* make sure next core seq is greater than all lock write seq */
		scoutfs_server_set_seq_if_greater(sb,
				le64_to_cpu(nlr->locks[i].write_seq));
	}

	/* send request for next batch of keys */
	key = nlr->locks[le16_to_cpu(nlr->nr) - 1].key;
	scoutfs_key_inc(&key);

	ret = scoutfs_server_lock_recover_request(sb, rid, &key);
out:
	return ret;
}

/*
 * A client is leaving the lock service.  They aren't using locks and
 * won't send any more requests.  We tear down all the state we had for
 * them.  This can be called multiple times for a given client as their
 * farewell is resent to new servers.  It's OK to not find any state.
 */
int scoutfs_lock_server_farewell(struct super_block *sb, u64 rid)
{
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct client_lock_entry *c_ent;
	struct client_lock_entry *tmp;
	struct server_lock_node *snode;
	struct scoutfs_key key;
	struct list_head *list;
	bool freed;
	int ret = 0;

	scoutfs_key_set_zeros(&key);
	while ((snode = get_server_lock(inf, &key, NULL, true))) {

		freed = false;
		for (list = &snode->granted; list != NULL;
		     list = (list == &snode->granted) ? &snode->requested :
			    (list == &snode->requested) ? &snode->invalidated :
			    NULL) {

			list_for_each_entry_safe(c_ent, tmp, list, head) {
				if (c_ent->rid == rid) {
					free_client_entry(inf, snode, c_ent);
					freed = true;
				}
			}
		}

		key = snode->key;
		scoutfs_key_inc(&key);

		if (freed) {
			ret = process_waiting_requests(sb, snode);
			if (ret)
				goto out;
		} else {
			put_server_lock(inf, snode);
		}
	}
	ret = 0;

out:
	if (ret < 0) {
		scoutfs_err(sb, "lock server err %d during client rid %016llx farewell, shutting down",
			    ret, rid);
		scoutfs_server_stop(sb);
	}

	return ret;
}

static char *lock_mode_string(u8 mode)
{
	static char *mode_strings[] = {
		[SCOUTFS_LOCK_NULL] = "null",
		[SCOUTFS_LOCK_READ] = "read",
		[SCOUTFS_LOCK_WRITE] = "write",
		[SCOUTFS_LOCK_WRITE_ONLY] = "write_only",
	};

	if (mode < ARRAY_SIZE(mode_strings) && mode_strings[mode])
		return mode_strings[mode];

	return "unknown";
}

static char *lock_on_list_string(u8 on_list)
{
	static char *on_list_strings[] = {
		[OL_GRANTED] = "granted",
		[OL_REQUESTED] = "requested",
		[OL_INVALIDATED] = "invalidated",
	};

	if (on_list < ARRAY_SIZE(on_list_strings) && on_list_strings[on_list])
		return on_list_strings[on_list];

	return "unknown";
}

static void lock_server_tseq_show(struct seq_file *m,
				  struct scoutfs_tseq_entry *ent)
{
	struct client_lock_entry *c_ent = container_of(ent,
						       struct client_lock_entry,
						       tseq_entry);
	struct server_lock_node *snode = c_ent->snode;

	seq_printf(m, SK_FMT" %s %s rid %016llx net_id %llu\n",
		   SK_ARG(&snode->key), lock_mode_string(c_ent->mode),
		   lock_on_list_string(c_ent->on_list), c_ent->rid,
		   c_ent->net_id);
}

static void stats_tseq_show(struct seq_file *m, struct scoutfs_tseq_entry *ent)
{
	struct server_lock_node *snode = container_of(ent, struct server_lock_node,
						      stats_tseq_entry);

	seq_printf(m, SK_FMT" req %llu inv %llu rsp %llu gr %llu\n",
		   SK_ARG(&snode->key), snode->stats[SLT_REQUEST], snode->stats[SLT_INVALIDATE],
		   snode->stats[SLT_RESPONSE], snode->stats[SLT_GRANT]);
}

/*
 * Setup the lock server.  This is called before networking can deliver
 * requests.
 */
int scoutfs_lock_server_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct lock_server_info *inf;

	inf = kzalloc(sizeof(struct lock_server_info), GFP_KERNEL);
	if (!inf)
		return -ENOMEM;

	inf->sb = sb;
	spin_lock_init(&inf->lock);
	inf->locks_root = RB_ROOT;
	scoutfs_tseq_tree_init(&inf->tseq_tree, lock_server_tseq_show);
	scoutfs_tseq_tree_init(&inf->stats_tseq_tree, stats_tseq_show);

	inf->tseq_dentry = scoutfs_tseq_create("server_locks", sbi->debug_root,
					       &inf->tseq_tree);
	if (!inf->tseq_dentry) {
		kfree(inf);
		return -ENOMEM;
	}

	inf->stats_tseq_dentry = scoutfs_tseq_create("server_lock_stats", sbi->debug_root,
						     &inf->stats_tseq_tree);
	if (!inf->stats_tseq_dentry) {
		debugfs_remove(inf->tseq_dentry);
		kfree(inf);
		return -ENOMEM;
	}

	sbi->lock_server_info = inf;

	return 0;
}

/*
 * The server will have shut down networking before stopping us so we
 * don't have to worry about message processing calls while we free.
 */
void scoutfs_lock_server_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_LOCK_SERVER_INFO(sb, inf);
	struct server_lock_node *snode;
	struct server_lock_node *stmp;
	struct client_lock_entry *c_ent;
	struct client_lock_entry *ctmp;
	LIST_HEAD(list);

	if (inf) {
		debugfs_remove(inf->tseq_dentry);
		debugfs_remove(inf->stats_tseq_dentry);

		rbtree_postorder_for_each_entry_safe(snode, stmp,
						     &inf->locks_root, node) {

			list_splice_init(&snode->granted, &list);
			list_splice_init(&snode->requested, &list);
			list_splice_init(&snode->invalidated, &list);

			mutex_lock(&snode->mutex);
			list_for_each_entry_safe(c_ent, ctmp, &list, head) {
				free_client_entry(inf, snode, c_ent);
			}
			mutex_unlock(&snode->mutex);

			kfree(snode);
		}

		kfree(inf);
		sbi->lock_server_info = NULL;
	}
}
