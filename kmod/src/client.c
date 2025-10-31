/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
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
#include <asm/barrier.h>
#include <linux/overflow.h>

#include "format.h"
#include "counters.h"
#include "inode.h"
#include "btree.h"
#include "scoutfs_trace.h"
#include "msg.h"
#include "client.h"
#include "net.h"
#include "endian_swap.h"
#include "quorum.h"
#include "omap.h"
#include "trans.h"

/*
 * The client is responsible for maintaining a connection to the server.
 */

#define CLIENT_CONNECT_DELAY_MS		(MSEC_PER_SEC / 10)
#define CLIENT_CONNECT_TIMEOUT_MS	(1 * MSEC_PER_SEC)

struct client_info {
	struct super_block *sb;

	struct scoutfs_net_connection *conn;
	atomic_t shutting_down;

	struct workqueue_struct *workq;
	struct delayed_work connect_dwork;
	unsigned long connect_delay_jiffies;

	u64 server_term;

	bool sending_farewell;
	int farewell_error;
	struct completion farewell_comp;
};

/*
 * Ask for a new run of allocated inode numbers.  The server can return
 * fewer than @count.  It will success with nr == 0 if we've run out.
 */
int scoutfs_client_alloc_inodes(struct super_block *sb, u64 count,
				u64 *ino, u64 *nr)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_net_inode_alloc ial;
	__le64 lecount = cpu_to_le64(count);
	u64 tmp;
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
				       SCOUTFS_NET_CMD_ALLOC_INODES,
				       &lecount, sizeof(lecount),
				       &ial, sizeof(ial));
	if (ret == 0) {
		*ino = le64_to_cpu(ial.ino);
		*nr = le64_to_cpu(ial.nr);

		if (*nr == 0)
			ret = -ENOSPC;
		else if (check_add_overflow(*ino, *nr - 1, &tmp))
			ret = -EINVAL;
	}

	return ret;
}

int scoutfs_client_get_log_trees(struct super_block *sb,
				 struct scoutfs_log_trees *lt)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_GET_LOG_TREES,
					NULL, 0, lt, sizeof(*lt));
}

int scoutfs_client_commit_log_trees(struct super_block *sb,
				    struct scoutfs_log_trees *lt)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_COMMIT_LOG_TREES,
					lt, sizeof(*lt), NULL, 0);
}

int scoutfs_client_get_roots(struct super_block *sb,
			     struct scoutfs_net_roots *roots)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_GET_ROOTS,
					NULL, 0, roots, sizeof(*roots));
}

int scoutfs_client_get_last_seq(struct super_block *sb, u64 *seq)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	__le64 last_seq;
	int ret;

	ret = scoutfs_net_sync_request(sb, client->conn,
				       SCOUTFS_NET_CMD_GET_LAST_SEQ,
				       NULL, 0, &last_seq, sizeof(last_seq));
	if (ret == 0)
		*seq = le64_to_cpu(last_seq);

	return ret;
}

/* process an incoming grant response from the server */
static int client_lock_response(struct super_block *sb,
				struct scoutfs_net_connection *conn,
				void *resp, unsigned int resp_len,
				int error, void *data)
{
	if (resp_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	/* XXX error? */

	return scoutfs_lock_grant_response(sb, resp);
}

/* Send a lock request to the server. */
int scoutfs_client_lock_request(struct super_block *sb,
				struct scoutfs_net_lock *nl)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_submit_request(sb, client->conn,
					  SCOUTFS_NET_CMD_LOCK,
					  nl, sizeof(*nl),
					  client_lock_response, NULL, NULL);
}

/* Send a lock response to the server. */
int scoutfs_client_lock_response(struct super_block *sb, u64 net_id,
				struct scoutfs_net_lock *nl)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_response(sb, client->conn, SCOUTFS_NET_CMD_LOCK,
				    net_id, 0, nl, sizeof(*nl));
}

/* Send a lock recover response to the server. */
int scoutfs_client_lock_recover_response(struct super_block *sb, u64 net_id,
					 struct scoutfs_net_lock_recover *nlr)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	u16 bytes = offsetof(struct scoutfs_net_lock_recover,
			     locks[le16_to_cpu(nlr->nr)]);

	return scoutfs_net_response(sb, client->conn,
				    SCOUTFS_NET_CMD_LOCK_RECOVER,
				    net_id, 0, nlr, bytes);
}

/* Find srch files that need to be compacted. */
int scoutfs_client_srch_get_compact(struct super_block *sb,
				    struct scoutfs_srch_compact *sc)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_SRCH_GET_COMPACT,
					NULL, 0, sc, sizeof(*sc));
}

/* Commit the result of a srch file compaction. */
int scoutfs_client_srch_commit_compact(struct super_block *sb,
				       struct scoutfs_srch_compact *res)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_SRCH_COMMIT_COMPACT,
					res, sizeof(*res), NULL, 0);
}

int scoutfs_client_get_log_merge(struct super_block *sb,
				 struct scoutfs_log_merge_request *req)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_GET_LOG_MERGE,
					NULL, 0, req, sizeof(*req));
}

int scoutfs_client_commit_log_merge(struct super_block *sb,
				    struct scoutfs_log_merge_complete *comp)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn,
					SCOUTFS_NET_CMD_COMMIT_LOG_MERGE,
					comp, sizeof(*comp), NULL, 0);
}

int scoutfs_client_send_omap_response(struct super_block *sb, u64 id,
				      struct scoutfs_open_ino_map *map)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_response(sb, client->conn, SCOUTFS_NET_CMD_OPEN_INO_MAP,
				    id, 0, map, sizeof(*map));
}

/* The client is receiving an omap request from the server */
static int client_open_ino_map(struct super_block *sb, struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	if (arg_len != sizeof(struct scoutfs_open_ino_map_args))
		return -EINVAL;

	return scoutfs_omap_client_handle_request(sb, id, arg);
}

/* The client is sending an omap request to the server */
int scoutfs_client_open_ino_map(struct super_block *sb, u64 group_nr,
				struct scoutfs_open_ino_map *map)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_open_ino_map_args args = {
		.group_nr = cpu_to_le64(group_nr),
		.req_id = 0,
	};

	return scoutfs_net_sync_request(sb, client->conn, SCOUTFS_NET_CMD_OPEN_INO_MAP,
					&args, sizeof(args), map, sizeof(*map));
}

/* The client is asking the server for the current volume options */
int scoutfs_client_get_volopt(struct super_block *sb, struct scoutfs_volume_options *volopt)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn, SCOUTFS_NET_CMD_GET_VOLOPT,
					NULL, 0, volopt, sizeof(*volopt));
}

/* The client is asking the server to update volume options */
int scoutfs_client_set_volopt(struct super_block *sb, struct scoutfs_volume_options *volopt)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn, SCOUTFS_NET_CMD_SET_VOLOPT,
					volopt, sizeof(*volopt), NULL, 0);
}

/* The client is asking the server to clear volume options */
int scoutfs_client_clear_volopt(struct super_block *sb, struct scoutfs_volume_options *volopt)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn, SCOUTFS_NET_CMD_CLEAR_VOLOPT,
					volopt, sizeof(*volopt), NULL, 0);
}

int scoutfs_client_resize_devices(struct super_block *sb, struct scoutfs_net_resize_devices *nrd)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn, SCOUTFS_NET_CMD_RESIZE_DEVICES,
					nrd, sizeof(*nrd), NULL, 0);
}

int scoutfs_client_statfs(struct super_block *sb, struct scoutfs_net_statfs *nst)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	return scoutfs_net_sync_request(sb, client->conn, SCOUTFS_NET_CMD_STATFS,
					NULL, 0, nst, sizeof(*nst));
}

/*
 * The server is asking that we trigger a commit of the current log
 * trees so that they can ensure an item seq discontinuity between
 * finalized log btrees and the next set of open log btrees.  If we're
 * shutting down then we're already going to perform a final commit.
 */
static int sync_log_trees(struct super_block *sb, struct scoutfs_net_connection *conn,
			  u8 cmd, u64 id, void *arg, u16 arg_len)
{
	if (arg_len != 0)
		return -EINVAL;

	if (!scoutfs_unmounting(sb))
		scoutfs_trans_sync(sb, 0);

	return scoutfs_net_response(sb, conn, cmd, id, 0, NULL, 0);
}

/* The client is receiving a invalidation request from the server */
static int client_lock(struct super_block *sb,
		       struct scoutfs_net_connection *conn, u8 cmd, u64 id,
		       void *arg, u16 arg_len)
{
	if (arg_len != sizeof(struct scoutfs_net_lock))
		return -EINVAL;

	/* XXX error? */

	return scoutfs_lock_invalidate_request(sb, id, arg);
}

/* The server is asking us for the client's locks starting with the given key */
static int client_lock_recover(struct super_block *sb,
			       struct scoutfs_net_connection *conn,
			       u8 cmd, u64 id, void *arg, u16 arg_len)
{
	if (arg_len != sizeof(struct scoutfs_key))
		return -EINVAL;

	/* XXX error? */

	return scoutfs_lock_recover_request(sb, id, arg);
}

/*
 * Process a greeting response in the client from the server.  This is
 * called for every connected socket on the connection.  Each response
 * contains the remote server's elected term which can be used to
 * identify server failover.
 */
static int client_greeting(struct super_block *sb,
			   struct scoutfs_net_connection *conn,
			   void *resp, unsigned int resp_len, int error,
			   void *data)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct client_info *client = sbi->client_info;
	struct scoutfs_net_greeting *gr = resp;
	bool new_server;
	int ret;

	if (error) {
		ret = error;
		goto out;
	}

	if (resp_len != sizeof(struct scoutfs_net_greeting)) {
		ret = -EINVAL;
		goto out;
	}

	if (gr->fsid != cpu_to_le64(sbi->fsid)) {
		scoutfs_warn(sb, "server greeting response fsid 0x%llx did not match client fsid 0x%llx",
			     le64_to_cpu(gr->fsid), sbi->fsid);
		ret = -EINVAL;
		goto out;
	}

	if (le64_to_cpu(gr->fmt_vers) != sbi->fmt_vers) {
		scoutfs_warn(sb, "server greeting response format version %llu did not match client format version %llu",
			     le64_to_cpu(gr->fmt_vers), sbi->fmt_vers);
		ret = -EINVAL;
		goto out;
	}

	new_server = le64_to_cpu(gr->server_term) != client->server_term;
	scoutfs_net_client_greeting(sb, conn, new_server);

	client->server_term = le64_to_cpu(gr->server_term);
	client->connect_delay_jiffies = 0;
	ret = 0;
out:
	return ret;
}

/*
 * The client is deciding if it needs to keep trying to reconnect to
 * have its farewell request processed.  The server removes our mounted
 * client item last so that if we don't see it we know the server has
 * processed our farewell and we don't need to reconnect, we can unmount
 * safely.
 *
 * This is peeking at btree blocks that the server could be actively
 * freeing with cow updates so it can see stale blocks, we just return
 * the error and we'll retry eventually as the connection times out.
 */
static int lookup_mounted_client_item(struct super_block *sb, u64 rid)
{
	struct scoutfs_key key = {
		.sk_zone = SCOUTFS_MOUNTED_CLIENT_ZONE,
		.skmc_rid = cpu_to_le64(rid),
	};
	struct scoutfs_super_block *super;
	SCOUTFS_BTREE_ITEM_REF(iref);
	int ret;

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	if (!super) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_read_super(sb, super);
	if (ret)
		goto out;

	ret = scoutfs_btree_lookup(sb, &super->mounted_clients, &key, &iref);
	if (ret == 0) {
		scoutfs_btree_put_iref(&iref);
		ret = 1;
	}
	if (ret == -ENOENT)
		ret = 0;

out:
	kfree(super);
	return ret;
}

/*
 * If we're not seeing successful connections we want to back off.  Each
 * connection attempt starts by setting a long connection work delay.
 * We only set a shorter delay if we see a greeting response from the
 * server.  At that point we'll try to immediately reconnect if the
 * connection is broken.
 */
static void queue_connect_dwork(struct super_block *sb, struct client_info *client)
{
	if (!atomic_read(&client->shutting_down) && !scoutfs_forcing_unmount(sb))
		queue_delayed_work(client->workq, &client->connect_dwork,
				   client->connect_delay_jiffies);
}

/*
 * This work is responsible for maintaining a connection from the client
 * to the server.  It's queued on mount and disconnect and we requeue
 * the work if the work fails and we're not shutting down.
 *
 * We ask quorum for an address to try and connect to.  If there isn't
 * one, or it fails, we back off a bit before trying again.
 *
 * There's a tricky bit of coordination required to safely unmount.
 * Clients need to tell the server that they won't be coming back with a
 * farewell request.  Once the server processes a farewell request from
 * the client it can forget the client.  If the connection is broken
 * before the client gets the farewell response it doesn't want to
 * reconnect to send it again.. instead the client can read the metadata
 * device to check for the lack of an item which indicates that the
 * server has processed its farewell.
 */
static void scoutfs_client_connect_worker(struct work_struct *work)
{
	struct client_info *client = container_of(work, struct client_info,
						  connect_dwork.work);
	struct super_block *sb = client->sb;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_mount_options opts;
	struct scoutfs_net_greeting greet;
	struct sockaddr_storage sin;
	bool am_quorum;
	int ret;

	scoutfs_options_read(sb, &opts);
	am_quorum = opts.quorum_slot_nr >= 0;

	/* can unmount once server farewell handling removes our item */
	if (client->sending_farewell &&
	    lookup_mounted_client_item(sb, sbi->rid) == 0) {
		client->farewell_error = 0;
		complete(&client->farewell_comp);
		ret = 0;
		goto out;
	}

	/* always wait a bit until a greeting response sets a lower delay */
	client->connect_delay_jiffies = msecs_to_jiffies(CLIENT_CONNECT_DELAY_MS);

	ret = scoutfs_quorum_server_sin(sb, &sin);
	if (ret < 0)
		goto out;

	ret = scoutfs_net_connect(sb, client->conn, &sin,
				  CLIENT_CONNECT_TIMEOUT_MS);
	if (ret < 0)
		goto out;

	/* send a greeting to verify endpoints of each connection */
	greet.fsid = cpu_to_le64(sbi->fsid);
	greet.fmt_vers = cpu_to_le64(sbi->fmt_vers);
	greet.server_term = cpu_to_le64(client->server_term);
	greet.rid = cpu_to_le64(sbi->rid);
	greet.flags = 0;
	if (client->sending_farewell)
		greet.flags |= cpu_to_le64(SCOUTFS_NET_GREETING_FLAG_FAREWELL);
	if (am_quorum)
		greet.flags |= cpu_to_le64(SCOUTFS_NET_GREETING_FLAG_QUORUM);

	ret = scoutfs_net_submit_request(sb, client->conn,
					 SCOUTFS_NET_CMD_GREETING,
					 &greet, sizeof(greet),
					 client_greeting, NULL, NULL);
	if (ret)
		scoutfs_net_shutdown(sb, client->conn);
out:
	if (ret)
		queue_connect_dwork(sb, client);
}

static scoutfs_net_request_t client_req_funcs[] = {
	[SCOUTFS_NET_CMD_SYNC_LOG_TREES]	= sync_log_trees,
	[SCOUTFS_NET_CMD_LOCK]			= client_lock,
	[SCOUTFS_NET_CMD_LOCK_RECOVER]		= client_lock_recover,
	[SCOUTFS_NET_CMD_OPEN_INO_MAP]		= client_open_ino_map,
};

/*
 * Called when either a connect attempt or established connection times
 * out and fails.
 */
static void client_notify_down(struct super_block *sb,
			       struct scoutfs_net_connection *conn, void *info,
			       u64 rid)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	queue_connect_dwork(sb, client);
}

int scoutfs_client_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct client_info *client;
	int ret;

	client = kzalloc(sizeof(struct client_info), GFP_KERNEL);
	if (!client) {
		ret = -ENOMEM;
		goto out;
	}
	sbi->client_info = client;

	client->sb = sb;
	atomic_set(&client->shutting_down, 0);
	INIT_DELAYED_WORK(&client->connect_dwork,
			  scoutfs_client_connect_worker);
	init_completion(&client->farewell_comp);

	client->conn = scoutfs_net_alloc_conn(sb, NULL, client_notify_down, 0,
					      client_req_funcs, "client");
	if (!client->conn) {
		ret = -ENOMEM;
		goto out;
	}

	client->workq = alloc_workqueue("scoutfs_client_workq", WQ_UNBOUND, 1);
	if (!client->workq) {
		ret = -ENOMEM;
		goto out;
	}

	queue_connect_dwork(sb, client);
	ret = 0;

out:
	if (ret)
		scoutfs_client_destroy(sb);
	return ret;
}

/* Once we get a response from the server we can shut down */
static int client_farewell_response(struct super_block *sb,
				    struct scoutfs_net_connection *conn,
				    void *resp, unsigned int resp_len,
				    int error, void *data)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	if (resp_len != 0)
		return -EINVAL;

	client->farewell_error = error;
	complete(&client->farewell_comp);

	return 0;
}

/*
 * There must be no more callers to the client request functions by the
 * time we get here.
 *
 * If we've connected to a server then we send them a farewell request
 * so that they don't wait for us to reconnect and trigger a timeout.
 *
 * This decision is a little racy.  The server considers us connected
 * when it records a persistent record of our rid as it processes our
 * greeting.  We can disconnect before receiving the greeting response
 * and leave without sending a farewell.  So given that awkward initial
 * race, we also have a bit of a race where we just test the server_term
 * to see if we've ever gotten a greeting reply from any server.  We
 * don't try to synchronize with pending connection attempts.
 *
 * The consequences of aborting a mount at just the wrong time and
 * disconnecting without the farewell handshake depend on what the
 * server does to timed out clients.  At best it'll spit out a warning
 * message that a client disconnected but it won't fence us if we didn't
 * have any persistent state.
 */
void scoutfs_client_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct client_info *client = SCOUTFS_SB(sb)->client_info;
	struct scoutfs_net_connection *conn;
	int ret;

	if (client == NULL)
		return;

	if (client->server_term != 0 && !scoutfs_forcing_unmount(sb)) {
		client->sending_farewell = true;
		ret = scoutfs_net_submit_request(sb, client->conn,
						 SCOUTFS_NET_CMD_FAREWELL,
						 NULL, 0,
						 client_farewell_response,
						 NULL, NULL);
		if (ret == 0) {
			wait_for_completion(&client->farewell_comp);
			ret = client->farewell_error;
		}
		if (ret) {
			scoutfs_inc_counter(sb, client_farewell_error);
			scoutfs_warn(sb, "client saw farewell error %d, server might see client connection time out", ret);
		}
	}

	/* stop notify_down from queueing connect work */
	atomic_set(&client->shutting_down, 1);

	/* make sure worker isn't using the conn */
	cancel_delayed_work_sync(&client->connect_dwork);

	/* make racing conn use explode */
	conn = client->conn;
	client->conn = NULL;
	scoutfs_net_free_conn(sb, conn);

	if (client->workq)
		destroy_workqueue(client->workq);
	kfree(client);
	sbi->client_info = NULL;
}

void scoutfs_client_net_shutdown(struct super_block *sb)
{
	struct client_info *client = SCOUTFS_SB(sb)->client_info;

	if (client && client->conn)
		scoutfs_net_shutdown(sb, client->conn);
}
