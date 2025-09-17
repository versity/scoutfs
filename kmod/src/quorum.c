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
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/hrtimer.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "format.h"
#include "msg.h"
#include "counters.h"
#include "quorum.h"
#include "server.h"
#include "block.h"
#include "net.h"
#include "sysfs.h"
#include "fence.h"
#include "scoutfs_trace.h"

/*
 * This quorum subsystem is responsible for ensuring that only one
 * server is ever running among the mounts and has exclusive read/write
 * access to the server structures in the metadata device.
 *
 * A specific set of mounts are quorum members as indicated by the
 * quorum_slot_nr mount option.  That option refers to the slot in the
 * super block that contains their configuration.  Only these mounts
 * participate in the election of the leader.
 *
 * As each quorum member mounts it starts background work that uses a
 * simplified raft leader election protocol to elect a leader.  Each
 * mount listens on a udp socket at the address found in its slot in the
 * super block.  It then sends and receives raft messages to and from
 * the other slot addresses in the super block.  As the protocol
 * progresses eventually a mount will receive enough votes to become the
 * leader.  We're not using the full key-value store of raft, just the
 * leadership election.  Much of the functionality matches the raft
 * concepts (roles, messages, timeouts) but there's no key value logs to
 * synchronize.
 *
 * Once elected leader, the mount now has to ensure that it's the only
 * running server.  There could be previously elected servers still
 * running (maybe they've deadlocked, or lost network communications).
 * In addition to a configuration slot in the super block, each quorum
 * member also has a known block location that represents their slot.
 * The block contains an array of events which are updated during the life
 * time of the quorum agent.  The elected leader set its elected event
 * and can then start the server.
 *
 * It's critical to raft elections that a participant's term not go
 * backwards in time so each mount also uses its quorum block to store
 * the greatest term it has used in messages.
 *
 * The quorum work still runs in the background while the server is
 * running.  The leader quorum work will regularly send heartbeat
 * messages to the other quorum members to keep them from electing a new
 * leader.  If the server shuts down, or the mount disappears, the other
 * quorum members will stop receiving heartbeats and will elect a new
 * leader.
 *
 * Typically we require a strict majority of the configured quorum
 * members to elect a leader.  However, for simple usability, we do
 * allow a majority of 1 when there are only one or two quorum members.
 * In the two member case this can lead to split elections where each
 * mount races to elect itself as leader and attempt to fence the other.
 * The random election timeouts in raft make this unlikely, but it is
 * possible.
 */

/*
 * The fields of the message that the receiver can use after the message
 * has been validated.
 */
struct quorum_host_msg {
	u64 term;
	u8 type;
	u8 from;
};

struct last_msg {
	struct quorum_host_msg msg;
	ktime_t ts;
};

struct count_recent {
	u64 count;
	ktime_t recent;
};

enum quorum_role { FOLLOWER, CANDIDATE, LEADER };

struct quorum_status {
	enum quorum_role role;
	u64 term;
	u64 server_start_term;
	int server_event;
	int vote_for;
	unsigned long vote_bits;
	ktime_t timeout;
};

#define HB_DELAY_NR		(SCOUTFS_QUORUM_MAX_HB_TIMEO_MS / MSEC_PER_SEC)

struct quorum_info {
	struct super_block *sb;
	struct scoutfs_quorum_config qconf;
	struct workqueue_struct *workq;
	struct work_struct work;
	struct socket *sock;
	bool shutdown;

	int our_quorum_slot_nr;
	int votes_needed;

	spinlock_t show_lock;
	struct quorum_status show_status;
	struct last_msg last_send[SCOUTFS_QUORUM_MAX_SLOTS];
	struct last_msg last_recv[SCOUTFS_QUORUM_MAX_SLOTS];
	struct count_recent *hb_delay;
	unsigned long max_hb_delay;

	struct scoutfs_sysfs_attrs ssa;
};

#define DECLARE_QUORUM_INFO(sb, name) \
	struct quorum_info *name = SCOUTFS_SB(sb)->quorum_info
#define DECLARE_QUORUM_INFO_KOBJ(kobj, name) \
	DECLARE_QUORUM_INFO(SCOUTFS_SYSFS_ATTRS_SB(kobj), name)

static bool quorum_slot_ipv4(struct scoutfs_quorum_config *qconf, int i)
{
	BUG_ON(i < 0 || i > SCOUTFS_QUORUM_MAX_SLOTS);

	return qconf->slots[i].addr.v4.family == cpu_to_le16(SCOUTFS_AF_IPV4);
}

static bool quorum_slot_ipv6(struct scoutfs_quorum_config *qconf, int i)
{
	BUG_ON(i < 0 || i > SCOUTFS_QUORUM_MAX_SLOTS);

	return qconf->slots[i].addr.v6.family == cpu_to_le16(SCOUTFS_AF_IPV6);
}

static bool quorum_slot_present(struct scoutfs_quorum_config *qconf, int i)
{
	return quorum_slot_ipv4(qconf, i) || quorum_slot_ipv6(qconf, i);
}

static void quorum_slot_sin(struct scoutfs_quorum_config *qconf, int i, struct sockaddr_storage *sin)
{
	BUG_ON(i < 0 || i >= SCOUTFS_QUORUM_MAX_SLOTS);

	scoutfs_addr_to_sin(sin, &qconf->slots[i].addr);
}

static ktime_t election_timeout(void)
{
	return ktime_add_ms(ktime_get(), SCOUTFS_QUORUM_ELECT_MIN_MS +
				 prandom_u32_max(SCOUTFS_QUORUM_ELECT_VAR_MS));
}

static ktime_t heartbeat_interval(void)
{
	return ktime_add_ms(ktime_get(), SCOUTFS_QUORUM_HB_IVAL_MS);
}

static ktime_t heartbeat_timeout(struct scoutfs_mount_options *opts)
{
	return ktime_add_ms(ktime_get(), opts->quorum_heartbeat_timeout_ms);
}

static int create_socket(struct super_block *sb)
{
	DECLARE_QUORUM_INFO(sb, qinf);
	struct socket *sock = NULL;
	struct sockaddr_storage sin;
	struct scoutfs_quorum_slot slot = qinf->qconf.slots[qinf->our_quorum_slot_nr];
	int addrlen;
	int ret;

	if (le16_to_cpu(slot.addr.v4.family) == SCOUTFS_AF_IPV4)
		ret = kc_sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	else if (le16_to_cpu(slot.addr.v6.family) == SCOUTFS_AF_IPV6)
		ret = kc_sock_create_kern(PF_INET6, SOCK_DGRAM, IPPROTO_UDP, &sock);
	else
		BUG();

	if (ret) {
		scoutfs_err(sb, "quorum couldn't create udp socket: %d", ret);
		goto out;
	}

	/* rather fail and retry than block waiting for free */
	sock->sk->sk_allocation = GFP_ATOMIC;

	addrlen = (le16_to_cpu(slot.addr.v4.family) == SCOUTFS_AF_IPV4) ?
		  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	quorum_slot_sin(&qinf->qconf, qinf->our_quorum_slot_nr, &sin);
	ret = kernel_bind(sock, (struct sockaddr *)&sin, addrlen);
	if (ret) {
		scoutfs_err(sb, "quorum failed to bind udp socket to "SIN_FMT": %d",
			    SIN_ARG(&sin), ret);
		goto out;
	}

out:
	if (ret < 0 && sock) {
		sock_release(sock);
		sock = NULL;
	}
	qinf->sock = sock;
	return ret;
}

static __le32 quorum_message_crc(struct scoutfs_quorum_message *qmes)
{
	/* crc up to the crc field at the end */
	unsigned int len = offsetof(struct scoutfs_quorum_message, crc);

	return cpu_to_le32(crc32c(~0, qmes, len));
}

/*
 * Returns the number of failures from sendmsg.
 */
static int send_msg_members(struct super_block *sb, int type, u64 term, int only)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_QUORUM_INFO(sb, qinf);
	int failed = 0;
	ktime_t now;
	int ret;
	int i;

	struct scoutfs_quorum_message qmes = {
		.fsid = cpu_to_le64(sbi->fsid),
		.term = cpu_to_le64(term),
		.type = type,
		.from = qinf->our_quorum_slot_nr,
	};
	struct kvec kv =  {
		.iov_base = &qmes,
		.iov_len = sizeof(qmes),
	};
	struct sockaddr_storage sin;
	struct msghdr mh = {
		.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
		.msg_name = &sin,
		.msg_namelen = sizeof(sin),
	};

	trace_scoutfs_quorum_send_message(sb, term, type, only);

	qmes.crc = quorum_message_crc(&qmes);

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (!quorum_slot_present(&qinf->qconf, i) ||
		    (only >= 0 && i != only) || i == qinf->our_quorum_slot_nr)
			continue;

		if (scoutfs_forcing_unmount(sb)) {
			failed = 0;
			break;
		}

		scoutfs_quorum_slot_sin(&qinf->qconf, i, &sin);
		now = ktime_get();

		ret = kernel_sendmsg(qinf->sock, &mh, &kv, 1, kv.iov_len);
		if (ret != kv.iov_len)
			failed++;

		spin_lock(&qinf->show_lock);
		qinf->last_send[i].msg.term = term;
		qinf->last_send[i].msg.type = type;
		qinf->last_send[i].ts = now;
		spin_unlock(&qinf->show_lock);

		if (i == only)
			break;
	}

	return failed;
}

#define send_msg_to(sb, type, term, nr)  send_msg_members(sb, type, term, nr)
#define send_msg_others(sb, type, term)  send_msg_members(sb, type, term, -1)

/*
 * The caller passes in their absolute timeout which we translate to a
 * relative timeval for RCVTIMEO.  It defines a 0.0 timeval as blocking
 * indefinitely so we're careful to set dontwait if we happen to hit a
 * 0.0 timeval.
 */
static int recv_msg(struct super_block *sb, struct quorum_host_msg *msg,
		    ktime_t abs_to)
{
	DECLARE_QUORUM_INFO(sb, qinf);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_quorum_message qmes;
	ktime_t rel_to;
	ktime_t now;
	int ret;

	struct kvec kv =  {
		.iov_base = &qmes,
		.iov_len = sizeof(struct scoutfs_quorum_message),
	};
	struct msghdr mh = {
		.msg_flags = MSG_NOSIGNAL,
	};

	memset(msg, 0, sizeof(*msg));

	now = ktime_get();
	if (ktime_before(now, abs_to))
		rel_to = ktime_sub(abs_to, now);
	else
		rel_to = ns_to_ktime(0);

	if (ktime_compare(rel_to, ns_to_ktime(NSEC_PER_USEC)) <= 0) {
		mh.msg_flags |= MSG_DONTWAIT;
	} else {
		ret = kc_tcp_sock_set_rcvtimeo(qinf->sock, rel_to);
	}

	ret = kernel_recvmsg(qinf->sock, &mh, &kv, 1, kv.iov_len, mh.msg_flags);
	if (ret < 0)
		return ret;

	if (scoutfs_forcing_unmount(sb))
		return 0;

	now = ktime_get();

	if (ret != sizeof(qmes) ||
	    qmes.crc != quorum_message_crc(&qmes) ||
	    qmes.fsid != cpu_to_le64(sbi->fsid) ||
	    qmes.type >= SCOUTFS_QUORUM_MSG_INVALID ||
	    qmes.from >= SCOUTFS_QUORUM_MAX_SLOTS ||
	    !quorum_slot_present(&qinf->qconf, qmes.from)) {
		/* should we be trying to open a new socket? */
		scoutfs_inc_counter(sb, quorum_recv_invalid);
		return -EAGAIN;
	}

	msg->term = le64_to_cpu(qmes.term);
	msg->type = qmes.type;
	msg->from = qmes.from;

	trace_scoutfs_quorum_recv_message(sb, msg->term, msg->type, msg->from);

	spin_lock(&qinf->show_lock);
	qinf->last_recv[msg->from].msg = *msg;
	qinf->last_recv[msg->from].ts = now;
	spin_unlock(&qinf->show_lock);

	return 0;
}

/*
 * Read and verify block fields before giving it to the caller.  We
 * should have exclusive write access to the block.  We know that
 * something has gone horribly wrong if we don't see our rid in the
 * begin event after we've written it as we started up.
 */
static int read_quorum_block(struct super_block *sb, u64 blkno, struct scoutfs_quorum_block *blk,
			     bool check_rid)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	const u64 fsid = sbi->fsid;
	const u64 rid = sbi->rid;
	char msg[150];
	__le32 crc;
	int ret;

	if (WARN_ON_ONCE(blkno < SCOUTFS_QUORUM_BLKNO) ||
	    WARN_ON_ONCE(blkno >= (SCOUTFS_QUORUM_BLKNO +
				   SCOUTFS_QUORUM_BLOCKS)))
		return -EINVAL;

	ret = scoutfs_block_read_sm(sb, sbi->meta_bdev, blkno,
				     &blk->hdr, sizeof(*blk), &crc);
	if (ret < 0) {
		scoutfs_err(sb, "quorum block read error %d", ret);
		goto out;
	}

	/* detect invalid blocks */
	if (blk->hdr.crc != crc)
		snprintf(msg, sizeof(msg), "blk crc %08x != %08x",
			 le32_to_cpu(blk->hdr.crc), le32_to_cpu(crc));
	else if (le32_to_cpu(blk->hdr.magic) != SCOUTFS_BLOCK_MAGIC_QUORUM) 
		snprintf(msg, sizeof(msg), "blk magic %08x != %08x",
			 le32_to_cpu(blk->hdr.magic), SCOUTFS_BLOCK_MAGIC_QUORUM);
	else if (blk->hdr.fsid != cpu_to_le64(fsid))
		snprintf(msg, sizeof(msg), "blk fsid %016llx != %016llx",
			 le64_to_cpu(blk->hdr.fsid), fsid);
	else if (le64_to_cpu(blk->hdr.blkno) != blkno)
		snprintf(msg, sizeof(msg), "blk blkno %llu != %llu",
			 le64_to_cpu(blk->hdr.blkno), blkno);
	else if (check_rid && le64_to_cpu(blk->events[SCOUTFS_QUORUM_EVENT_BEGIN].rid) != rid)
		snprintf(msg, sizeof(msg), "quorum block begin rid %016llx != our rid %016llx, are multiple mounts configured with this slot?",
		le64_to_cpu(blk->events[SCOUTFS_QUORUM_EVENT_BEGIN].rid), rid);
	else
		msg[0] = '\0';

	if (msg[0] != '\0') {
		scoutfs_err(sb, "read invalid quorum block, %s", msg);
		ret = -EIO;
		goto out;
	}

out:
	return ret;
}

/*
 * It's really important in raft elections that the term not go
 * backwards in time.  We achieve this by having each participant record
 * the greatest term they've seen in their quorum block.  It's also
 * important that participants agree on the greatest term.  It can
 * happen that one gets ahead of the rest, perhaps by being forcefully
 * shutdown after having just been elected.  As everyone starts up it's
 * possible to have N-1 have term T-1 while just one participant thinks
 * the term is T.   That single participant will ignore all messages
 * from older terms.  If its timeout is greater then the others it can
 * immediately override the election of the majority and request votes
 * and become elected.
 *
 * A best-effort work around is to have everyone try and start from the
 * greatest term that they can find in everyone's blocks.  If it works
 * then you avoid having those with greater terms ignore others.  If it
 * doesn't work the elections will eventually stabilize after rocky
 * periods of fencing from what looks like concurrent elections.
 */
static void read_greatest_term(struct super_block *sb, u64 *term)
{
	DECLARE_QUORUM_INFO(sb, qinf);
	struct scoutfs_quorum_block blk;
	int ret;
	int e;
	int s;

	*term = 0;

	for (s = 0; s < SCOUTFS_QUORUM_MAX_SLOTS; s++) {
		if (!quorum_slot_present(&qinf->qconf, s))
			continue;

		ret = read_quorum_block(sb, SCOUTFS_QUORUM_BLKNO + s, &blk, false);
		if (ret < 0)
			continue;

		for (e = 0; e < ARRAY_SIZE(blk.events); e++) {
			if (blk.events[e].rid)
				*term = max(*term, le64_to_cpu(blk.events[e].term));
		}
	}
}

static void set_quorum_block_event(struct super_block *sb, struct scoutfs_quorum_block *blk,
				   int event, u64 term)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_quorum_block_event *ev;
	struct timespec64 ts;

	if (WARN_ON_ONCE(event < 0 || event >= SCOUTFS_QUORUM_EVENT_NR))
		return;

	ktime_get_ts64(&ts);
	le64_add_cpu(&blk->write_nr, 1);

	ev = &blk->events[event];
	ev->write_nr = blk->write_nr;
	ev->rid = cpu_to_le64(sbi->rid);
	ev->term = cpu_to_le64(term);
	ev->ts.sec = cpu_to_le64(ts.tv_sec);
	ev->ts.nsec = cpu_to_le32(ts.tv_nsec);
}

static int write_quorum_block(struct super_block *sb, u64 blkno, struct scoutfs_quorum_block *blk)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (WARN_ON_ONCE(blkno < SCOUTFS_QUORUM_BLKNO) ||
	    WARN_ON_ONCE(blkno >= (SCOUTFS_QUORUM_BLKNO +
				   SCOUTFS_QUORUM_BLOCKS)))
		return -EINVAL;

	return scoutfs_block_write_sm(sb, sbi->meta_bdev, blkno, &blk->hdr, sizeof(*blk));
}

/*
 * Read the caller's slot's quorum block, make a change, and write it
 * back out.
 */
static int update_quorum_block(struct super_block *sb, int event, u64 term, bool check_rid)
{
	DECLARE_QUORUM_INFO(sb, qinf);
	u64 blkno = SCOUTFS_QUORUM_BLKNO + qinf->our_quorum_slot_nr;
	struct scoutfs_quorum_block blk;
	int ret;

	ret = read_quorum_block(sb, blkno, &blk, check_rid);
	if (ret == 0) {
		set_quorum_block_event(sb, &blk, event, term);
		ret = write_quorum_block(sb, blkno, &blk);
		if (ret < 0)
			scoutfs_err(sb, "error %d writing quorum block %llu after updating event %d term %llu",
				    ret, blkno, event, term);
	} else {
		scoutfs_err(sb, "error %d reading quorum block %llu to update event %d term %llu",
			    ret, blkno, event, term);
	}

	return ret;
}

/*
 * The calling server has been elected and has started running but can't
 * yet assume that it has exclusive access to the metadata device.  We
 * read all the quorum blocks looking for previously elected leaders to
 * fence so that we're the only leader running.
 *
 * We're relying on the invariant that there can't be two mounts running
 * with the same slot nr at the same time.  With this constraint there
 * can be at most two previous leaders per slot that need to be fenced:
 * a persistent record of an old mount on the slot, and an active mount.
 *
 * If we start fence requests then we only wait for them to complete
 * before returning.  The server will reclaim their resources once it is
 * up and running and will call us to update the fence event.  If we
 * don't start fence requests then we update the fence event
 * immediately, the server has nothing more to do.
 *
 * Quorum will be sending heartbeats while we wait for fencing.  That
 * keeps us from being fenced while we allow userspace fencing to take a
 * reasonably long time.  We still want to timeout eventually.
 */
int scoutfs_quorum_fence_leaders(struct super_block *sb, struct scoutfs_quorum_config *qconf,
				 u64 term)
{
#define NR_OLD 2
	struct scoutfs_quorum_block_event (*old)[NR_OLD];
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_quorum_block blk;
	struct sockaddr_storage sin;
	union scoutfs_inet_addr addr;
	const __le64 lefsid = cpu_to_le64(sbi->fsid);
	const u64 rid = sbi->rid;
	bool fence_started = false;
	u64 fenced = 0;
	__le64 fence_rid;
	int ret = 0;
	int err;
	int i;
	int j;

	BUILD_BUG_ON(SCOUTFS_QUORUM_BLOCKS < SCOUTFS_QUORUM_MAX_SLOTS);

	old = kmalloc(NR_OLD * SCOUTFS_QUORUM_MAX_SLOTS * sizeof(struct scoutfs_quorum_block_event), GFP_KERNEL);
	if (!old) {
		ret = -ENOMEM;
		goto out;
	}
	memset(old, 0, NR_OLD * SCOUTFS_QUORUM_MAX_SLOTS * sizeof(struct scoutfs_quorum_block_event));

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (!quorum_slot_present(qconf, i))
			continue;

		ret = read_quorum_block(sb, SCOUTFS_QUORUM_BLKNO + i, &blk, false);
		if (ret < 0)
			goto out_free;

		/* elected leader still running */
		if (le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_ELECT].term) >
		    le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_STOP].term))
			old[i][0] = blk.events[SCOUTFS_QUORUM_EVENT_ELECT];

		/* persistent record of previous server before elected */
		if ((le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_FENCE].term) >
		     le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_STOP].term)) &&
		    (le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_FENCE].term) <
		     le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_ELECT].term)))
			old[i][1] = blk.events[SCOUTFS_QUORUM_EVENT_FENCE];

		/* find greatest term that has fenced everything before it */
		fenced = max(fenced, le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_FENCE].term));
	}

	/* now actually fence any old leaders which haven't been fenced yet */
	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		for (j = 0; j < NR_OLD; j++) {
			if (le64_to_cpu(old[i][j].term) == 0 ||		/* uninitialized */
			    le64_to_cpu(old[i][j].term) < fenced ||	/* already fenced */
			    le64_to_cpu(old[i][j].term) > term ||	/* newer than us */
			    le64_to_cpu(old[i][j].rid) == rid)		/* us */
				continue;

			scoutfs_inc_counter(sb, quorum_fence_leader);
			quorum_slot_sin(qconf, i, &sin);
			fence_rid = old[i][j].rid;

			scoutfs_info(sb, "fencing previous leader "SCSBF" at term %llu in slot %u with address "SIN_FMT,
				     SCSB_LEFR_ARGS(lefsid, fence_rid),
				     le64_to_cpu(old[i][j].term), i, SIN_ARG(&sin));
			scoutfs_sin_to_addr(&addr, &sin);
			ret = scoutfs_fence_start(sb, le64_to_cpu(fence_rid), &addr,
						  SCOUTFS_FENCE_QUORUM_BLOCK_LEADER);
			if (ret < 0)
				goto out_free;
			fence_started = true;
		}
	}

out_free:
	kfree(old);
out:
	err = scoutfs_fence_wait_fenced(sb, msecs_to_jiffies(SCOUTFS_QUORUM_FENCE_TO_MS));
	if (ret == 0)
		ret = err;

	if (ret < 0)
		scoutfs_inc_counter(sb, quorum_fence_error);

	return ret;
}

static void clear_hb_delay(struct quorum_info *qinf)
{
	int i;

	spin_lock(&qinf->show_lock);
	qinf->max_hb_delay = 0;
	for (i = 0; i < HB_DELAY_NR; i++) {
		qinf->hb_delay[i].recent = ns_to_ktime(0);
		qinf->hb_delay[i].count = 0;
	}
	spin_unlock(&qinf->show_lock);
}

struct hb_recording {
	ktime_t prev;
	int count;
};

/*
 * Record long heartbeat delays.  We only record the delay between back
 * to back send attempts in the leader or back to back recv messages in
 * the followers.  The worker caller sets record_hb when their iteration
 * sent or received a heartbeat.  An iteration that does anything else
 * resets the tracking.
 */
static void record_hb_delay(struct super_block *sb, struct quorum_info *qinf,
			    struct hb_recording *hbr, bool record_hb, int role)
{
	bool log = false;
	ktime_t now;
	s64 s;

	if (!record_hb) {
		hbr->count = 0;
		return;
	}

	now = ktime_get();

	if (hbr->count < 2 && ++hbr->count < 2) {
		hbr->prev = now;
		return;
	}

	s = ktime_ms_delta(now, hbr->prev) / MSEC_PER_SEC;
	hbr->prev = now;

	if (s <= 0 || s >= HB_DELAY_NR)
		return;

	spin_lock(&qinf->show_lock);
	if (qinf->max_hb_delay < s) {
		qinf->max_hb_delay = s;
		if (s >= 3)
			log = true;
	}
	qinf->hb_delay[s].recent = now;
	qinf->hb_delay[s].count++;
	spin_unlock(&qinf->show_lock);

	if (log)
		scoutfs_info(sb, "longest quorum heartbeat %s delay of %lld sec",
			     role == LEADER ? "send" : "recv", s);
}

/*
 * The main quorum task maintains its private status.  It seemed cleaner
 * to occasionally copy the status for showing in sysfs/debugfs files
 * than to have the two lock access to shared status.  The show copy is
 * updated after being modified before the quorum task sleeps for a
 * significant amount of time, either waiting on timeouts or interacting
 * with the server.
 */
static void update_show_status(struct quorum_info *qinf, struct quorum_status *qst)
{
	spin_lock(&qinf->show_lock);
	qinf->show_status = *qst;
	spin_unlock(&qinf->show_lock);
}

/*
 * The quorum work always runs in the background of quorum member
 * mounts.  It's responsible for starting and stopping the server if
 * it's elected leader.  While it's leader it sends heartbeats to
 * suppress other quorum work from standing for election.
 */
static void scoutfs_quorum_worker(struct work_struct *work)
{
	struct quorum_info *qinf = container_of(work, struct quorum_info, work);
	struct scoutfs_mount_options opts;
	struct super_block *sb = qinf->sb;
	struct sockaddr_storage unused;
	struct quorum_host_msg msg;
	struct quorum_status qst = {0,};
	struct hb_recording hbr;
	bool record_hb;
	int ret;
	int err;

	memset(&hbr, 0, sizeof(struct hb_recording));

	/* recording votes from slots as native single word bitmap */
	BUILD_BUG_ON(SCOUTFS_QUORUM_MAX_SLOTS > BITS_PER_LONG);

	scoutfs_options_read(sb, &opts);

	/* start out as a follower */
	qst.role = FOLLOWER;
	qst.vote_for = -1;

	/* read our starting term from greatest in all events in all slots */
	read_greatest_term(sb, &qst.term);

	/* see if there's a server to chose heartbeat or election timeout */
	if (scoutfs_quorum_server_sin(sb, &unused) == 0)
		qst.timeout = heartbeat_timeout(&opts);
	else
		qst.timeout = election_timeout();

	/* record that we're up and running, readers check that it isn't updated */
	ret = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_BEGIN, qst.term, false);
	if (ret < 0)
		goto out;

	while (!(qinf->shutdown || scoutfs_forcing_unmount(sb))) {

		update_show_status(qinf, &qst);

		ret = recv_msg(sb, &msg, qst.timeout);
		if (ret < 0) {
			if (ret != -ETIMEDOUT && ret != -EAGAIN) {
				scoutfs_err(sb, "quorum recvmsg err %d", ret);
				scoutfs_inc_counter(sb, quorum_recv_error);
				goto out;
			}
			msg.type = SCOUTFS_QUORUM_MSG_INVALID;
			ret = 0;
		}

		scoutfs_options_read(sb, &opts);
		record_hb = false;

		/* ignore messages from older terms */
		if (msg.type != SCOUTFS_QUORUM_MSG_INVALID &&
		    msg.term < qst.term)
			msg.type = SCOUTFS_QUORUM_MSG_INVALID;

		trace_scoutfs_quorum_loop(sb, qst.role, qst.term, qst.vote_for,
					  qst.vote_bits, ktime_to_ns(qst.timeout));

		/* receiving greater terms resets term, becomes follower */
		if (msg.type != SCOUTFS_QUORUM_MSG_INVALID &&
		    msg.term > qst.term) {
			if (qst.role == LEADER) {
				scoutfs_warn(sb, "saw msg type %u from %u for term %llu while leader in term %llu, shutting down server.",
					     msg.type, msg.from, msg.term, qst.term);
				clear_hb_delay(qinf);
			}
			qst.role = FOLLOWER;
			qst.term = msg.term;
			qst.vote_for = -1;
			qst.vote_bits = 0;
			scoutfs_inc_counter(sb, quorum_term_follower);

			if (msg.type == SCOUTFS_QUORUM_MSG_HEARTBEAT)
				qst.timeout = heartbeat_timeout(&opts);
			else
				qst.timeout = election_timeout();

			/* store our increased term */
			ret = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_TERM, qst.term, true);
			if (ret < 0)
				goto out;
		}

		/* receiving heartbeats extends timeout, delaying elections */
		if (msg.type == SCOUTFS_QUORUM_MSG_HEARTBEAT) {
			qst.timeout = heartbeat_timeout(&opts);
			scoutfs_inc_counter(sb, quorum_recv_heartbeat);
			record_hb = true;
		}

		/* receiving a resignation from server starts election */
		if (msg.type == SCOUTFS_QUORUM_MSG_RESIGNATION &&
		    qst.role == FOLLOWER &&
		    msg.term == qst.term) {
			qst.timeout = election_timeout();
			scoutfs_inc_counter(sb, quorum_recv_resignation);
		}

		/* followers and candidates start new election on timeout */
		if (qst.role != LEADER &&
		    msg.type == SCOUTFS_QUORUM_MSG_INVALID &&
		    ktime_after(ktime_get(), qst.timeout)) {
			/* .. but only if their server has stopped */
			if (!scoutfs_server_is_down(sb)) {
				qst.timeout = election_timeout();
				scoutfs_inc_counter(sb, quorum_candidate_server_stopping);
				continue;
			}

			qst.role = CANDIDATE;
			qst.term++;
			qst.vote_for = -1;
			qst.vote_bits = 0;
			set_bit(qinf->our_quorum_slot_nr, &qst.vote_bits);
			send_msg_others(sb, SCOUTFS_QUORUM_MSG_REQUEST_VOTE,
					qst.term);
			qst.timeout = election_timeout();
			scoutfs_inc_counter(sb, quorum_send_request);

			/* store our increased term */
			ret = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_TERM, qst.term, true);
			if (ret < 0)
				goto out;
		}

		/* candidates count votes in their term */
		if (qst.role == CANDIDATE &&
		    msg.type == SCOUTFS_QUORUM_MSG_VOTE) {
			if (test_and_set_bit(msg.from, &qst.vote_bits)) {
				scoutfs_warn(sb, "already received vote from %u in term %llu, are there multiple mounts with quorum_slot_nr=%u?",
					     msg.from, qst.term, msg.from);
			}
			scoutfs_inc_counter(sb, quorum_recv_vote);
		}

		/*
		 * Candidates become leaders when they receive enough
		 * votes.  (Possibly only counting their own vote in
		 * single vote majorities.)
		 */
		if (qst.role == CANDIDATE &&
		    hweight_long(qst.vote_bits) >= qinf->votes_needed) {
			qst.role = LEADER;
			scoutfs_inc_counter(sb, quorum_elected);

			/* send heartbeat before server starts */
			send_msg_others(sb, SCOUTFS_QUORUM_MSG_HEARTBEAT,
					qst.term);
			qst.timeout = heartbeat_interval();

			update_show_status(qinf, &qst);
			clear_hb_delay(qinf);

			/* record that we've been elected before starting up server */
			ret = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_ELECT, qst.term, true);
			if (ret < 0)
				goto out;

			qst.server_start_term = qst.term;
			qst.server_event = SCOUTFS_QUORUM_EVENT_ELECT;
			scoutfs_server_start(sb, &qinf->qconf, qst.term);
		}

		/*
		 * This leader's server is up, having finished fencing
		 * previous leaders.  We update the fence event with the
		 * current term to let future leaders know that previous
		 * servers have been fenced.
		 */
		if (qst.role == LEADER && qst.server_event != SCOUTFS_QUORUM_EVENT_FENCE &&
		    scoutfs_server_is_up(sb)) {
			ret = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_FENCE, qst.term, true);
			if (ret < 0)
				goto out;
			qst.server_event = SCOUTFS_QUORUM_EVENT_FENCE;
		}

		/*
		 * Stop a running server if we're no longer leader in
		 * its term.
		 */
		if (!(qst.role == LEADER && qst.term == qst.server_start_term) &&
		    scoutfs_server_is_running(sb)) {
			scoutfs_server_stop(sb);
		}

		/*
		 * A previously running server has stopped.  The quorum
		 * protocol might have shut it down by changing roles or
		 * it might have stopped on its own, perhaps on errors.
		 * If we're still a leader then we become a follower and
		 * send resignations to encourage the next election.
		 * Always update the _STOP event to stop connections and
		 * fencing.
		 */
		if (qst.server_start_term > 0 && scoutfs_server_is_down(sb)) {
			if (qst.role == LEADER) {
				qst.role = FOLLOWER;
				qst.vote_for = -1;
				qst.vote_bits = 0;
				qst.timeout = election_timeout();
				scoutfs_inc_counter(sb, quorum_server_shutdown);

				send_msg_others(sb, SCOUTFS_QUORUM_MSG_RESIGNATION,
						qst.server_start_term);
				scoutfs_inc_counter(sb, quorum_send_resignation);
				clear_hb_delay(qinf);
			}

			ret = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_STOP,
						  qst.server_start_term, true);
			if (ret < 0)
				goto out;

			qst.server_start_term = 0;
		}

		/* leaders regularly send heartbeats to delay elections */
		if (qst.role == LEADER &&
		    ktime_after(ktime_get(), qst.timeout)) {
			ret = send_msg_others(sb, SCOUTFS_QUORUM_MSG_HEARTBEAT, qst.term);
			if (ret > 0) {
				scoutfs_add_counter(sb, quorum_send_heartbeat_dropped, ret);
				ret = 0;
			}

			qst.timeout = heartbeat_interval();
			scoutfs_inc_counter(sb, quorum_send_heartbeat);
			record_hb = true;

		}

		/* followers vote once per term */
		if (qst.role == FOLLOWER &&
		    msg.type == SCOUTFS_QUORUM_MSG_REQUEST_VOTE &&
		    qst.vote_for == -1) {
			qst.vote_for = msg.from;
			send_msg_to(sb, SCOUTFS_QUORUM_MSG_VOTE, qst.term,
				    msg.from);
			scoutfs_inc_counter(sb, quorum_send_vote);
		}

		record_hb_delay(sb, qinf, &hbr, record_hb, qst.role);
	}

	update_show_status(qinf, &qst);

	/* always try to stop a running server as we stop */
	if (scoutfs_server_is_running(sb)) {
		scoutfs_server_stop_wait(sb);
		send_msg_others(sb, SCOUTFS_QUORUM_MSG_RESIGNATION, qst.term);

		if (qst.server_start_term > 0) {
			err = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_STOP,
						  qst.server_start_term, true);
			if (err < 0 && ret == 0)
				ret = err;
		}
	}

	/* record that this slot no longer has an active quorum */
	err = update_quorum_block(sb, SCOUTFS_QUORUM_EVENT_END, qst.term, true);
	if (err < 0 && ret == 0)
		ret = err;

out:
	if (ret < 0) {
		scoutfs_err(sb, "quorum service saw error %d, shutting down.  This mount is no longer participating in quorum.  It should be remounted to restore service.",
			    ret);
	}
}

/*
 * Clients read quorum blocks looking for the leader with a server whose
 * address it can try and connect to.
 *
 * There can be records of multiple previous elected leaders if the
 * current server hasn't yet fenced any old servers.  We use the elected
 * leader with the greatest elected term.  If we get it wrong the
 * connection will timeout and the client will try again.
 */
int scoutfs_quorum_server_sin(struct super_block *sb, struct sockaddr_storage *sin)
{
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_quorum_block blk;
	u64 elect_term;
	u64 term = 0;
	int ret = 0;
	int i;

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	if (!super) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_read_super(sb, super);
	if (ret)
		goto out;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (!quorum_slot_present(&super->qconf, i))
			continue;

		ret = read_quorum_block(sb, SCOUTFS_QUORUM_BLKNO + i, &blk, false);
		if (ret < 0) {
			scoutfs_err(sb, "error reading quorum block nr %u: %d",
				    i, ret);
			goto out;
		}

		elect_term = le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_ELECT].term);
		if (elect_term > term &&
		    elect_term > le64_to_cpu(blk.events[SCOUTFS_QUORUM_EVENT_STOP].term)) {
			term = elect_term;
			scoutfs_quorum_slot_sin(&super->qconf, i, sin);
			continue;
		}
	}

	if (term == 0)
		ret = -ENOENT;

out:
	kfree(super);
	return ret;
}

/*
 * The number of votes needed for a member to reach quorum and be
 * elected the leader: a majority of the number of present slots in the
 * super block.
 */
u8 scoutfs_quorum_votes_needed(struct super_block *sb)
{
	DECLARE_QUORUM_INFO(sb, qinf);

	return qinf->votes_needed;
}

void scoutfs_quorum_slot_sin(struct scoutfs_quorum_config *qconf, int i, struct sockaddr_storage *sin)
{
	return quorum_slot_sin(qconf, i, sin);
}

static char *role_str(int role)
{
	static char *roles[] = {
		[FOLLOWER] = "follower",
		[CANDIDATE] = "candidate",
		[LEADER] = "leader",
	};

	if (role < 0 || role >= ARRAY_SIZE(roles) || !roles[role])
		return "invalid";

	return roles[role];
}

#define snprintf_ret(buf, size, retp, fmt...)				\
do {									\
	__typeof__(buf) _buf = buf;					\
	__typeof__(size) _size = size;					\
	__typeof__(retp) _retp = retp;					\
	__typeof__(*retp) _ret = *_retp;				\
	__typeof__(*retp) _len;						\
									\
	if (_ret >= 0 && _ret < _size) {				\
		_len = snprintf(_buf + _ret, _size - _ret, ##fmt);	\
		if (_len < 0)						\
			_ret = _len;					\
		else							\
			_ret += _len;					\
		*_retp = _ret;						\
	}								\
} while (0)

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	DECLARE_QUORUM_INFO_KOBJ(kobj, qinf);
	struct quorum_status qst;
	struct count_recent cr;
	struct last_msg last;
	struct timespec64 ts;
	const ktime_t now = ktime_get();
	unsigned long ul;
	size_t size;
	int ret;
	int i;

	spin_lock(&qinf->show_lock);
	qst = qinf->show_status;
	spin_unlock(&qinf->show_lock);

	size = PAGE_SIZE;
	ret = 0;

	snprintf_ret(buf, size, &ret, "quorum_slot_nr %u\n",
		     qinf->our_quorum_slot_nr);
	snprintf_ret(buf, size, &ret, "term %llu\n",
		     qst.term);
	snprintf_ret(buf, size, &ret, "server_start_term %llu\n", qst.server_start_term);
	snprintf_ret(buf, size, &ret, "server_event %d\n", qst.server_event);
	snprintf_ret(buf, size, &ret, "role %d (%s)\n",
		     qst.role, role_str(qst.role));
	snprintf_ret(buf, size, &ret, "vote_for %d\n",
		     qst.vote_for);
	snprintf_ret(buf, size, &ret, "vote_bits 0x%lx (count %lu)\n",
		     qst.vote_bits, hweight_long(qst.vote_bits));
	ts = ktime_to_timespec64(ktime_sub(qst.timeout, now));
	snprintf_ret(buf, size, &ret, "timeout_in_secs %lld.%09u\n",
		     (s64)ts.tv_sec, (int)ts.tv_nsec);

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		spin_lock(&qinf->show_lock);
		last = qinf->last_send[i];
		spin_unlock(&qinf->show_lock);

		if (last.msg.term == 0)
			continue;

		ts = ktime_to_timespec64(ktime_sub(now, last.ts));
		snprintf_ret(buf, size, &ret,
			     "last_send to %u term %llu type %u secs_since %lld.%09u\n",
			     i, last.msg.term, last.msg.type,
			     (s64)ts.tv_sec, (int)ts.tv_nsec);
	}

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		spin_lock(&qinf->show_lock);
		last = qinf->last_recv[i];
		spin_unlock(&qinf->show_lock);

		if (last.msg.term == 0)
			continue;

		ts = ktime_to_timespec64(ktime_sub(now, last.ts));
		snprintf_ret(buf, size, &ret,
			     "last_recv from %u term %llu type %u secs_since %lld.%09u\n",
			     i, last.msg.term, last.msg.type,
			     (s64)ts.tv_sec, (int)ts.tv_nsec);
	}

	spin_lock(&qinf->show_lock);
	ul = qinf->max_hb_delay;
	spin_unlock(&qinf->show_lock);
	if (ul)
		snprintf_ret(buf, size, &ret, "HB Delay(s)      Count  Secs Since\n");

	for (i = 1; i <= ul && i < HB_DELAY_NR; i++) {
		spin_lock(&qinf->show_lock);
		cr = qinf->hb_delay[i];
		spin_unlock(&qinf->show_lock);

		if (cr.count == 0)
			continue;

		ts = ktime_to_timespec64(ktime_sub(now, cr.recent));
		snprintf_ret(buf, size, &ret,
			     "%11u  %9llu  %lld.%09u\n",
			     i, cr.count, (s64)ts.tv_sec, (int)ts.tv_nsec);
	}

	return ret;
}
SCOUTFS_ATTR_RO(status);

static ssize_t is_leader_show(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	DECLARE_QUORUM_INFO_KOBJ(kobj, qinf);

	return snprintf(buf, PAGE_SIZE, "%u",
		        !!(qinf->show_status.role == LEADER));
}
SCOUTFS_ATTR_RO(is_leader);

static struct attribute *quorum_attrs[] = {
	SCOUTFS_ATTR_PTR(status),
	SCOUTFS_ATTR_PTR(is_leader),
	NULL,
};

static inline bool valid_ipv4_unicast(__be32 addr)
{
	return !(ipv4_is_multicast(addr) && ipv4_is_lbcast(addr) &&
		 ipv4_is_zeronet(addr) && ipv4_is_local_multicast(addr));
}

static inline bool valid_ipv4_port(__be16 port)
{
	return port != 0 && be16_to_cpu(port) != U16_MAX;
}

static int verify_quorum_slots(struct super_block *sb, struct quorum_info *qinf,
			       struct scoutfs_quorum_config *qconf)
{
	char slots[(SCOUTFS_QUORUM_MAX_SLOTS * 3) + 1];
	struct sockaddr_storage other;
	struct sockaddr_storage sin;
	struct sockaddr_in *sin4;
	struct sockaddr_in *other4;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in6 *other6;
	int found = 0;
	int ret;
	int i;
	int j;


	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (!quorum_slot_present(qconf, i))
			continue;

		if (quorum_slot_ipv4(qconf, i)) {
			scoutfs_quorum_slot_sin(qconf, i, &sin);
			sin4 = (struct sockaddr_in *)&sin;

			if (!valid_ipv4_unicast(sin4->sin_addr.s_addr)) {
				scoutfs_err(sb, "quorum slot #%d has invalid ipv4 unicast address: "SIN_FMT,
					    i, SIN_ARG(&sin));
				return -EINVAL;
			}

			if (!valid_ipv4_port(sin4->sin_port)) {
				scoutfs_err(sb, "quorum slot #%d has invalid ipv4 port number:"SIN_FMT,
					    i, SIN_ARG(&sin));
				return -EINVAL;
			}

			for (j = i + 1; j < SCOUTFS_QUORUM_MAX_SLOTS; j++) {
				if (!quorum_slot_ipv4(qconf, j))
					continue;

				scoutfs_quorum_slot_sin(qconf, j, &other);
				other4 = (struct sockaddr_in *)&other;

				if (sin4->sin_addr.s_addr == other4->sin_addr.s_addr &&
				    sin4->sin_port == other4->sin_port) {
					scoutfs_err(sb, "quorum slots #%u and #%u have the same address: "SIN_FMT,
						    i, j, SIN_ARG(&sin));
					return -EINVAL;
				}
			}

			found++;
		} else if (quorum_slot_ipv6(qconf, i)) {
			quorum_slot_sin(qconf, i, &sin);
			sin6 = (struct sockaddr_in6 *)&sin;

			if ((sin6->sin6_addr.in6_u.u6_addr32[0] == 0) && (sin6->sin6_addr.in6_u.u6_addr32[1] == 0) &&
			    (sin6->sin6_addr.in6_u.u6_addr32[2] == 0) && (sin6->sin6_addr.in6_u.u6_addr32[3] == 0)) {
				scoutfs_err(sb, "quorum slot #%d has unspecified ipv6 address:"SIN_FMT,
					    i, SIN_ARG(&sin));
				return -EINVAL;
			}

			if (sin6->sin6_addr.in6_u.u6_addr8[0] == 0xff) {
				scoutfs_err(sb, "quorum slot #%d has multicast ipv6 address:"SIN_FMT,
					    i, SIN_ARG(&sin));
				return -EINVAL;
			}

			if (!valid_ipv4_port(sin6->sin6_port)) {
				scoutfs_err(sb, "quorum slot #%d has invalid ipv6 port number:"SIN_FMT,
					    i,  SIN_ARG(&sin));
				return -EINVAL;
			}

			for (j = i + 1; j < SCOUTFS_QUORUM_MAX_SLOTS; j++) {
				if (!quorum_slot_ipv6(qconf, j))
					continue;

				quorum_slot_sin(qconf, j, &other);
				other6 = (struct sockaddr_in6 *)&other;

				if ((ipv6_addr_equal(&sin6->sin6_addr, &other6->sin6_addr)) &&
				    (sin6->sin6_port == other6->sin6_port)) {
					scoutfs_err(sb, "quorum slots #%u and #%u have the same address: "SIN_FMT,
						    i, j, SIN_ARG(&sin));
					return -EINVAL;
				}
			}

			found++;
		}
	}

	if (found == 0)  {
		scoutfs_err(sb, "no populated quorum slots in superblock");
		return -EINVAL;
	}

	if (!quorum_slot_present(qconf, qinf->our_quorum_slot_nr)) {
		char *str = slots;
		*str = '\0';
		for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
			if (quorum_slot_present(qconf, i)) {
				ret = snprintf(str, &slots[ARRAY_SIZE(slots)] - str, "%c%u",
					       str == slots ? ' ' : ',', i);
				if (ret < 2 || ret > 3) {
					scoutfs_err(sb, "error gathering populated slots");
					return -EINVAL;
				}
				str += ret;
			}
		}
		scoutfs_err(sb, "quorum_slot_nr=%u option references unused slot, must be one of the following configured slots:%s",
			    qinf->our_quorum_slot_nr, slots);
		return -EINVAL;
	}

	/*
	 * Always require a majority except in the pathological cases of
	 * 1 or 2 members.
	 */
	if (found < 3)
		qinf->votes_needed = 1;
	else
		qinf->votes_needed = (found / 2) + 1;

	qinf->qconf = *qconf;

	return 0;
}

/*
 * Once this schedules the quorum worker it can be elected leader and
 * start the server, possibly before this returns.  The quorum agent
 * would be responsible for tracking the quorum config in the super
 * block if it changes.  Until then uses a static config that it reads
 * during setup.
 */
int scoutfs_quorum_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_mount_options opts;
	struct quorum_info *qinf;
	int ret;

	scoutfs_options_read(sb, &opts);
	if (opts.quorum_slot_nr < 0)
		return 0;

	qinf = kzalloc(sizeof(struct quorum_info), GFP_KERNEL);
	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_KERNEL);
	if (qinf)
		qinf->hb_delay = kc__vmalloc(HB_DELAY_NR * sizeof(struct count_recent),
					   GFP_KERNEL | __GFP_ZERO);
	if (!qinf || !super || !qinf->hb_delay) {
		if (qinf)
			vfree(qinf->hb_delay);
		kfree(qinf);
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_init(&qinf->show_lock);
	INIT_WORK(&qinf->work, scoutfs_quorum_worker);
	scoutfs_sysfs_init_attrs(sb, &qinf->ssa);
	/* static for the lifetime of the mount */
	qinf->our_quorum_slot_nr = opts.quorum_slot_nr;

	sbi->quorum_info = qinf;
	qinf->sb = sb;

	/* a high priority single threaded context without mem reclaim */
	qinf->workq = alloc_workqueue("scoutfs_quorum_work",
				       WQ_NON_REENTRANT | WQ_UNBOUND |
				       WQ_HIGHPRI, 1);
	if (!qinf->workq) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_read_super(sb, super);
	if (ret < 0)
		goto out;

	ret = verify_quorum_slots(sb, qinf, &super->qconf);
	if (ret < 0)
		goto out;

	/* create in setup so errors cause mount to fail */
	ret = create_socket(sb);
	if (ret < 0)
		goto out;

	ret = scoutfs_sysfs_create_attrs(sb, &qinf->ssa, quorum_attrs,
					 "quorum");
	if (ret < 0)
		goto out;

	queue_work(qinf->workq, &qinf->work);

out:
	if (ret)
		scoutfs_quorum_destroy(sb);

	kfree(super);
	return ret;
}

/*
 * Shutdown the quorum worker and destroy all our resources.
 *
 * This is called after client destruction which only completes once
 * farewell requests are resolved. That only happens for a quorum member
 * once it isn't needed for quorum.
 *
 * The work is the only place that starts the server, and it stops the
 * server as it exits, so we can wait for it to finish and know that no
 * server can be running to call back into us as it shuts down.
 */
void scoutfs_quorum_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct quorum_info *qinf = SCOUTFS_SB(sb)->quorum_info;

	if (qinf) {
		qinf->shutdown = true;
		flush_work(&qinf->work);

		if (qinf->workq)
			destroy_workqueue(qinf->workq);

		scoutfs_sysfs_destroy_attrs(sb, &qinf->ssa);
		if (qinf->sock)
			sock_release(qinf->sock);

		vfree(qinf->hb_delay);
		kfree(qinf);
		sbi->quorum_info = NULL;
	}
}
