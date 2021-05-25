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
 * They set a flag in their block indicating that they've been elected
 * leader, then read slots for all the other blocks looking for
 * previously active leaders to fence.  After that it can start the
 * server.
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
	struct timespec64 ts;
};

enum quorum_role { FOLLOWER, CANDIDATE, LEADER };

struct quorum_status {
	enum quorum_role role;
	u64 term;
	int vote_for;
	unsigned long vote_bits;
	ktime_t timeout;
};

struct quorum_info {
	struct super_block *sb;
	struct work_struct work;
	struct socket *sock;
	bool shutdown;

	unsigned long flags;
	int votes_needed;

	spinlock_t show_lock;
	struct quorum_status show_status;
	struct last_msg last_send[SCOUTFS_QUORUM_MAX_SLOTS];
	struct last_msg last_recv[SCOUTFS_QUORUM_MAX_SLOTS];

	struct scoutfs_sysfs_attrs ssa;
};

#define QINF_FLAG_SERVER 0

#define DECLARE_QUORUM_INFO(sb, name) \
	struct quorum_info *name = SCOUTFS_SB(sb)->quorum_info
#define DECLARE_QUORUM_INFO_KOBJ(kobj, name) \
	DECLARE_QUORUM_INFO(SCOUTFS_SYSFS_ATTRS_SB(kobj), name)

static bool quorum_slot_present(struct scoutfs_super_block *super, int i)
{
	BUG_ON(i < 0 || i > SCOUTFS_QUORUM_MAX_SLOTS);

	return super->qconf.slots[i].addr.v4.family == cpu_to_le16(SCOUTFS_AF_IPV4);
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

static ktime_t heartbeat_timeout(void)
{
	return ktime_add_ms(ktime_get(), SCOUTFS_QUORUM_HB_TIMEO_MS);
}

static int create_socket(struct super_block *sb)
{
	DECLARE_QUORUM_INFO(sb, qinf);
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct mount_options *opts = &sbi->opts;
	struct scoutfs_super_block *super = &sbi->super;
	struct socket *sock = NULL;
	struct sockaddr_in sin;
	int addrlen;
	int ret;

	ret = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret) {
		scoutfs_err(sb, "quorum couldn't create udp socket: %d", ret);
		goto out;
	}

	sock->sk->sk_allocation = GFP_NOFS;

	scoutfs_quorum_slot_sin(super, opts->quorum_slot_nr, &sin);

	addrlen = sizeof(sin);
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

static void send_msg_members(struct super_block *sb, int type, u64 term,
			     int only)
{
	DECLARE_QUORUM_INFO(sb, qinf);
	struct mount_options *opts = &SCOUTFS_SB(sb)->opts;
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct timespec64 ts;
	int i;

	struct scoutfs_quorum_message qmes = {
		.fsid = super->hdr.fsid,
		.term = cpu_to_le64(term),
		.type = type,
		.from = opts->quorum_slot_nr,
	};
	struct kvec kv =  {
		.iov_base = &qmes,
		.iov_len = sizeof(qmes),
	};
	struct sockaddr_in sin;
	struct msghdr mh = {
		.msg_iov = (struct iovec *)&kv,
		.msg_iovlen = 1,
		.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
		.msg_name = &sin,
		.msg_namelen = sizeof(sin),
	};

	trace_scoutfs_quorum_send_message(sb, term, type, only);

	qmes.crc = quorum_message_crc(&qmes);

	ts = ktime_to_timespec64(ktime_get());

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (!quorum_slot_present(super, i) ||
		    (only >= 0 && i != only) || i == opts->quorum_slot_nr)
			continue;

		scoutfs_quorum_slot_sin(super, i, &sin);
		kernel_sendmsg(qinf->sock, &mh, &kv, 1, kv.iov_len);

		spin_lock(&qinf->show_lock);
		qinf->last_send[i].msg.term = term;
		qinf->last_send[i].msg.type = type;
		qinf->last_send[i].ts = ts;
		spin_unlock(&qinf->show_lock);

		if (i == only)
			break;
	}
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
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	struct scoutfs_quorum_message qmes;
	struct timeval tv;
	ktime_t rel_to;
	ktime_t now;
	int ret;

	struct kvec kv =  {
		.iov_base = &qmes,
		.iov_len = sizeof(struct scoutfs_quorum_message),
	};
	struct msghdr mh = {
		.msg_iov = (struct iovec *)&kv,
		.msg_iovlen = 1,
		.msg_flags = MSG_NOSIGNAL,
	};

	memset(msg, 0, sizeof(*msg));

	now = ktime_get();
	if (ktime_before(now, abs_to))
		rel_to = ktime_sub(abs_to, now);
	else
		rel_to = ns_to_ktime(0);

	tv = ktime_to_timeval(rel_to);
	if (tv.tv_sec == 0 && tv.tv_usec == 0) {
		mh.msg_flags |= MSG_DONTWAIT;
	} else {
		ret = kernel_setsockopt(qinf->sock, SOL_SOCKET, SO_RCVTIMEO,
					(char *)&tv, sizeof(tv));
		if (ret < 0)
			return ret;
	}

	ret = kernel_recvmsg(qinf->sock, &mh, &kv, 1, kv.iov_len, mh.msg_flags);
	if (ret < 0)
		return ret;

	if (ret != sizeof(qmes) ||
	    qmes.crc != quorum_message_crc(&qmes) ||
	    qmes.fsid != super->hdr.fsid ||
	    qmes.type >= SCOUTFS_QUORUM_MSG_INVALID ||
	    qmes.from >= SCOUTFS_QUORUM_MAX_SLOTS ||
	    !quorum_slot_present(super, qmes.from)) {
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
	qinf->last_recv[msg->from].ts = ktime_to_timespec64(ktime_get());
	spin_unlock(&qinf->show_lock);

	return 0;
}

/*
 * The caller can provide a mark that they're using to track their
 * written blocks.  It's updated as they write the block and we can
 * compare it with what we read to see if there have been unexpected
 * intervening writes to the block -- the caller is supposed to have
 * exclusive access to the block (or was fenced).
 */
static int read_quorum_block(struct super_block *sb, u64 blkno,
			     struct scoutfs_quorum_block *blk, __le64 *mark)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
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
	else if (blk->hdr.fsid != super->hdr.fsid)
		snprintf(msg, sizeof(msg), "blk fsid %016llx != %016llx",
			 le64_to_cpu(blk->hdr.fsid), le64_to_cpu(super->hdr.fsid));
	else if (le64_to_cpu(blk->hdr.blkno) != blkno)
		snprintf(msg, sizeof(msg), "blk blkno %llu != %llu",
			 le64_to_cpu(blk->hdr.blkno), blkno);
	else if (mark && *mark != 0 && blk->random_write_mark != *mark)
		snprintf(msg, sizeof(msg), "blk mark %016llx != %016llx, are multiple mounts configured with the same slot?",
			 le64_to_cpu(blk->random_write_mark), le64_to_cpu(*mark));
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

static void set_quorum_block_event(struct super_block *sb,
				   struct scoutfs_quorum_block *blk,
				   struct scoutfs_quorum_block_event *ev)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct timespec64 ts;

	getnstimeofday64(&ts);

	ev->rid = cpu_to_le64(sbi->rid);
	ev->ts.sec = cpu_to_le64(ts.tv_sec);
	ev->ts.nsec = cpu_to_le32(ts.tv_nsec);
}

/*
 * Every time we write a block we update the write stamp and random
 * write mark so readers can see our write.
 */
static int write_quorum_block(struct super_block *sb, u64 blkno,
			      struct scoutfs_quorum_block *blk, __le64 *mark)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret;

	if (WARN_ON_ONCE(blkno < SCOUTFS_QUORUM_BLKNO) ||
	    WARN_ON_ONCE(blkno >= (SCOUTFS_QUORUM_BLKNO +
				   SCOUTFS_QUORUM_BLOCKS)))
		return -EINVAL;

	do {
		get_random_bytes(&blk->random_write_mark,
				 sizeof(blk->random_write_mark));
	} while (blk->random_write_mark == 0);

	if (mark)
		*mark = blk->random_write_mark;

	set_quorum_block_event(sb, blk, &blk->write);

	ret = scoutfs_block_write_sm(sb, sbi->meta_bdev, blkno,
				      &blk->hdr, sizeof(*blk));
	if (ret < 0)
		scoutfs_err(sb, "quorum block write error %d", ret);

	return ret;
}

/*
 * Read the caller's slot's current quorum block, make a change, and
 * write it back out.  If the caller provides a mark it can cause read
 * errors if we read a mark that doesn't match the last mark that the
 * caller wrote.
 */
static int update_quorum_block(struct super_block *sb, u64 blkno,
			       __le64 *mark, int role, u64 term)
{
	struct scoutfs_quorum_block blk;
	u64 flags;
	u64 bits;
	u64 set;
	int ret;

	ret = read_quorum_block(sb, blkno, &blk, mark);
	if (ret == 0) {
		if (blk.term != cpu_to_le64(term)) {
			blk.term = cpu_to_le64(term);
			set_quorum_block_event(sb, &blk, &blk.update_term);
		}

		flags = le64_to_cpu(blk.flags);
		bits = SCOUTFS_QUORUM_BLOCK_LEADER;
		set = role == LEADER ? SCOUTFS_QUORUM_BLOCK_LEADER : 0;
		if ((flags & bits) != set)
			set_quorum_block_event(sb, &blk,
					       set ? &blk.set_leader :
					             &blk.clear_leader);
		blk.flags = cpu_to_le64((flags & ~bits) | set);

		ret = write_quorum_block(sb, blkno, &blk, mark);
	}

	return ret;
}

/*
 * The calling server had fenced previous leaders before starting up,
 * now that it's up it has reclaimed their resources and can clear their
 * leader flags.
 */
int scoutfs_quorum_clear_rid_leader(struct super_block *sb, u64 rid)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct mount_options *opts = &sbi->opts;
	struct scoutfs_quorum_block blk;
	int ret = 0;
	u64 blkno;
	int i;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (i == opts->quorum_slot_nr || !quorum_slot_present(super, i))
			continue;

		blkno = SCOUTFS_QUORUM_BLKNO + i;
		ret = read_quorum_block(sb, blkno, &blk, NULL);
		if (ret < 0)
			break;

		if (le64_to_cpu(blk.set_leader.rid) == rid) {
			blk.flags &= ~cpu_to_le64(SCOUTFS_QUORUM_BLOCK_LEADER);
			set_quorum_block_event(sb, &blk, &blk.fenced);

			ret = write_quorum_block(sb, blkno, &blk, NULL);
			break;
		}
	}

	if (ret < 0)
		scoutfs_err(sb, "error %d clearing leader block for rid %016llx", ret, rid);

	return ret;
}

/*
 * The calling server has been elected, had its block updated, and has
 * started running but can't yet assume that it has exclusive access to
 * the metadata device.  We read all the quorum blocks looking for
 * previously elected leaders to fence so that we're the only leader
 * running.
 *
 * We only wait for the previous leaders to be fenced.  We don't clear
 * the leader bits because the server is going to reclaim their
 * resources once its up and running.  Only then will the leader bits be
 * cleared.
 *
 * Quorum will be sending heartbeats while we wait for fencing.  That
 * keeps us from being fenced while we allow userspace fencing to take a
 * reasonably long time.  We still want to timeout eventually.
 */
int scoutfs_quorum_fence_leader_blocks(struct super_block *sb, u64 term)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct mount_options *opts = &sbi->opts;
	struct scoutfs_quorum_block blk;
	struct sockaddr_in sin;
	bool fence_started = false;
	u64 blkno;
	int ret = 0;
	int err;
	int i;

	BUILD_BUG_ON(SCOUTFS_QUORUM_BLOCKS < SCOUTFS_QUORUM_MAX_SLOTS);

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (i == opts->quorum_slot_nr || !quorum_slot_present(super, i))
			continue;

		blkno = SCOUTFS_QUORUM_BLKNO + i;
		ret = read_quorum_block(sb, blkno, &blk, NULL);
		if (ret < 0)
			goto out;

		if (!(le64_to_cpu(blk.flags) & SCOUTFS_QUORUM_BLOCK_LEADER) ||
		    le64_to_cpu(blk.term) > term)
			continue;

		scoutfs_inc_counter(sb, quorum_fence_leader);
		scoutfs_quorum_slot_sin(super, i, &sin);

		scoutfs_info(sb, "fencing previous leader "SCSBF" in slot %u with address "SIN_FMT,
			     SCSB_LEFR_ARGS(super->hdr.fsid, blk.set_leader.rid), i, SIN_ARG(&sin));
		ret = scoutfs_fence_start(sb, le64_to_cpu(blk.set_leader.rid), sin.sin_addr.s_addr,
					  SCOUTFS_FENCE_QUORUM_BLOCK_LEADER);
		if (ret < 0)
			goto out;
		fence_started = true;

	}

out:
	if (fence_started) {
		err = scoutfs_fence_wait_fenced(sb, msecs_to_jiffies(SCOUTFS_QUORUM_FENCE_TO_MS));
		if (ret == 0)
			ret = err;
	}
	if (ret < 0) {
		scoutfs_err(sb, "error %d fencing leader blocks", ret);
		scoutfs_inc_counter(sb, quorum_fence_error);
	}

	return ret;
}

/*
 * The quorum work always runs in the background of quorum member
 * mounts.  It's responsible for starting and stopping the server if
 * it's elected leader, and the server can call back into it to let it
 * know that it has shut itself down (perhaps due to error) so that the
 * work should stop sending heartbeats.
 */
static void scoutfs_quorum_worker(struct work_struct *work)
{
	struct quorum_info *qinf = container_of(work, struct quorum_info, work);
	struct super_block *sb = qinf->sb;
	struct mount_options *opts = &SCOUTFS_SB(sb)->opts;
	struct scoutfs_quorum_block blk;
	struct sockaddr_in unused;
	struct quorum_host_msg msg;
	struct quorum_status qst;
	__le64 mark;
	u64 blkno;
	int ret;

	/* recording votes from slots as native single word bitmap */
	BUILD_BUG_ON(SCOUTFS_QUORUM_MAX_SLOTS > BITS_PER_LONG);

	/* get our starting term from our persistent block */
	mark = 0;
	blkno = SCOUTFS_QUORUM_BLKNO + opts->quorum_slot_nr;
	ret = read_quorum_block(sb, blkno, &blk, &mark);
	if (ret < 0)
		goto out;

	/* start out as a follower */
	qst.role = FOLLOWER;
	qst.term = le64_to_cpu(blk.term);
	qst.vote_for = -1;
	qst.vote_bits = 0;

	/* see if there's a server to chose heartbeat or election timeout */
	if (scoutfs_quorum_server_sin(sb, &unused) == 0)
		qst.timeout = heartbeat_timeout();
	else
		qst.timeout = election_timeout();

	while (!qinf->shutdown) {

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

		/* ignore messages from older terms */
		if (msg.type != SCOUTFS_QUORUM_MSG_INVALID &&
		    msg.term < qst.term)
			msg.type = SCOUTFS_QUORUM_MSG_INVALID;

		/* if the server has shutdown we become follower */
		if (!test_bit(QINF_FLAG_SERVER, &qinf->flags) &&
		    qst.role == LEADER) {
			qst.role = FOLLOWER;
			qst.vote_for = -1;
			qst.vote_bits = 0;
			qst.timeout = election_timeout();
			scoutfs_inc_counter(sb, quorum_server_shutdown);

			send_msg_others(sb, SCOUTFS_QUORUM_MSG_RESIGNATION,
					qst.term);
			scoutfs_inc_counter(sb, quorum_send_resignation);

			ret = update_quorum_block(sb, blkno, &mark,
						  qst.role, qst.term);
			if (ret < 0)
				goto out;
		}

		spin_lock(&qinf->show_lock);
		qinf->show_status = qst;
		spin_unlock(&qinf->show_lock);

		trace_scoutfs_quorum_loop(sb, qst.role, qst.term, qst.vote_for,
					  qst.vote_bits,
					  ktime_to_timespec64(qst.timeout));

		/* receiving greater terms resets term, becomes follower */
		if (msg.type != SCOUTFS_QUORUM_MSG_INVALID &&
		    msg.term > qst.term) {
			if (qst.role == LEADER) {
				scoutfs_warn(sb, "saw msg type %u from %u for term %llu while leader in term %llu, shutting down server.",
					     msg.type, msg.from, msg.term, qst.term);
				scoutfs_server_stop(sb);
			}
			qst.role = FOLLOWER;
			qst.term = msg.term;
			qst.vote_for = -1;
			qst.vote_bits = 0;
			scoutfs_inc_counter(sb, quorum_term_follower);

			if (msg.type == SCOUTFS_QUORUM_MSG_HEARTBEAT)
				qst.timeout = heartbeat_timeout();
			else
				qst.timeout = election_timeout();

			/* store our increased term */
			ret = update_quorum_block(sb, blkno, &mark,
						  qst.role, qst.term);
			if (ret < 0)
				goto out;
		}

		/* followers and candidates start new election on timeout */
		if (qst.role != LEADER &&
		    ktime_after(ktime_get(), qst.timeout)) {
			qst.role = CANDIDATE;
			qst.term++;
			qst.vote_for = -1;
			qst.vote_bits = 0;
			set_bit(opts->quorum_slot_nr, &qst.vote_bits);
			send_msg_others(sb, SCOUTFS_QUORUM_MSG_REQUEST_VOTE,
					qst.term);
			qst.timeout = election_timeout();
			scoutfs_inc_counter(sb, quorum_send_request);
		}

		/* candidates count votes in their term */
		if (qst.role == CANDIDATE &&
		    msg.type == SCOUTFS_QUORUM_MSG_VOTE) {
			if (test_bit(msg.from, &qst.vote_bits)) {
				scoutfs_warn(sb, "already received vote from %u in term %llu, are there multiple mounts with quorum_slot_nr=%u?",
					     msg.from, qst.term, msg.from);
			}
			set_bit(msg.from, &qst.vote_bits);
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

			/* set our leader flag before starting server */
			ret = update_quorum_block(sb, blkno, &mark, qst.role, qst.term);
			if (ret < 0)
				goto out;

			/* make very sure server is fully shut down */
			scoutfs_server_stop(sb);
			/* set server bit before server shutdown could clear */
			set_bit(QINF_FLAG_SERVER, &qinf->flags);

			ret = scoutfs_server_start(sb, qst.term);
			if (ret < 0) {
				scoutfs_err(sb, "server startup failed with %d",
					    ret);
				goto out;
			}
		}

		/* leaders regularly send heartbeats to delay elections */
		if (qst.role == LEADER &&
		    ktime_after(ktime_get(), qst.timeout)) {
			send_msg_others(sb, SCOUTFS_QUORUM_MSG_HEARTBEAT,
					qst.term);
			qst.timeout = heartbeat_interval();
			scoutfs_inc_counter(sb, quorum_send_heartbeat);
		}

		/* receiving heartbeats extends timeout, delaying elections */
		if (msg.type == SCOUTFS_QUORUM_MSG_HEARTBEAT) {
			qst.timeout = heartbeat_timeout();
			scoutfs_inc_counter(sb, quorum_recv_heartbeat);
		}

		/* receiving a resignation from server starts election */
		if (msg.type == SCOUTFS_QUORUM_MSG_RESIGNATION &&
		    qst.role == FOLLOWER &&
		    msg.term == qst.term) {
			qst.timeout = election_timeout();
			scoutfs_inc_counter(sb, quorum_recv_resignation);
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
	}

	/* always try to stop a running server as we stop */
	if (test_bit(QINF_FLAG_SERVER, &qinf->flags)) {
		scoutfs_server_stop(sb);
		scoutfs_fence_stop(sb);
		send_msg_others(sb, SCOUTFS_QUORUM_MSG_RESIGNATION,
				qst.term);
	}

	/* always try to clear leader block as we stop to avoid fencing */
	if (qst.role == LEADER) {
		ret = update_quorum_block(sb, blkno, &mark,
					  FOLLOWER, qst.term);
		if (ret < 0)
			goto out;
	}
out:
	if (ret < 0) {
		scoutfs_err(sb, "quorum service saw error %d, shutting down.  Cluster will be degraded until this slot is remounted to restart the quorum service",
			    ret);
	}
}

/*
 * Clear the server flag for the quorum work's next iteration to
 * indicate that the server has shutdown and that it should step down as
 * leader, update quorum blocks, and stop sending heartbeats.
 */
void scoutfs_quorum_server_shutdown(struct super_block *sb)
{
	DECLARE_QUORUM_INFO(sb, qinf);

	clear_bit(QINF_FLAG_SERVER, &qinf->flags);
}

/*
 * Clients read quorum blocks looking for the leader with a server whose
 * address it can try and connect to.
 *
 * There can be multiple running servers if a client checks before a
 * server has had a chance to fence any old servers.  We try to use the
 * block with the most recent timestamp.  If we get it wrong the
 * connection will timeout and the client will try again, presumably
 * finding a single server block.
 */
int scoutfs_quorum_server_sin(struct super_block *sb, struct sockaddr_in *sin)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super = &sbi->super;
	struct scoutfs_quorum_block blk;
	struct timespec64 recent = {0,};
	struct timespec64 ts;
	int ret;
	int i;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		ret = read_quorum_block(sb, SCOUTFS_QUORUM_BLKNO + i, &blk,
					NULL);
		if (ret < 0) {
			scoutfs_err(sb, "error reading quorum block nr %u: %d",
				    i, ret);
			goto out;
		}

		ts.tv_sec = le64_to_cpu(blk.set_leader.ts.sec);
		ts.tv_nsec = le32_to_cpu(blk.set_leader.ts.nsec);

		if ((le64_to_cpu(blk.flags) & SCOUTFS_QUORUM_BLOCK_LEADER) &&
		    (timespec64_to_ns(&ts) > timespec64_to_ns(&recent))) {
			recent = ts;
			scoutfs_quorum_slot_sin(super, i, sin);
			continue;
		}
	}

	if (timespec64_to_ns(&recent) == 0)
		ret = -ENOENT;

out:
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

void scoutfs_quorum_slot_sin(struct scoutfs_super_block *super, int i,
			     struct sockaddr_in *sin)
{
	BUG_ON(i < 0 || i >= SCOUTFS_QUORUM_MAX_SLOTS);

	scoutfs_addr_to_sin(sin, &super->qconf.slots[i].addr);
}

static char *role_str(int role)
{
	static char *roles[] = {
		[FOLLOWER] = "follower",
		[CANDIDATE] = "candidate",
		[LEADER] = "leader",
	};

	if (role < 0 || role > ARRAY_SIZE(roles) || !roles[role])
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
	struct mount_options *opts = &SCOUTFS_SB(qinf->sb)->opts;
	struct quorum_status qst;
	struct last_msg last;
	struct timespec64 ts;
	size_t size;
	int ret;
	int i;

	spin_lock(&qinf->show_lock);
	qst = qinf->show_status;
	spin_unlock(&qinf->show_lock);

	size = PAGE_SIZE;
	ret = 0;

	snprintf_ret(buf, size, &ret, "quorum_slot_nr %u\n",
		     opts->quorum_slot_nr);
	snprintf_ret(buf, size, &ret, "term %llu\n",
		     qst.term);
	snprintf_ret(buf, size, &ret, "role %d (%s)\n",
		     qst.role, role_str(qst.role));
	snprintf_ret(buf, size, &ret, "vote_for %d\n",
		     qst.vote_for);
	snprintf_ret(buf, size, &ret, "vote_bits 0x%lx (count %lu)\n",
		     qst.vote_bits, hweight_long(qst.vote_bits));
	ts = ktime_to_timespec64(qst.timeout);
	snprintf_ret(buf, size, &ret, "timeout %llu.%u\n",
		     (u64)ts.tv_sec, (int)ts.tv_nsec);

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		spin_lock(&qinf->show_lock);
		last = qinf->last_send[i];
		spin_unlock(&qinf->show_lock);

		if (last.msg.term == 0)
			continue;

		snprintf_ret(buf, size, &ret,
			     "last_send to %u term %llu type %u ts %llu.%u\n",
			     i, last.msg.term, last.msg.type,
			     (u64)last.ts.tv_sec, (int)last.ts.tv_nsec);
	}

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		spin_lock(&qinf->show_lock);
		last = qinf->last_recv[i];
		spin_unlock(&qinf->show_lock);

		if (last.msg.term == 0)
			continue;
		snprintf_ret(buf, size, &ret,
			     "last_recv from %u term %llu type %u ts %llu.%u\n",
			     i, last.msg.term, last.msg.type,
			     (u64)last.ts.tv_sec, (int)last.ts.tv_nsec);
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

static int verify_quorum_slots(struct super_block *sb)
{
	struct scoutfs_super_block *super = &SCOUTFS_SB(sb)->super;
	DECLARE_QUORUM_INFO(sb, qinf);
	struct sockaddr_in other;
	struct sockaddr_in sin;
	int found = 0;
	int i;
	int j;

	for (i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		if (!quorum_slot_present(super, i))
			continue;

		scoutfs_quorum_slot_sin(super, i, &sin);

		if (!valid_ipv4_unicast(sin.sin_addr.s_addr)) {
			scoutfs_err(sb, "quorum slot #%d has invalid ipv4 unicast address: "SIN_FMT,
				    i,  SIN_ARG(&sin));
			return -EINVAL;
		}

		if (!valid_ipv4_port(sin.sin_port)) {
			scoutfs_err(sb, "quorum slot #%d has invalid ipv4 port number:"SIN_FMT,
				    i,  SIN_ARG(&sin));
			return -EINVAL;
		}

		for (j = i + 1; j < SCOUTFS_QUORUM_MAX_SLOTS; j++) {
			if (!quorum_slot_present(super, j))
				continue;

			scoutfs_quorum_slot_sin(super, j, &other);

			if (sin.sin_addr.s_addr == other.sin_addr.s_addr &&
			    sin.sin_port == other.sin_port) {
				scoutfs_err(sb, "quorum slots #%u and #%u have the same address: "SIN_FMT,
					    i, j, SIN_ARG(&sin));
				return -EINVAL;
			}
		}

		found++;
	}

	if (found == 0)  {
		scoutfs_err(sb, "no populated quorum slots in superblock");
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

	return 0;
}

/*
 * Once this schedules the quorum worker it can be elected leader and
 * start the server, possibly before this returns.
 */
int scoutfs_quorum_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct mount_options *opts = &sbi->opts;
	struct quorum_info *qinf;
	int ret;

	if (opts->quorum_slot_nr < 0)
		return 0;

	qinf = kzalloc(sizeof(struct quorum_info), GFP_KERNEL);
	if (!qinf) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_init(&qinf->show_lock);
	INIT_WORK(&qinf->work, scoutfs_quorum_worker);
	scoutfs_sysfs_init_attrs(sb, &qinf->ssa);

	sbi->quorum_info = qinf;
	qinf->sb = sb;

	ret = verify_quorum_slots(sb);
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

	schedule_work(&qinf->work);

out:
	if (ret)
		scoutfs_quorum_destroy(sb);

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

		scoutfs_sysfs_destroy_attrs(sb, &qinf->ssa);
		if (qinf->sock)
			sock_release(qinf->sock);

		kfree(qinf);
		sbi->quorum_info = NULL;
	}
}
