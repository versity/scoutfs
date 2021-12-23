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
#include <linux/rcupdate.h>
#include <linux/random.h>

#include "cwskip.h"

/*
 * This skip list is built to allow concurrent modification and limit
 * contention to the region of the list around the modification.  All
 * node references are protected by RCU.   Each node has a write_seq
 * that works like a seqlock, the big differences are that we nest them
 * and use trylock to acquire them.
 *
 * Readers sample the write_seqs of nodes containing links as they
 * traverse them, verifying that the node hasn't been modified before
 * traversing to the node referenced by the link.
 *
 * Writers remember the seqs of all the nodes they traversed to end up
 * at their final node.   They try to acquire the lock of all the nodes
 * needed to modify the list at a given height.   Their trylocks will
 * fail if any of the nodes have changed since their traversal.
 *
 * The interface is built around references to adjacent pairs of nodes
 * and their sequence numbers.   This lets readers and writers traverse
 * through their local region of the list until they hit contention and
 * must start over with a full search.
 *
 * The caller is responsible for allocating and freeing nodes.   The
 * interface is built around caller's objects which each have embedded
 * nodes.
 */

/*
 * node_off is the positive offset of the cwskip node within the
 * container structs stored in the list.  The node_off is subtracted
 * from node pointers to give the caller a pointer to their stored
 * container struct.
 */
void scoutfs_cwskip_init_root(struct scoutfs_cwskip_root *root, scoutfs_cwskip_cmp_t cmp_fn,
			      unsigned long node_off)
{
	memset(root, 0, sizeof(&root));
	root->cmp_fn = cmp_fn;
	root->node_off = node_off;
}

/* This is completely racey and should be used accordingly. */
bool scoutfs_cwskip_empty(struct scoutfs_cwskip_root *root)
{
	int i;

	for (i = 0; i < SCOUTFS_CWSKIP_MAX_HEIGHT; i++) {
		if (root->node.links[i] != NULL)
			return false;
	}

	return true;
}

/*
 * Return a random height between 1 and max height, inclusive.  Using
 * ffs means that each greater height relies on all lower height bits
 * being clear and we get the height distribution we want: 1 = 1/2,
 * 2 = 1/4, 3 = 1/8, etc.
 */
int scoutfs_cwskip_rand_height(void)
{
	return ffs(prandom_u32() | (1 << (SCOUTFS_CWSKIP_MAX_HEIGHT - 1)));
}

static void *node_container(struct scoutfs_cwskip_root *root, struct scoutfs_cwskip_node *node)
{
	return node ? (void *)((unsigned long)node - root->node_off) : NULL;
}

/*
 * Set the caller's containers for the given nodes.   There isn't a
 * previous container when the previous node is the root's static
 * full-height node.
 */
static void set_containers(struct scoutfs_cwskip_root *root, struct scoutfs_cwskip_node *prev,
			   struct scoutfs_cwskip_node *node, void **prev_cont, void **node_cont)
{
	if (prev_cont)
		*prev_cont = (prev != &root->node) ? node_container(root, prev) : NULL;
	if (node_cont)
		*node_cont = node_container(root, node);
}

static struct scoutfs_cwskip_node *node_read_begin(struct scoutfs_cwskip_node *node,
						   unsigned int *seq)
{
	if (node) {
		*seq = READ_ONCE(node->write_seq) & ~1U;
		smp_rmb();
	} else {
		*seq = 1;  /* caller shouldn't use if we return null, being careful */
	}

	return node;
}

static bool node_read_retry(struct scoutfs_cwskip_node *node, unsigned int seq)
{
	if (node) {
	       smp_rmb();
	       return READ_ONCE(node->write_seq) != seq;
	}

	return false;
}

/*
 * write_seq is only an int to reduce the size of nodes and full-height
 * seq arrays, it could be a long if archs have trouble with int
 * cmpxchg.
 */
static bool __node_trylock(struct scoutfs_cwskip_node *node, unsigned int seq)
{
	if (seq & 1)
		return false;

	return cmpxchg(&node->write_seq, seq, seq + 1) == seq;
}

static bool node_trylock(struct scoutfs_cwskip_node *node, unsigned int seq)
{
	bool locked = __node_trylock(node, seq);
	if (locked)
		smp_wmb();
	return locked;
}

static void __node_unlock(struct scoutfs_cwskip_node *node)
{
	node->write_seq++;
}

static void node_unlock(struct scoutfs_cwskip_node *node)
{
	__node_unlock(node);
	smp_wmb();
}

/* return -1/1 to go left/right, never 0 */
static int random_cmp(void *K, void *C)
{
	return (int)(prandom_u32() & 2) - 1;
}

static void cwskip_search(struct scoutfs_cwskip_root *root, void *key, int *node_cmp,
			  struct scoutfs_cwskip_reader *rd, struct scoutfs_cwskip_writer *wr,
			  unsigned int *prev_seqs)
{
	struct scoutfs_cwskip_node *prev;
	struct scoutfs_cwskip_node *node;
	scoutfs_cwskip_cmp_t cmp_fn;
	unsigned int prev_seq;
	unsigned int node_seq;
	int level;
	int cmp;

	if (key == NULL)
		cmp_fn = random_cmp;

restart:
	prev = node_read_begin(&root->node, &prev_seq);
	node = NULL;
	node_seq = 1;
	cmp = -1;

	level = SCOUTFS_CWSKIP_MAX_HEIGHT - 1;
	while (prev && level >= 0) {
		node = node_read_begin(prev->links[level], &node_seq);
		if (!node) {
			cmp = -1;
			level--;
			continue;
		}

		cmp = cmp_fn(key, node_container(root, node));
		if (cmp > 0) {
			if (node_read_retry(prev, prev_seq))
				goto restart;
			prev = node;
			prev_seq = node_seq;
			node = NULL;
			continue;
		}

		if (wr) {
			wr->prevs[level] = prev;
			prev_seqs[level] = prev_seq;
		}

		level--;
	}

	rd->prev = prev;
	rd->prev_seq = prev_seq;
	rd->node = node;
	rd->node_seq = node_seq;
	*node_cmp = cmp;
}

static void init_reader(struct scoutfs_cwskip_reader *rd, struct scoutfs_cwskip_root *root)
{
	memset(rd, 0, sizeof(struct scoutfs_cwskip_reader));
	rd->root = root;
}

/*
 * Find and returns nodes that surround the search key.
 *
 * Either prev or null can be null if there are no nodes before or after
 * the search key.  *node_cmp is set to the final comparison of the key
 * and the returned node's container key, it will be 0 if an exact match
 * is found.
 *
 * This starts an RCU read critical section and is fully concurrent with
 * both other readers and writers.   The nodes won't be freed until
 * after the section so its always safe to reference them but their
 * contents might be nonsense if they're modified during the read.
 * Nothing learned from the list during the read section should have an
 * effect until after _read_valid has said it was OK.
 *
 * _read_valid can be called after referencing the nodes to see if they
 * were stable during the read.  _read_next can be used to iterate
 * forward through the list without repeating the search.   The caller
 * must always call a matching _read_end once they're done.
 */
void scoutfs_cwskip_read_begin(struct scoutfs_cwskip_root *root, void *key, void **prev_cont,
			       void **node_cont, int *node_cmp, struct scoutfs_cwskip_reader *rd)
	__acquires(RCU) /* :/ */
{
	init_reader(rd, root);

	rcu_read_lock();
	cwskip_search(root, key, node_cmp, rd, NULL, NULL);
	set_containers(root, rd->prev, rd->node, prev_cont, node_cont);
}

/*
 * Returns true of the nodes referenced by the reader haven't been
 * modified and any references of them were consistent.  Thsi does not
 * end the reader critical section and can be called multiple times.
 */
bool scoutfs_cwskip_read_valid(struct scoutfs_cwskip_reader *rd)
{
	return !(node_read_retry(rd->prev, rd->prev_seq) &&
		 node_read_retry(rd->node, rd->node_seq));
}

/*
 * Advance from the current prev/node to the next pair of nodes in the
 * list.  prev_cont is set to what node_cont was before the call.
 * node_cont is set to the next node after the current node_cont.
 *
 * This returns true if it found a next node and that its load of the
 * next pointer from node was valid and stable.  Returning false means
 * that the caller should retry.  There could be more items in the list.
 */
bool scoutfs_cwskip_read_next(struct scoutfs_cwskip_reader *rd, void **prev_cont, void **node_cont)
{
	struct scoutfs_cwskip_node *next;
	unsigned int next_seq;
	bool valid_next;

	next = rd->node ? node_read_begin(rd->node->links[0], &next_seq) : NULL;
	valid_next = scoutfs_cwskip_read_valid(rd) && next;
	if (valid_next) {
		rd->prev = rd->node;
		rd->prev_seq = rd->node_seq;
		rd->node = next;
		rd->node_seq = next_seq;

		set_containers(rd->root, rd->prev, rd->node, prev_cont, node_cont);
	}

	return valid_next;
}

/*
 * End the critical section started with _read_begin.
 */
void scoutfs_cwskip_read_end(struct scoutfs_cwskip_reader *rd)
	__releases(RCU) /* :/ */
{
	rcu_read_unlock();
}

/*
 * Higher locks are more likely to cause contention so we unlock them
 * first.
 */
static void writer_unlock(struct scoutfs_cwskip_writer *wr)
{
	int i;

	for (i = wr->locked_height - 1; i >= 0; i--) {
		if (i == 0 || (wr->prevs[i - 1] != wr->prevs[i]))
			__node_unlock(wr->prevs[i]);
	}

	if (wr->node_locked)
		__node_unlock(wr->node);

	smp_wmb();

	wr->locked_height = 0;
	wr->node_locked = false;
}

/*
 * A search traversal has saved all the previous nodes at each level.
 *
 * We try to acquire the write_seq locks for all the prevs up to height
 * from the seqs that we read during the search.   The search was
 * protected by read sections so the prevs represent a consistent
 * version of the list at some point in the past.  If nodes have been
 * locked since we read them we won't be able to acquire the locks.
 * Nodes aren't re-inserted after removal so we shouldn't see nodes in
 * multiple places (which would deadlock).
 *
 * The same node can be in multiple prev slots.  We're careful to only
 * try locking the lowest duplicate slot.
 *
 * We lock from the highest level down.   This only matters when there's
 * contention.   The higher nodes are more likely to see contention so
 * we want trylock to fail early to avoid useless locking churn on lower
 * nodes.
 */
static bool writer_trylock(struct scoutfs_cwskip_writer *wr, unsigned int *prev_seqs, int height)
{
	int i;

	if (WARN_ON_ONCE(wr->locked_height != 0) ||
	    WARN_ON_ONCE(height < 1 || height > ARRAY_SIZE(wr->prevs)))
		return false;

	for (i = height - 1; i >= 0; i--) {
		if ((i == 0 || wr->prevs[i - 1] != wr->prevs[i]) &&
		    !__node_trylock(wr->prevs[i], prev_seqs[i]))
			break;
		wr->locked_height++;
	}

	if (i < height) {
		writer_unlock(wr);
		return false;
	}

	/* paranoid debugging verification */
	for (i = 0; i < wr->locked_height; i++) {
		BUG_ON(wr->prevs[i]->height <= i);
		BUG_ON(wr->node && i < wr->node->height && wr->prevs[i]->links[i] != wr->node);
	}

	smp_mb();
	return true;
}

static void init_writer(struct scoutfs_cwskip_writer *wr, struct scoutfs_cwskip_root *root)
{
	memset(wr, 0, sizeof(struct scoutfs_cwskip_writer));
	wr->root = root;
}

/*
 * Search for and return references to the two nodes that surround the
 * search key, with the nodes locked.
 *
 * Either node can be null if there are no nodes before or after the
 * search key.  We still hold a lock on the static root node if the
 * search key falls before the first node in the list.
 *
 * If lock_height is 0 then the caller is saying that they just want to
 * lock the surrounding nodes and not modify their position in the list.
 * We only lock those two nodes.  Any greater lock_height represents a
 * height that we need to lock so the caller can insert an allocated
 * node with that height.
 *
 * The caller can use the writer context to iterate through locked nodes
 * via the lowest level list that contains all nodes.  If they hit a
 * node that's higher than the locked height in the writer then they
 * have to unlock and restart because we don't have the previous node
 * for that height.  We set a min level that we lock to reduce the
 * possibility of hitting higher nodes and retrying.
 */
#define MIN_LOCKED_HEIGHT 4
void scoutfs_cwskip_write_begin(struct scoutfs_cwskip_root *root, void *key, int lock_height,
				void **prev_cont, void **node_cont, int *node_cmp,
				struct scoutfs_cwskip_writer *wr)
	__acquires(RCU) /* :/ */
{
	unsigned int prev_seqs[SCOUTFS_CWSKIP_MAX_HEIGHT];
	struct scoutfs_cwskip_reader rd;
	int node_height;
	int use_height;
	bool locked;

	BUG_ON(WARN_ON_ONCE(lock_height < 0 || lock_height > SCOUTFS_CWSKIP_MAX_HEIGHT));

	do {
		init_reader(&rd, root);
		init_writer(wr, root);

		rcu_read_lock();
		cwskip_search(root, key, node_cmp, &rd, wr, NULL);

		wr->node = rd.node;
		if (wr->node) {
			/* _trylock of prevs will issue barrier on success */
			if (!__node_trylock(wr->node, rd.node_seq)) {
				locked = false;
				continue;
			}
			wr->node_locked = true;
			node_height = wr->node->height;
		} else {
			node_height = 0;
		}

		if (lock_height > 0)
			use_height = max3(MIN_LOCKED_HEIGHT, node_height, lock_height);
		else
			use_height = 1;

		locked = writer_trylock(wr, prev_seqs, use_height);
		if (!locked)
			rcu_read_unlock();
	} while (!locked);

	set_containers(root, wr->prevs[0], wr->node, prev_cont, node_cont);
}

/*
 * Insert a new node between the writer's two locked nodes.  The
 * inserting node is locked and replaces the existing node in the writer
 * which is unlocked.
 *
 * The next node may not exist.   The previous nodes will always exist
 * though they may be the static root node.
 *
 * The inserting node is visible to readers the moment we store the
 * first link to it in previous nodes.  We first lock it with a write
 * barrier so that any readers will retry if they visit it before all
 * its links are updated and its unlocked.
 *
 * We don't unlock prevs that are higher than the inserting node.  This
 * lets the caller continue iterating through nodes that are higher than
 * insertion but still under the locked height.
 */
void scoutfs_cwskip_write_insert(struct scoutfs_cwskip_writer *wr,
				 struct scoutfs_cwskip_node *ins)
{
	struct scoutfs_cwskip_node *node = wr->node;
	int i;

	BUG_ON(ins->height > wr->locked_height);
	node_trylock(ins, ins->write_seq);

	for (i = 0; i < ins->height; i++) {
		ins->links[i] = wr->prevs[i]->links[i];
		wr->prevs[i]->links[i] = ins;
	}

	if (node)
		node_unlock(node);
	wr->node = ins;
}

/*
 * Remove the node in the writer from the list.  The writers node
 * pointer is not advanced because we don't want this to be able to fail
 * if trylock on the next node fails.  The caller can call _write_next
 * on this writer and it will try and iterate from prevs[0].
 *
 * The caller's removal argument must be the node pointer in the writer.
 * This is redundant but meant to communicate to the caller that they're
 * responsible for the node after removing it (presumably queueing it
 * for freeing before _write_end leaves rcu).
 *
 * Readers can be traversing our node as we modify its pointers and can
 * read a temporarily inconsistent state.  We have the node locked so
 * the reader will immediately retry once the check the seqs after
 * hitting our node that's being removed.
 */
void scoutfs_cwskip_write_remove(struct scoutfs_cwskip_writer *wr,
				 struct scoutfs_cwskip_node *node)
{
	int i;

	BUG_ON(node != wr->node);
	BUG_ON(node->height > wr->locked_height);

	for (i = 0; i < node->height; i++) {
		wr->prevs[i]->links[i] = node->links[i];
		node->links[i] = NULL;
	}

	node_unlock(node);
	wr->node = NULL;
}

/*
 * Advance through the list by setting prevs to node and node to the
 * next node in the list after locking it.  Returns true only if there
 * was a next node that we were able to lock.   Returning false can mean
 * that we weren't able to lock the next node and the caller should
 * retry a full search.
 *
 * This may be called after _write_remove clears node so we try to
 * iterate from prev if there is no node.
 *
 * If lock_height is greater than zero then the caller needs at least
 * that lock_height to insert a node of that height.   If locked_height
 * doesn't cover it then we return false so the caller can retry
 * _write_begin with the needed height.
 *
 * Like insertion, we don't unlock prevs higher than the height of the
 * next node.   They're not strictly needed to modify the next node but
 * we want to keep them locked so the caller can continue to iterate
 * through nodes up to the locked height.
 */
bool scoutfs_cwskip_write_next(struct scoutfs_cwskip_writer *wr, int lock_height,
			       void **prev_cont, void **node_cont)
{
	struct scoutfs_cwskip_node *next;
	int i;

	if (WARN_ON_ONCE(lock_height < 0 || lock_height > SCOUTFS_CWSKIP_MAX_HEIGHT))
		return false;

	if (wr->node)
		next = rcu_dereference(wr->node->links[0]);
	else
		next = rcu_dereference(wr->prevs[0]->links[0]);

	if (!next ||
	    (lock_height > wr->locked_height) ||
	    (lock_height > 0 && next->height > wr->locked_height) ||
	    !__node_trylock(next, next->write_seq))
		return false;

	if (!wr->node) {
		/* set next as missing node */
		wr->node = next;
		wr->node_locked = true;

	} else {
		/* existing node becomes prevs for its height */
		__node_unlock(wr->prevs[0]);
		for (i = 0; i < wr->node->height; i++)
			wr->prevs[0] = wr->node;
		wr->node = next;
	}

	smp_wmb(); /* next locked and prev unlocked */

	set_containers(wr->root, wr->prevs[0], wr->node, prev_cont, node_cont);

	return true;
}

void scoutfs_cwskip_write_end(struct scoutfs_cwskip_writer *wr)
	__releases(RCU) /* :/ */
{
	writer_unlock(wr);
	rcu_read_unlock();
}
