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
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/random.h>

#include "super.h"
#include "format.h"
#include "key.h"
#include "btree.h"
#include "counters.h"
#include "triggers.h"
#include "options.h"
#include "msg.h"
#include "block.h"
#include "alloc.h"
#include "avl.h"
#include "hash.h"
#include "sort_priv.h"
#include "forest.h"

#include "scoutfs_trace.h"

/*
 * scoutfs uses a cow btree to index fs metadata.
 *
 * Today callers provide all the locking.  They serialize readers and
 * writers and writers and committing all the dirty blocks.
 *
 * Block reference have sufficient metadata to discover corrupt
 * references.  If a reader encounters a bad block it backs off which
 * gives the caller the opportunity to resample the root in case it was
 * reading through a stale btree that has been overwritten.  This lets
 * mounts read trees that are modified by other mounts without exclusive
 * locking.
 *
 * Btree items are stored as a dense array of structs at the front of
 * each block.  New items are allocated at the end of the array.
 * Deleted items are swapped with the last item to maintain the dense
 * array.  The items are indexed by a balanced binary tree with parent
 * pointers so the relocated item can have references to it updated.
 *
 * Values are allocated from the end of the block towards the front,
 * consuming the end of free space in the center of the block.  Deleted
 * values create fragmented free space in other existing values.  Rather
 * than tracking free space specifically, we compact values in bulk to
 * defragment free space if there is enough of to be worth the cost of
 * compaction.  When there's only a little bit of fragmented free space
 * we split the block as usual.
 *
 * Exact item searches are only performed on leaf blocks.  Leaf blocks
 * have a hash table at the end of the block which is used to find items
 * with a specific key.  It uses linear probing and maintains a low load
 * factor so any given search will most likely only need a single
 * cacheline.
 *
 * Parent block reference items are stored as items with a block
 * reference as a value.  There's an item with a key for every child
 * reference instead of having separator keys between child references.
 * The key in a child reference contains the largest key that may be
 * found in the child subtree.  The right spine of the tree has maximal
 * keys so that they don't have to be updated if we insert an item with
 * a key greater than everything in the tree.
 */

/* btree walking has a bunch of behavioural bit flags */
enum btree_walk_flags {
	 BTW_NEXT	= (1 <<  0), /* return >= key */
	 BTW_PREV	= (1 <<  1), /* return <= key */
	 BTW_DIRTY	= (1 <<  2), /* cow stable blocks */
	 BTW_ALLOC	= (1 <<  3), /* allocate a new block for 0 ref, requires dirty */
	 BTW_INSERT	= (1 <<  4), /* walking to insert, try splitting */
	 BTW_DELETE	= (1 <<  5), /* walking to delete, try joining */
	 BTW_PAR_RNG	= (1 <<  6), /* return range through final parent */
	 BTW_GET_PAR	= (1 <<  7), /* get reference to final parent */
	 BTW_SET_PAR	= (1 <<  8), /* override reference to final parent */
	 BTW_SUBTREE	= (1 <<  9), /* root is parent subtree, return -ERANGE if split/join */
};

/* total length of the value payload */
static inline unsigned int val_bytes(unsigned val_len)
{
	return round_up(val_len, SCOUTFS_BTREE_VALUE_ALIGN);
}

/* number of bytes in a block used by an item with the given value length */
static inline unsigned int item_len_bytes(unsigned val_len)
{
	return sizeof(struct scoutfs_btree_item) + val_bytes(val_len);
}

/* number of bytes used by an existing item */
static inline unsigned int item_bytes(struct scoutfs_btree_item *item)
{
	return item_len_bytes(le16_to_cpu(item->val_len));
}

/*
 * Refill blocks from their siblings when they're under 1/4 full.  This
 * puts some distance between the join threshold and the full threshold
 * for splitting.  Blocks that just split or joined need to undergo a
 * reasonable amount of item modification before they'll split or join
 * again.
 */
static unsigned int join_low_watermark(void)
{
	return (SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block)) / 4;
}

static bool total_above_join_low_water(struct scoutfs_btree_block *bt)
{
	return le16_to_cpu(bt->total_item_bytes) >= join_low_watermark();
}

/*
 * return the integer percentages of total space the block could have
 * consumed by items that is currently consumed.
 */
static unsigned int item_full_pct(struct scoutfs_btree_block *bt)
{
	return (int)le16_to_cpu(bt->total_item_bytes) * 100 /
		(SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block));
}

static inline __le16 ptr_off(struct scoutfs_btree_block *bt, void *ptr)
{
	return cpu_to_le16(ptr - (void *)bt);
}

static inline void *off_ptr(struct scoutfs_btree_block *bt, u16 off)
{
	return (void *)bt + off;
}

static inline struct scoutfs_btree_item *
off_item(struct scoutfs_btree_block *bt, __le16 off)
{
	return (void *)bt + le16_to_cpu(off);
}


/*
 * The item at the end of the item array.  This is *not* the item in the
 * block with the greatest key.
 */
static struct scoutfs_btree_item *end_item(struct scoutfs_btree_block *bt)
{
	BUG_ON(bt->nr_items == 0);

	return &bt->items[le16_to_cpu(bt->nr_items) - 1];
}

/* offset of the start of the free range in the middle of the block */
static inline unsigned int mid_free_off(struct scoutfs_btree_block *bt)
{
	return le16_to_cpu(ptr_off(bt, &bt->items[le16_to_cpu(bt->nr_items)]));
}

/* true if the mid free region has room for an item struct and its value */
static inline bool mid_free_item_room(struct scoutfs_btree_block *bt,
				      int val_len)
{
	return le16_to_cpu(bt->mid_free_len) >= item_len_bytes(val_len);
}

static inline struct scoutfs_key *item_key(struct scoutfs_btree_item *item)
{
	return &item->key;
}

static inline void *item_val(struct scoutfs_btree_block *bt,
			     struct scoutfs_btree_item *item)
{
	return off_ptr(bt, le16_to_cpu(item->val_off));
}

static inline unsigned item_val_len(struct scoutfs_btree_item *item)
{
	return le16_to_cpu(item->val_len);
}

static struct scoutfs_btree_item *node_item(struct scoutfs_avl_node *node)
{
	if (node == NULL)
		return NULL;
	return container_of(node, struct scoutfs_btree_item, node);
}

static struct scoutfs_btree_item *last_item(struct scoutfs_btree_block *bt)
{
	return node_item(scoutfs_avl_last(&bt->item_root));
}

static struct scoutfs_btree_item *prev_item(struct scoutfs_btree_block *bt,
					    struct scoutfs_btree_item *item)
{
	if (item == NULL)
		return NULL;
	return node_item(scoutfs_avl_prev(&bt->item_root, &item->node));
}

static struct scoutfs_btree_item *next_item(struct scoutfs_btree_block *bt,
					    struct scoutfs_btree_item *item)
{
	if (item == NULL)
		return NULL;
	return node_item(scoutfs_avl_next(&bt->item_root, &item->node));
}

static int cmp_key_item(void *arg, struct scoutfs_avl_node *node)
{
	struct scoutfs_key *key = arg;
	struct scoutfs_btree_item *item = node_item(node);

	return scoutfs_key_compare(key, item_key(item));
}

/*
 * We have a small fixed-size linearly probed hash table at the end of
 * leaf blocks which is used for direct item lookups (as opposed to
 * iterators).  The hash table only stores non-zero offsets to the
 * items.  If an item is moved then its offset is updated.  The hash
 * table is sized to allow a max load of 75%, but most items are larger
 * and most blocks aren't full.
 */
static int leaf_item_hash_ind(struct scoutfs_key *key)
{
	return scoutfs_hash32(key, sizeof(struct scoutfs_key)) %
	       SCOUTFS_BTREE_LEAF_ITEM_HASH_NR;
}

static __le16 *leaf_item_hash_buckets(struct scoutfs_btree_block *bt)
{
	return (void *)bt + SCOUTFS_BLOCK_LG_SIZE -
		SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES;
}

static inline int leaf_item_hash_next_bucket(int i)
{
	if (++i >= SCOUTFS_BTREE_LEAF_ITEM_HASH_NR)
		i = 0;
	return i;
}

#define foreach_leaf_item_hash_bucket(i, nr, key)			       \
	for (i = leaf_item_hash_ind(key), nr = SCOUTFS_BTREE_LEAF_ITEM_HASH_NR;\
	     nr-- > 0;							       \
	     i = leaf_item_hash_next_bucket(i))

static struct scoutfs_btree_item *
leaf_item_hash_search(struct super_block *sb, struct scoutfs_btree_block *bt,
		      struct scoutfs_key *key)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	struct scoutfs_btree_item *item;
	__le16 off;
	int nr;
	int i;

	scoutfs_inc_counter(sb, btree_leaf_item_hash_search);

	if (WARN_ON_ONCE(bt->level > 0))
		return NULL;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		off = buckets[i];
		if (off == 0)
			return NULL;

		item = off_item(bt, off);
		if (scoutfs_key_compare(key, item_key(item)) == 0)
			return item;
	}

	return NULL;
}

static void leaf_item_hash_insert(struct scoutfs_btree_block *bt,
				  struct scoutfs_key *key, __le16 off)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	int nr;
	int i;

	if (bt->level > 0)
		return;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		if (buckets[i] == 0) {
			buckets[i] = off;
			return;
		}
	}

	/* table should have been been enough for all items */
	BUG();
}

/*
 * Deletion clears the offset in a bucket.  That could create a
 * discontinuity that would stop a search from seeing colliding
 * insertions that were pushed into further buckets.  Each time we zero
 * a bucket we rehash all the populated buckets following it.  There
 * won't be many in our light load tables and this works reliably as the
 * contiguous population wraps past the end of table.  Comparing hashed
 * bucket positions to find candidates to relocate after the wrap is
 * tricky.  
 */
static void leaf_item_hash_delete(struct scoutfs_btree_block *bt,
				  struct scoutfs_key *key, __le16 del_off)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	__le16 off;
	int nr;
	int i;

	if (bt->level > 0)
		return;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		off = buckets[i];
		/* we must find the item we're trying to delete */
		BUG_ON(off == 0);

		if (off == del_off) {
			buckets[i] = 0;
			break;
		}
	}

	while ((i = leaf_item_hash_next_bucket(i)), buckets[i] != 0) {
		off = buckets[i];
		buckets[i] = 0;
		leaf_item_hash_insert(bt, item_key(off_item(bt, off)), off);
	}
}

static void leaf_item_hash_change(struct scoutfs_btree_block *bt,
				  struct scoutfs_key *key, __le16 to,
				  __le16 from)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	__le16 off;
	int nr;
	int i;

	if (bt->level > 0)
		return;

	foreach_leaf_item_hash_bucket(i, nr, key) {
		off = buckets[i];
		/* we must find the item we're trying to change */
		BUG_ON(off == 0);

		if (off == from) {
			buckets[i] = to;
			return;
		}
	}
}

static int cmp_sorted(void *priv, const void *A, const void *B)
{
	struct scoutfs_btree_block *bt = priv;
	const unsigned short *a = A;
	const unsigned short *b = B;
	struct scoutfs_btree_item *item_a = &bt->items[*a];
	struct scoutfs_btree_item *item_b = &bt->items[*b];

	return scoutfs_cmp(le16_to_cpu(item_a->val_off),
			   le16_to_cpu(item_b->val_off));
}

static void swap_sorted(void *priv, void *A, void *B, int size)
{
	unsigned short *a = A;
	unsigned short *b = B;

	swap(*a, *b);
}

/*
 * As values are freed they can leave fragmented free space amongst
 * other values.  We compact the values by sorting an array of item
 * indices by the offset of the item's values.  We can then walk values
 * from the back of the block and pack them into contiguous space,
 * bubbling any fragmented free space towards the middle.
 *
 * This is called when we can't insert because there isn't enough
 * available free space in the middle of the block but we know that
 * there's sufficient free fragmented space in the values.
 *
 * We only want to compact when there is enough free space to justify
 * the cost of the compaction.  We don't want to bother compacting if
 * the block is almost full and we just be split in a few more
 * operations.  The split heuristic requires a generous amount of
 * fragmented free space that will avoid a split.
 */
static int compact_values(struct super_block *sb,
			  struct scoutfs_btree_block *bt)
{
	const int nr = le16_to_cpu(bt->nr_items);
	struct scoutfs_btree_item *item;
	unsigned short *sorted = NULL;
	unsigned int to_off;
	unsigned int vb;
	void *from;
	void *to;
	int i;

	scoutfs_inc_counter(sb, btree_compact_values);

	BUILD_BUG_ON(sizeof(sorted[0]) != sizeof(bt->nr_items));

	sorted = kmalloc_array(le16_to_cpu(bt->nr_items), sizeof(sorted[0]),
			       GFP_NOFS);
	if (!sorted) {
		scoutfs_inc_counter(sb, btree_compact_values_enomem);
		return -ENOMEM;
	}

	/* sort the sorted array of item indices by their value offset */
	for (i = 0; i < nr; i++)
		sorted[i] = i;
	sort_priv(bt, sorted, nr, sizeof(sorted[0]), cmp_sorted, swap_sorted);

	to_off = SCOUTFS_BLOCK_LG_SIZE;
	if (bt->level == 0)
		to_off -= SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES;

	/* move values towards the back of the block */
	for (i = nr - 1; i >= 0; i--) {
		item = &bt->items[sorted[i]];
		if (item->val_len == 0)
			continue;

		vb = val_bytes(le16_to_cpu(item->val_len));
		to_off -= vb;
		from = off_ptr(bt, le16_to_cpu(item->val_off));
		to = off_ptr(bt, to_off);

		if (from != to) {
			if (to >= from + vb)
				memcpy(to, from, vb);
			else
				memmove(to, from, vb);

			item->val_off = cpu_to_le16(to_off);
		}
	}

	bt->mid_free_len = cpu_to_le16(to_off - mid_free_off(bt));

	kfree(sorted);
	return 0;
}

/*
 * Insert an item's value into the block.  The caller has made sure
 * there's free space.  We store the value at the end of free space in
 * the block and point its final offset at its owning item, and copy the
 * value into place.
 */
static __le16 insert_value(struct scoutfs_btree_block *bt, __le16 item_off,
			   void *val, unsigned val_len)
{
	unsigned int val_off;
	unsigned int vb;

	if (val_len == 0)
		return 0;

	BUG_ON(le16_to_cpu(bt->mid_free_len) < val_bytes(val_len));

	vb = val_bytes(val_len);
	val_off = mid_free_off(bt) + le16_to_cpu(bt->mid_free_len) - vb;
	le16_add_cpu(&bt->mid_free_len, -vb);

	memcpy(off_ptr(bt, val_off), val, val_len);

	return cpu_to_le16(val_off);
}

/*
 * Insert a new item into the block.  The caller has made sure that
 * there is sufficient free space in block for the new item.  We might
 * have to compact the values to the end of the block to reclaim
 * fragmented free space between values.
 *
 * This only consumes free space.  It's safe to use references to block
 * structures after this call.
 */
static void create_item(struct scoutfs_btree_block *bt, struct scoutfs_key *key, u64 seq, u8 flags,
			void *val, unsigned val_len, struct scoutfs_avl_node *parent, int cmp)
{
	struct scoutfs_btree_item *item;

	BUG_ON(le16_to_cpu(bt->mid_free_len) < item_len_bytes(val_len));

	le16_add_cpu(&bt->mid_free_len,
		     -(u16)sizeof(struct scoutfs_btree_item));
	le16_add_cpu(&bt->nr_items, 1);
	item = end_item(bt);

	item->key = *key;
	item->seq = cpu_to_le64(seq);
	item->flags = flags;

	scoutfs_avl_insert(&bt->item_root, parent, &item->node, cmp);
	leaf_item_hash_insert(bt, item_key(item), ptr_off(bt, item));

	item->val_off = insert_value(bt, ptr_off(bt, item), val, val_len);
	item->val_len = cpu_to_le16(val_len);
	memset(item->__pad, 0, sizeof(item->__pad));

	le16_add_cpu(&bt->total_item_bytes, item_bytes(item));
}

/*
 * Delete an item from a btree block.
 *
 * As we delete the item we can relocate an unrelated item to maintain
 * the dense array of items.  The caller can use another single item
 * after this call if they give us the opportunity to let them know if
 * we move it.
 */
static void delete_item(struct scoutfs_btree_block *bt,
			struct scoutfs_btree_item *item,
			struct scoutfs_btree_item **use_after)
{
	struct scoutfs_btree_item *end;
	unsigned int val_off;
	unsigned int val_len;

	/* save some values before we delete the item */
	val_off = le16_to_cpu(item->val_off);
	val_len = le16_to_cpu(item->val_len);
	end = end_item(bt);

	/* delete the item */
	scoutfs_avl_delete(&bt->item_root, &item->node);
	leaf_item_hash_delete(bt, item_key(item), ptr_off(bt, item));
	le16_add_cpu(&bt->nr_items, -1);
	le16_add_cpu(&bt->mid_free_len, sizeof(struct scoutfs_btree_item));
	le16_add_cpu(&bt->total_item_bytes, -item_bytes(item));

	/* move the final item into the deleted space */
	if (end != item) {
		item->key = end->key;
		item->seq = end->seq;
		item->flags = end->flags;
		item->val_off = end->val_off;
		item->val_len = end->val_len;
		leaf_item_hash_change(bt, &end->key, ptr_off(bt, item),
				      ptr_off(bt, end));
		scoutfs_avl_relocate(&bt->item_root, &item->node,&end->node);
		if (use_after && *use_after == end)
			*use_after = item;
	}
}

/*
 * Move items from a source block to a destination block.  The caller
 * has made sure there's sufficient free space in the destination block,
 * though item creation may need to compact values.  The caller tells us
 * if we're moving from the tail of the source block right to the head
 * of the destination block, or vice versa.  We're always adding the
 * first or last item to the avl, so the parent is always the previous
 * first or last node.
 */
static void move_items(struct scoutfs_btree_block *dst,
		       struct scoutfs_btree_block *src, bool move_right,
		       int to_move)
{
	struct scoutfs_avl_node *par;
	struct scoutfs_avl_node *node;
	struct scoutfs_btree_item *from;
	struct scoutfs_btree_item *next;
	int cmp;

	if (move_right) {
		node = scoutfs_avl_last(&src->item_root);
		par = scoutfs_avl_first(&dst->item_root);
		cmp = -1;
	} else {
		node = scoutfs_avl_first(&src->item_root);
		par = scoutfs_avl_last(&dst->item_root);
		cmp = 1;
	}
	from = node_item(node);

	while (to_move > 0 && from != NULL) {
		to_move -= item_bytes(from);

		if (move_right)
			next = prev_item(src, from);
		else
			next = next_item(src, from);

		create_item(dst, item_key(from), le64_to_cpu(from->seq), from->flags,
			    item_val(src, from), item_val_len(from), par, cmp);

		if (move_right) {
			if (par)
				par = scoutfs_avl_prev(&dst->item_root, par);
			else
				par = scoutfs_avl_first(&dst->item_root);
		} else {
			if (par)
				par = scoutfs_avl_next(&dst->item_root, par);
			else
				par = scoutfs_avl_last(&dst->item_root);
		}

		delete_item(src, from, &next);
		from = next;
	}
}

/*
 * This is used to lookup cached blocks, read blocks, cow blocks for
 * dirtying, and allocate new blocks.
 *
 * If we read a stale block we return stale so the caller can retry with
 * a newer root or return an error.
 */
static int get_ref_block(struct super_block *sb,
			 struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri, int flags,
			 struct scoutfs_block_ref *ref,
			 struct scoutfs_block **bl_ret)
{
	int ret;

	if (WARN_ON_ONCE((flags & BTW_ALLOC) && !(flags & BTW_DIRTY)))
		return -EINVAL;

	if (ref->blkno == 0 && !(flags & BTW_ALLOC)) {
		ret = -ENOENT;
		goto out;
	}

	if (flags & BTW_DIRTY)
		ret = scoutfs_block_dirty_ref(sb, alloc, wri, ref, SCOUTFS_BLOCK_MAGIC_BTREE,
					      bl_ret, 0, NULL);
	else
		ret = scoutfs_block_read_ref(sb, ref, SCOUTFS_BLOCK_MAGIC_BTREE, bl_ret);
out:
	if (ret < 0) {
		if (ret == -ESTALE)
			scoutfs_inc_counter(sb, btree_stale_read);
	}

	return ret;
}

/*
 * Create a new item in the parent which references the child.  The caller
 * specifies the key in the item that describes the items in the child.
 */
static void create_parent_item(struct scoutfs_btree_block *parent,
			       struct scoutfs_btree_block *child,
			       struct scoutfs_key *key)
{
	struct scoutfs_avl_node *par;
	int cmp;
	struct scoutfs_block_ref ref = {
		.blkno = child->hdr.blkno,
		.seq = child->hdr.seq,
	};

	scoutfs_avl_search(&parent->item_root, cmp_key_item, key, &cmp, &par,
			   NULL, NULL);
	create_item(parent, key, 0, 0, &ref, sizeof(ref), par, cmp);
}

/*
 * Update an existing parent item reference to a child who may be new or
 * may have had its last item changed.
 */
static void update_parent_item(struct scoutfs_btree_block *parent,
			       struct scoutfs_btree_item *par_item,
			       struct scoutfs_btree_block *child)
{
	struct scoutfs_block_ref *ref = item_val(parent, par_item);

	par_item->key = *item_key(last_item(child));
	ref->blkno = child->hdr.blkno;
	ref->seq = child->hdr.seq;
}

static __le16 init_mid_free_len(int level)
{
	int free;

	free = SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block);
	if (level == 0)
		free -= SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES;

	return cpu_to_le16(free);
}

static void init_btree_block(struct scoutfs_btree_block *bt, int level)
{

	bt->level = level;
	bt->mid_free_len = init_mid_free_len(level);
}

/*
 * See if we need to split this block while descending for insertion so
 * that we have enough space to insert.  Parent blocks need enough space
 * to insert a new parent item if a child block splits.  Leaf blocks
 * need enough space to insert the new item with its value.
 *
 * We split to the left so that the greatest key in the existing block
 * doesn't change so we don't have to update the key in its parent item.
 *
 * Returns -errno, 0 if nothing done, or 1 if we split.
 */
static int try_split(struct super_block *sb,
		     struct scoutfs_alloc *alloc,
		     struct scoutfs_block_writer *wri,
		     struct scoutfs_btree_root *root,
		     struct scoutfs_key *key, unsigned val_len,
		     struct scoutfs_btree_block *parent,
		     struct scoutfs_btree_block *right)
{
	struct scoutfs_block *left_bl = NULL;
	struct scoutfs_block *par_bl = NULL;
	struct scoutfs_btree_block *left;
	struct scoutfs_key max_key;
	struct scoutfs_block_ref zeros;
	int ret;
	int err;

	/* parents need to leave room for child references */
	if (right->level)
		val_len = sizeof(struct scoutfs_block_ref);

	/* don't need to split if there's enough space for the item */
	if (mid_free_item_room(right, val_len))
		return 0;

	if (item_full_pct(right) < 80)
		return compact_values(sb, right);

	scoutfs_inc_counter(sb, btree_split);

	/* alloc split neighbour first to avoid unwinding tree growth */
	memset(&zeros, 0, sizeof(zeros));
	ret = get_ref_block(sb, alloc, wri, BTW_ALLOC | BTW_DIRTY, &zeros, &left_bl);
	if (ret)
		return ret;
	left = left_bl->data;

	init_btree_block(left, right->level);

	if (!parent) {
		memset(&zeros, 0, sizeof(zeros));
		ret = get_ref_block(sb, alloc, wri, BTW_ALLOC | BTW_DIRTY, &zeros, &par_bl);
		if (ret) {
			err = scoutfs_free_meta(sb, alloc, wri,
						le64_to_cpu(left->hdr.blkno));
			BUG_ON(err); /* radix should have been dirty */
			scoutfs_block_put(sb, left_bl);
			return ret;
		}
		parent = par_bl->data;

		init_btree_block(parent, root->height);
		root->height++;
		root->ref.blkno = parent->hdr.blkno;
		root->ref.seq = parent->hdr.seq;

		scoutfs_key_set_ones(&max_key);
		create_parent_item(parent, right, &max_key);
	}

	move_items(left, right, false,
		   le16_to_cpu(right->total_item_bytes) / 2);

	create_parent_item(parent, left, item_key(last_item(left)));

	scoutfs_block_put(sb, left_bl);
	scoutfs_block_put(sb, par_bl);

	return 1;
}

/*
 * This is called during descent for deletion when we have a parent and
 * might need to join this block with a sibling block if this block has
 * too much free space.  Eventually we'll be able to fit all of the
 * sibling's items in our free space which lets us delete the sibling
 * block.
 */
static int try_join(struct super_block *sb,
		    struct scoutfs_alloc *alloc,
		    struct scoutfs_block_writer *wri,
		    struct scoutfs_btree_root *root,
		    struct scoutfs_btree_block *parent,
		    struct scoutfs_btree_item *par_item,
		    struct scoutfs_btree_block *bt)
{
	struct scoutfs_btree_item *sib_par_item;
	struct scoutfs_btree_block *sib;
	struct scoutfs_block *sib_bl;
	struct scoutfs_block_ref *ref;
	const unsigned int lwm = join_low_watermark();
	unsigned int sib_tot;
	bool move_right;
	int to_move;
	int ret;

	if (total_above_join_low_water(bt))
		return 0;

	scoutfs_inc_counter(sb, btree_join);

	/* move items right into our block if we have a left sibling */
	sib_par_item = prev_item(parent, par_item);
	if (sib_par_item) {
		move_right = true;
	} else {
		sib_par_item = next_item(parent, par_item);
		move_right = false;
	}

	ref = item_val(parent, sib_par_item);
	ret = get_ref_block(sb, alloc, wri, BTW_DIRTY, ref, &sib_bl);
	if (ret)
		return ret;
	sib = sib_bl->data;

	/* combine if resulting block would be up to 75% full, move big chunk otherwise */
	sib_tot = le16_to_cpu(sib->total_item_bytes);
	if (sib_tot <= lwm * 2)
		to_move = sib_tot;
	else
		to_move = lwm;

	/* compact to make room for over-estimate of worst case move overrun */
	if (le16_to_cpu(bt->mid_free_len) <
	    (to_move + item_len_bytes(SCOUTFS_BTREE_MAX_VAL_LEN))) {
		ret = compact_values(sb, bt);
		if (ret < 0) {
			scoutfs_block_put(sb, sib_bl);
			return ret;
		}
	}

	move_items(bt, sib, move_right, to_move);

	/* update our parent's item */
	if (!move_right)
		update_parent_item(parent, par_item, bt);

	/* update or delete sibling's parent item */
	if (le16_to_cpu(sib->nr_items) == 0) {
		delete_item(parent, sib_par_item, NULL);
		ret = scoutfs_free_meta(sb, alloc, wri,
					le64_to_cpu(sib->hdr.blkno));
		BUG_ON(ret);

	} else if (move_right) {
		update_parent_item(parent, sib_par_item, sib);
	}

	/* and finally shrink the tree if our parent is the root with 1 */
	if (le16_to_cpu(parent->nr_items) == 1) {
		root->height--;
		root->ref.blkno = bt->hdr.blkno;
		root->ref.seq = bt->hdr.seq;
		ret = scoutfs_free_meta(sb, alloc, wri,
					le64_to_cpu(parent->hdr.blkno));
		BUG_ON(ret);
	}

	scoutfs_block_put(sb, sib_bl);

	return 1;
}

static bool bad_item_off(int off, int nr)
{
	return (off < offsetof(struct scoutfs_btree_block, items[0])) ||
	       (off >= offsetof(struct scoutfs_btree_block, items[nr])) ||
	       ((off - offsetof(struct scoutfs_btree_block, items[0]))
		% sizeof(struct scoutfs_btree_item));
}

static bool bad_avl_node_off(__le16 node_off, int nr)
{
	int item_off;

	if (node_off == 0)
		return false;

	item_off = (int)le16_to_cpu(node_off) +
		   offsetof(struct scoutfs_btree_block, item_root) -
		   offsetof(struct scoutfs_btree_item, node);

	return bad_item_off(item_off, nr);
}

/*
 * XXX:
 *  - values don't overlap items
 *  - values don't overlap each other
 *  - last_free_offset is in fact last free region
 *  - call after leaf modification
 *  - padding is zero
 */
__attribute__((unused))
static void verify_btree_block(struct super_block *sb, char *str,
			       struct scoutfs_btree_block *bt, int level,
			       bool last_ref, struct scoutfs_key *start,
			       struct scoutfs_key *end)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *node;
	char *reason = NULL;
	int first_val = 0;
	int hashed = 0;
	int end_off;
	int tot = 0;
	int i = 0;
	int nr;

	if (bt->level != level) {
		reason = "unexpected level";
		goto out;
	}

	BUILD_BUG_ON(SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES % SCOUTFS_BTREE_VALUE_ALIGN != 0);

	end_off = SCOUTFS_BLOCK_LG_SIZE -
		  (level ? 0 : SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES);

	/* can have 0 item blocks during first insertion into a tree */
	nr = le16_to_cpu(bt->nr_items);
	if (nr < 0 || nr > SCOUTFS_BLOCK_LG_SIZE ||
	    offsetof(struct scoutfs_btree_block, items[nr]) > end_off) {
		reason = "nr_items out of range";
		goto out;
	}

	if (bad_avl_node_off(bt->item_root.node, nr)) {
		reason = "item_root node off";
		goto out;
	}

	tot = 0;
	first_val = end_off;

	for (i = 0; i < le16_to_cpu(bt->nr_items); i++) {
		item = &bt->items[i];

		if (bad_avl_node_off(item->node.parent, nr) ||
		    bad_avl_node_off(item->node.left, nr) ||
		    bad_avl_node_off(item->node.right, nr)) {
			reason = "item node off";
			goto out;
		}

		if (memchr_inv(item->__pad, '\0', sizeof(item->__pad))) {
			reason = "item struct __pad isn't zero";
			goto out;
		}

		if (scoutfs_key_compare(&item->key, start) < 0 ||
		    scoutfs_key_compare(&item->key, end) > 0) {
			reason = "item key out of parent range";
			goto out;
		}

		if (level == 0 &&
		    leaf_item_hash_search(sb, bt, &item->key) != item) {
			reason = "item not found in hash";
			goto out;
		}

		if (level > 0 && le16_to_cpu(item->val_len) !=
				 sizeof(struct scoutfs_block_ref)) {
			reason = "parent item val not sizeof ref";
			goto out;
		}

		if (le16_to_cpu(item->val_len) > SCOUTFS_BTREE_MAX_VAL_LEN) {
			reason = "bad item val len";
			goto out;
		}

		if (le16_to_cpu(item->val_off) % SCOUTFS_BTREE_VALUE_ALIGN) {
			reason = "item value not aligned";
			goto out;
		}

		if (((int)le16_to_cpu(item->val_off) +
		     le16_to_cpu(item->val_len)) > end_off) {
			reason = "item value outside valid";
			goto out;
		}

		tot += item_len_bytes(le16_to_cpu(item->val_len));

		if (item->val_len != 0) {
			first_val = min_t(int, first_val,
					  le16_to_cpu(item->val_off));
		}
	}

	if (last_ref && level > 0 &&
	    (node = scoutfs_avl_last(&bt->item_root)) != NULL) {
		item = node_item(node);
		if (scoutfs_key_compare(&item->key, end) != 0) {
			reason = "final ref item key not range end";
			goto out;
		}
	}

	for (i = 0; level == 0 && i < SCOUTFS_BTREE_LEAF_ITEM_HASH_NR; i++) {
		if (buckets[i] == 0)
			continue;

		if (bad_item_off(le16_to_cpu(buckets[i]), nr)) {
			reason = "bad item hash offset";
			goto out;
		}

		hashed++;
	}

	if (level == 0 && hashed != nr) {
		reason = "set hash buckets not nr";
		goto out;
	}

	if (le16_to_cpu(bt->total_item_bytes) != tot) {
		reason = "total_item_bytes not sum of items";
		goto out;
	}

	/* value deletion doesn't merge with adjacent fragmented freed vals */
	if (le16_to_cpu(bt->mid_free_len) >
	    (first_val - offsetof(struct scoutfs_btree_block, items[nr]))) {
		reason = "mid_free_len too large";
		goto out;
	}
out:
	if (!reason)
		return;

	printk("verifying btree %s: %s\n", str, reason);
	printk("args: level %u last_ref %u start "SK_FMT" end "SK_FMT"\n",
		level, last_ref, SK_ARG(start), SK_ARG(end));
	printk("calced: i %u tot %u hashed %u fv %u\n",
	       i, tot, hashed, first_val);

	printk("bt hdr: crc %x magic %x fsid %llx seq %llx blkno %llu\n", 
		le32_to_cpu(bt->hdr.crc), le32_to_cpu(bt->hdr.magic),
		le64_to_cpu(bt->hdr.fsid), le64_to_cpu(bt->hdr.seq),
		le64_to_cpu(bt->hdr.blkno));
	printk("item_root: node %u\n", le16_to_cpu(bt->item_root.node));
	printk("bt: nr %u tib %u mfl %u lvl %u\n",
		le16_to_cpu(bt->nr_items), le16_to_cpu(bt->total_item_bytes),
		le16_to_cpu(bt->mid_free_len), bt->level);

	for (i = 0; i < le16_to_cpu(bt->nr_items); i++) {
		item = &bt->items[i];
		printk(" %u: n %u,%u,%u,%u k "SK_FMT" vo %u vl %u\n",
		       i, le16_to_cpu(item->node.parent),
		       le16_to_cpu(item->node.left),
		       le16_to_cpu(item->node.right), item->node.height,
		       SK_ARG(&item->key), le16_to_cpu(item->val_off),
		       le16_to_cpu(item->val_len));
	}

	BUG();
}

/*
 * Walk from the root to the leaf, verifying the blocks traversed.
 */
__attribute__((unused))
static void verify_btree_walk(struct super_block *sb, char *str,
			      struct scoutfs_btree_root *root,
			      struct scoutfs_key *key)
{
	struct scoutfs_avl_node *next_node;
	struct scoutfs_avl_node *node;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_item *prev;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block_ref ref;
	struct scoutfs_key start;
	struct scoutfs_key end;
	bool last_ref;
	int level;
	int ret;

	if (root->height == 0 && root->ref.blkno != 0) {
		WARN_ONCE(1, "invalid btree root height %u blkno %llu seq %016llx\n",
			root->height, le64_to_cpu(root->ref.blkno),
			le64_to_cpu(root->ref.seq));
		return;
	}

	if (root->height == 0)
		return;

	scoutfs_key_set_zeros(&start);
	scoutfs_key_set_ones(&end);
	level = root->height;
	ref = root->ref;
	/* first parent last ref isn't all ones in subtrees */
	last_ref = false;

	while(level-- > 0) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
		ret = get_ref_block(sb, NULL, NULL, 0, &ref, &bl);
		if (ret) {
			printk("verifying  btree %s: read error %d\n",
			       str, ret);
			break;
		}
		bt = bl->data;

		verify_btree_block(sb, str, bt, level, last_ref, &start, &end);

		if (level == 0)
			break;

		node = scoutfs_avl_search(&bt->item_root, cmp_key_item, key,
					  NULL, NULL, &next_node, NULL);
		item = node_item(node ?: next_node);

		if (item == NULL) {
			printk("verifying btree %s: no ref item\n", str);
			printk("root: height %u blkno %llu seq %016llx\n",
			       root->height, le64_to_cpu(root->ref.blkno),
			       le64_to_cpu(root->ref.seq));
			printk("walk level %u start "SK_FMT" end "SK_FMT"\n",
				level, SK_ARG(&start), SK_ARG(&end));

			printk("block: level %u blkno %llu seq %016llx\n",
			       bt->level, le64_to_cpu(bt->hdr.blkno),
			       le64_to_cpu(bt->hdr.seq));
			printk("key: "SK_FMT"\n", SK_ARG(key));
			BUG();
		}

		if ((prev = prev_item(bt, item))) {
			start = *item_key(prev);
			scoutfs_key_inc(&start);
		}
		end = *item_key(item);

		memcpy(&ref, item_val(bt, item), sizeof(ref));
		last_ref = !next_item(bt, item);
	}

	scoutfs_block_put(sb, bl);
}

struct btree_walk_key_range {
	struct scoutfs_key start;
	struct scoutfs_key end;
	/* zero if no remaining blocks outside our walk in that direction */
	struct scoutfs_key iter_prev;
	struct scoutfs_key iter_next;
};

/*
 * Return the leaf block that should contain the given key.  The caller
 * is responsible for searching the leaf block and performing their
 * operation.
 *
 * Iteration starting from a key can end up in a leaf that doesn't
 * contain the next item in the direction iteration.  As we descend we
 * give the caller the nearest key in the direction of iteration that
 * will land in a different leaf.
 *
 * Migrating is a special kind of dirtying that returns the parent block
 * in the walk if the leaf block is already current and doesn't need to
 * be migrated.  It's presumed that the caller is iterating over keys
 * dirtying old leaf blocks and isn't actually doing anything with the
 * blocks themselves.
 */
static int btree_walk(struct super_block *sb,
		      struct scoutfs_alloc *alloc,
		      struct scoutfs_block_writer *wri,
		      struct scoutfs_btree_root *root,
		      int flags, struct scoutfs_key *key,
		      unsigned int val_len,
		      struct scoutfs_block **bl_ret,
		      struct btree_walk_key_range *kr,
		      struct scoutfs_btree_root *par_root)
{
	struct scoutfs_block *par_bl = NULL;
	struct scoutfs_block *bl = NULL;
	struct scoutfs_btree_block *parent = NULL;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *par_item;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_item *prev;
	struct scoutfs_avl_node *next_node;
	struct scoutfs_avl_node *node;
	struct scoutfs_block_ref *ref;
	unsigned int level;
	unsigned int nr;
	int ret;

	if (WARN_ON_ONCE((flags & BTW_DIRTY) && (!alloc || !wri)) ||
	    WARN_ON_ONCE((flags & BTW_PAR_RNG) && !kr) ||
	    WARN_ON_ONCE((flags & (BTW_GET_PAR|BTW_SET_PAR)) && !par_root))
		return -EINVAL;

	scoutfs_inc_counter(sb, btree_walk);

restart:
	scoutfs_block_put(sb, par_bl);
	par_bl = NULL;
	parent = NULL;
	par_item = NULL;
	scoutfs_block_put(sb, bl);
	bl = NULL;
	bt = NULL;
	if (kr) {
		scoutfs_key_set_zeros(&kr->start);
		scoutfs_key_set_ones(&kr->end);
		scoutfs_key_set_zeros(&kr->iter_prev);
		scoutfs_key_set_zeros(&kr->iter_next);
	}
	level = root->height;
	ret = 0;

	if (!root->height) {
		if (flags & BTW_GET_PAR) {
			memset(par_root, 0, sizeof(*par_root));
			*root = *par_root;
			ret = 0;
		} else if (flags & BTW_SET_PAR) {
			*root = *par_root;
			ret = 0;
		} else if (!(flags & BTW_INSERT)) {
			ret = -ENOENT;
		} else {
			ret = get_ref_block(sb, alloc, wri, BTW_ALLOC | BTW_DIRTY, &root->ref, &bl);
			if (ret == 0) {
				bt = bl->data;
				init_btree_block(bt, 0);
				root->height = 1;
			}
		}
		goto out;
	}

	ref = &root->ref;

	while(level-- > 0) {

		trace_scoutfs_btree_walk(sb, root, key, flags, level, ref);

		/* par range set by ref to last parent block */
		if (level < 2 && (flags & BTW_PAR_RNG)) {
			ret = 0;
			break;
		}

		if (level < 2 && (flags & BTW_GET_PAR)) {
			par_root->ref = *ref;
			par_root->height = level + 1;
			ret = 0;
			break;
		}

		if (level < 2 && (flags & BTW_SET_PAR)) {
			if (ref == &root->ref) {
				/* single parent block is replaced, can shrink/grow */
				*root = *par_root;
			} else {
				/* subtree replacing one of parents must match height */
				if (par_root->height != level + 1) {
					ret = -EINVAL;
					break;
				}
				*ref = par_root->ref;
			}
			ret = 0;
			break;
		}

		ret = get_ref_block(sb, alloc, wri, flags, ref, &bl);
		if (ret)
			break;
		bt = bl->data;

		/* XXX more aggressive block verification, before ref updates? */
		if (bt->level != level) {
			scoutfs_corruption(sb, SC_BTREE_BLOCK_LEVEL,
					   corrupt_btree_block_level,
					   "root_height %u root_blkno %llu root_seq %llu blkno %llu seq %llu level %u expected %u",
					   root->height,
					   le64_to_cpu(root->ref.blkno),
					   le64_to_cpu(root->ref.seq),
					   le64_to_cpu(bt->hdr.blkno),
					   le64_to_cpu(bt->hdr.seq), bt->level,
					   level);
			ret = -EIO;
			break;
		}

		/*
		 * join/split won't check subtree parent root, let
		 * caller know when it needs to be split/join.
		 */
		if ((flags & BTW_SUBTREE) && level == 1 &&
		    (!total_above_join_low_water(bt) ||
		     !mid_free_item_room(bt, sizeof(struct scoutfs_block_ref)))) {
			ret = -ERANGE;
			break;
		}

		/*
		 * Splitting and joining can add or remove parents or
		 * change the parent item we use to reach the child
		 * block with the search key.  In the rare case that we
		 * split or join we simply restart the walk instead of
		 * update our state to reflect the tree changes.
		 */
		ret = 0;
		if (flags & (BTW_INSERT | BTW_DELETE))
			ret = try_split(sb, alloc, wri, root, key, val_len,
					parent, bt);
		if (ret == 0 && (flags & BTW_DELETE) && parent)
			ret = try_join(sb, alloc, wri, root, parent, par_item,
				       bt);
		if (ret > 0) {
			scoutfs_inc_counter(sb, btree_walk_restart);
			goto restart;
		}
		else if (ret < 0)
			break;

		/* done at the leaf */
		if (level == 0)
			break;

		nr = le16_to_cpu(bt->nr_items);
		/* Find the next child block for the search key. */
		node = scoutfs_avl_search(&bt->item_root, cmp_key_item, key,
					  NULL, NULL, &next_node, NULL);
		item = node_item(node ?: next_node);
		if (item == NULL) {
			scoutfs_corruption(sb, SC_BTREE_NO_CHILD_REF,
					   corrupt_btree_block_level,
					   "root_height %u root_blkno %llu root_seq %llu blkno %llu seq %llu level %u nr %u",
					   root->height,
					   le64_to_cpu(root->ref.blkno),
					   le64_to_cpu(root->ref.seq),
					   le64_to_cpu(bt->hdr.blkno),
					   le64_to_cpu(bt->hdr.seq), bt->level,
					   nr);
			ret = -EIO;
			break;
		}

		if (kr) {
			/* update keys for walk bounds and next iteration */
			if ((prev = prev_item(bt, item))) {
				kr->start = *item_key(prev);
				scoutfs_key_inc(&kr->start);
				kr->iter_prev = *item_key(prev);
			}
			kr->end = *item_key(item);
			if (next_item(bt, item)) {
				kr->iter_next = *item_key(item);
				scoutfs_key_inc(&kr->iter_next);
			}
		}

		scoutfs_block_put(sb, par_bl);
		par_bl = bl;
		parent = bt;
		bl = NULL;
		bt = NULL;

		par_item = item;
		ref = item_val(parent, par_item);
	}

out:
	scoutfs_block_put(sb, par_bl);
	if (ret) {
		scoutfs_block_put(sb, bl);
		bl = NULL;
	}

	if (bl_ret)
		*bl_ret = bl;
	else
		scoutfs_block_put(sb, bl);

	return ret;
}

static void init_item_ref(struct scoutfs_btree_item_ref *iref,
			  struct super_block *sb,
			  struct scoutfs_block *bl,
			  struct scoutfs_btree_item *item)
{
	struct scoutfs_btree_block *bt = bl->data;

	iref->sb = sb;
	iref->bl = bl;
	iref->key = item_key(item);
	iref->val = item_val(bt, item);
	iref->val_len = le16_to_cpu(item->val_len);
}

void scoutfs_btree_put_iref(struct scoutfs_btree_item_ref *iref)
{
	if (!IS_ERR_OR_NULL(iref) && !IS_ERR_OR_NULL(iref->bl)) {
		scoutfs_block_put(iref->sb, iref->bl);
		memset(iref, 0, sizeof(struct scoutfs_btree_item_ref));
	}
}

/*
 * Find the item with the given key and point to it from the caller's
 * item ref.  They're given a reference to the block that they'll drop
 * when they're done.
 */
int scoutfs_btree_lookup(struct super_block *sb,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	scoutfs_inc_counter(sb, btree_lookup);

	if (WARN_ON_ONCE(iref->key))
		return -EINVAL;

	ret = btree_walk(sb, NULL, NULL, root, 0, key, 0, &bl, NULL, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(sb, bt, key);
		if (item) {
			init_item_ref(iref, sb, bl, item);
			ret = 0;
		} else {
			scoutfs_block_put(sb, bl);
			ret = -ENOENT;
		}
	}

	return ret;
}

static bool invalid_item(unsigned val_len)
{
	return WARN_ON_ONCE(val_len > SCOUTFS_BTREE_MAX_VAL_LEN);
}

/*
 * Insert a new item in the tree.
 *
 * 0 is returned on success.  -EEXIST is returned if the key is already
 * present in the tree.
 *
 * If no value pointer is given then the item is created with a zero
 * length value.
 */
int scoutfs_btree_insert(struct super_block *sb,
			 struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 void *val, unsigned val_len)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_avl_node *node;
	struct scoutfs_avl_node *par;
	struct scoutfs_block *bl;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, btree_insert);

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(sb, bt, key);
		if (item) {
			ret = -EEXIST;
		} else {
			node = scoutfs_avl_search(&bt->item_root, cmp_key_item,
						  key, &cmp, &par, NULL, NULL);
			if (node) {
				ret = -EEXIST;
			} else {
				create_item(bt, key, 0, 0, val, val_len, par, cmp);
				ret = 0;
			}
		}

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

static void update_item_value(struct scoutfs_btree_block *bt,
			      struct scoutfs_btree_item *item,
			      void *val, unsigned val_len)
{
	le16_add_cpu(&bt->total_item_bytes, val_bytes(val_len) -
		     val_bytes(le16_to_cpu(item->val_len)));
	item->val_off = insert_value(bt, ptr_off(bt, item), val, val_len);
	item->val_len = cpu_to_le16(val_len);
}

/*
 * Update a btree item.  -ENOENT is returned if the item didn't exist.
 *
 * We don't know the existing item's value length as we first descend.
 * We assume that the new value is longer and try to split so that we
 * can insert if that's true.  If the new value is shorter than the
 * existing then the leaf might fall under the minimum watermark, but at
 * least we can do that while we simply can't insert a new longer value
 * which doesn't fit.
 */
int scoutfs_btree_update(struct super_block *sb,
			 struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key,
			 void *val, unsigned val_len)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	scoutfs_inc_counter(sb, btree_update);

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(sb, bt, key);
		if (item) {
			update_item_value(bt, item, val, val_len);
			ret = 0;
		} else {
			ret = -ENOENT;
		}

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Create an item, overwriting any item that might exist.  It's _update
 * which will insert instead of returning -ENOENT.
 */
int scoutfs_btree_force(struct super_block *sb,
			struct scoutfs_alloc *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *key,
			void *val, unsigned val_len)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *par;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int cmp;
	int ret;

	scoutfs_inc_counter(sb, btree_force);

	if (invalid_item(val_len))
		return -EINVAL;

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT, key,
			 val_len, &bl, NULL, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(sb, bt, key);
		if (item) {
			update_item_value(bt, item, val, val_len);
		} else {
			scoutfs_avl_search(&bt->item_root, cmp_key_item, key,
					   &cmp, &par, NULL, NULL);
			create_item(bt, key, 0, 0, val, val_len, par, cmp);
		}
		ret = 0;

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Delete an item from the tree.  -ENOENT is returned if the key isn't
 * found.
 */
int scoutfs_btree_delete(struct super_block *sb,
			 struct scoutfs_alloc *alloc,
			 struct scoutfs_block_writer *wri,
			 struct scoutfs_btree_root *root,
			 struct scoutfs_key *key)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	scoutfs_inc_counter(sb, btree_delete);

	ret = btree_walk(sb, alloc, wri, root, BTW_DELETE | BTW_DIRTY, key,
			 0, &bl, NULL, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(sb, bt, key);
		if (item) {
			if (le16_to_cpu(bt->nr_items) == 1) {
				/* remove final empty block */
				ret = scoutfs_free_meta(sb, alloc, wri,
							bl->blkno);
				if (ret == 0) {
					root->height = 0;
					root->ref.blkno = 0;
					root->ref.seq = 0;
				}
			} else {
				delete_item(bt, item, NULL);
				ret = 0;
			}
		} else {
			ret = -ENOENT;
		}

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Iterate from a key value to the next item in the direction of
 * iteration.  Callers set flags to tell which way to iterate.  The
 * first key is always inclusive.
 *
 * Walking can land in a leaf that doesn't contain any items in the
 * direction of the iteration.  Walking gives us the next key to walk
 * towards in this case.  We keep trying until we run out of blocks or
 * find the next item.  This method is aggressively permissive because
 * it lets the tree shape change between each walk and allows empty
 * blocks.
 */
static int btree_iter(struct super_block *sb,struct scoutfs_btree_root *root,
		      int flags, struct scoutfs_key *key,
		      struct scoutfs_btree_item_ref *iref)
{
	struct scoutfs_avl_node *node;
	struct scoutfs_avl_node *next;
	struct scoutfs_avl_node *prev;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct btree_walk_key_range kr;
	struct scoutfs_key walk_key;
	struct scoutfs_key *iter_key;
	struct scoutfs_block *bl;
	int ret;

	if (WARN_ON_ONCE(flags & BTW_DIRTY) ||
	    WARN_ON_ONCE(iref->key))
		return -EINVAL;

	walk_key = *key;

	for (;;) {
		ret = btree_walk(sb, NULL, NULL, root, flags, &walk_key,
				 0, &bl, &kr, NULL);
		if (ret < 0)
			break;
		bt = bl->data;

		node = scoutfs_avl_search(&bt->item_root, cmp_key_item, key,
					  NULL, NULL, &next, &prev);

		if (node == NULL && (flags & BTW_NEXT))
			node = next;
		else if (node == NULL && (flags & BTW_PREV))
			node = prev;
		item = node_item(node);
		if (item) {
			init_item_ref(iref, sb, bl, item);
			ret = 0;
			break;
		}

		scoutfs_block_put(sb, bl);

		/* nothing in this leaf, walk gave us a key */
		iter_key = (flags & BTW_NEXT) ? &kr.iter_next : &kr.iter_prev;
		if (!scoutfs_key_is_zeros(iter_key)) {
			walk_key = *iter_key;
			continue;
		}

		ret = -ENOENT;
		break;
	}

	return ret;
}

int scoutfs_btree_next(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *key,
		       struct scoutfs_btree_item_ref *iref)
{
	scoutfs_inc_counter(sb, btree_next);

	return btree_iter(sb, root, BTW_NEXT, key, iref);
}

int scoutfs_btree_prev(struct super_block *sb, struct scoutfs_btree_root *root,
		       struct scoutfs_key *key,
		       struct scoutfs_btree_item_ref *iref)
{
	scoutfs_inc_counter(sb, btree_prev);

	return btree_iter(sb, root, BTW_PREV, key, iref);
}

/*
 * Ensure that the blocks that lead to the item with the given key are
 * dirty.  caller can hold a transaction to pin the dirty blocks and
 * guarantee that later updates of the item will succeed.
 *
 * <0 is returned on error, including -ENOENT if the key isn't present.
 */
int scoutfs_btree_dirty(struct super_block *sb,
			struct scoutfs_alloc *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_btree_root *root,
			struct scoutfs_key *key)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl;
	int ret;

	scoutfs_inc_counter(sb, btree_dirty);

	ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY, key, 0, &bl,
			 NULL, NULL);
	if (ret == 0) {
		bt = bl->data;

		item = leaf_item_hash_search(sb, bt, key);
		if (item)
			ret = 0;
		else
			ret = -ENOENT;

		scoutfs_block_put(sb, bl);
	}

	return ret;
}

/*
 * Call the users callback on all the items in the leaf that we find.
 * We also set the caller's keys for the first and last possible keys
 * that could exist in the leaf block.
 */
int scoutfs_btree_read_items(struct super_block *sb,
			     struct scoutfs_btree_root *root,
			     struct scoutfs_key *key,
			     struct scoutfs_key *start,
			     struct scoutfs_key *end,
			     scoutfs_btree_item_cb cb, void *arg)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_avl_node *next_node;
	struct scoutfs_avl_node *node;
	struct btree_walk_key_range kr;
	struct scoutfs_block *bl;
	int ret;

	ret = btree_walk(sb, NULL, NULL, root, 0, key, 0, &bl, &kr, NULL);
	if (ret < 0)
		goto out;
	bt = bl->data;

	if (scoutfs_key_compare(&kr.start, start) > 0)
		*start = kr.start;
	if (scoutfs_key_compare(&kr.end, end) < 0)
		*end = kr.end;

	node = scoutfs_avl_search(&bt->item_root, cmp_key_item, start, NULL,
				  NULL, &next_node, NULL) ?: next_node;
	while (node) {
		item = node_item(node);
		if (scoutfs_key_compare(&item->key, end) > 0)
			break;

		ret = cb(sb, item_key(item), le64_to_cpu(item->seq), item->flags,
			 item_val(bt, item), item_val_len(item), arg);
		if (ret < 0)
			break;

		node = scoutfs_avl_next(&bt->item_root, node);
	}

	scoutfs_block_put(sb, bl);
out:
	return ret;
}

/*
 * The caller has a sorted list of items to insert.  We find the leaf
 * block that contains each item and either overwrite or insert the
 * caller's item.  This has no mechanism for deleting items.
 *
 * This can make partial progress before returning an error, leaving
 * dirty btree blocks with only some of the caller's items.  It's up to
 * the caller to resolve this.
 *
 * This, along with merging, are the only places that seq and flags are
 * set in btree items.  They're only used for fs items written through
 * the item cache and forest of log btrees.
 */
int scoutfs_btree_insert_list(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_btree_root *root,
			      struct scoutfs_btree_item_list *lst)
{
	struct scoutfs_btree_item *item;
	struct btree_walk_key_range kr;
	struct scoutfs_btree_block *bt;
	struct scoutfs_avl_node *par;
	struct scoutfs_block *bl;
	int cmp;
	int ret = 0;

	while (lst) {
		ret = btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_INSERT,
				 &lst->key, lst->val_len, &bl, &kr, NULL);
		if (ret < 0)
			goto out;
		bt = bl->data;

		do {
			item = leaf_item_hash_search(sb, bt, &lst->key);
			if (item) {
				/* try to merge delta values, _NULL not deleted; merge will */
				ret = scoutfs_forest_combine_deltas(&lst->key,
								    item_val(bt, item),
								    item_val_len(item),
								    lst->val, lst->val_len);
				if (ret < 0) {
					scoutfs_block_put(sb, bl);
					goto out;
				}

				item->seq = cpu_to_le64(lst->seq);
				item->flags = lst->flags;

				if (ret == 0)
					update_item_value(bt, item, lst->val, lst->val_len);
				else
					ret = 0;
			} else {
				scoutfs_avl_search(&bt->item_root,
						   cmp_key_item, &lst->key,
						   &cmp, &par, NULL, NULL);
				create_item(bt, &lst->key, lst->seq, lst->flags, lst->val,
					    lst->val_len, par, cmp);
			}

			lst = lst->next;
		} while (lst && scoutfs_key_compare(&lst->key, &kr.end) <= 0 &&
			 mid_free_item_room(bt, lst->val_len));

		scoutfs_block_put(sb, bl);
	}

out:
	return ret;
}

/*
 * Descend towards the leaf that would contain the key.  As we arrive at
 * the last parent block, set start and end to the range of keys that
 * could be found through traversal of that last parent.
 *
 * If the tree is too short for parent blocks then the max key range
 * is returned.
 */
int scoutfs_btree_parent_range(struct super_block *sb,
			       struct scoutfs_btree_root *root,
			       struct scoutfs_key *key,
			       struct scoutfs_key *start,
			       struct scoutfs_key *end)
{
	struct btree_walk_key_range kr;
	int ret;

	ret = btree_walk(sb, NULL, NULL, root, BTW_PAR_RNG, key, 0, NULL,
			 &kr, NULL);
	if (ret == -ENOENT)
		ret = 0;

	*start = kr.start;
	*end = kr.end;
	return ret;
}

/*
 * Initialize the caller's root as a subtree whose ref points to the
 * last parent found as we traverse towards the leaf containing the key.
 * If the tree is too small to have multiple blocks at the final parent
 * level then the caller's root will be initialized to equal full input
 * root.  If the tree is empty then the par root will also be empty.
 */
int scoutfs_btree_get_parent(struct super_block *sb,
			     struct scoutfs_btree_root *root,
			     struct scoutfs_key *key,
			     struct scoutfs_btree_root *par_root)
{
	return btree_walk(sb, NULL, NULL, root, BTW_GET_PAR, key, 0, NULL,
			  NULL, par_root);
}

/*
 * Dirty a path towards the leaf block containing the key.  As we reach
 * the reference to the final parent block override it with the ref in
 * the caller's block.  If the tree only has a single block at the final
 * parent level, or a single leaf block, then the entire tree is
 * replaced with the caller's root.
 *
 * This manages allocs and frees while dirtying blocks in the path to
 * the ref, but it doesn't account for allocating the blocks that are
 * referenced by the ref nor freeing blocks referenced by the old ref
 * that's overwritten.  Keeping allocators in sync with the result of
 * the ref override is the responsibility of the caller.
 */
int scoutfs_btree_set_parent(struct super_block *sb,
			     struct scoutfs_alloc *alloc,
			     struct scoutfs_block_writer *wri,
			     struct scoutfs_btree_root *root,
			     struct scoutfs_key *key,
			     struct scoutfs_btree_root *par_root)
{

	trace_scoutfs_btree_set_parent(sb, root, key, par_root);

	return btree_walk(sb, alloc, wri, root, BTW_DIRTY | BTW_SET_PAR,
			  key, 0, NULL, NULL, par_root);
}

/*
 * Descend to the leaf, making sure that all the blocks conform to the
 * balance constraints.  Blocks below the low threshold will be joined.
 * This is called to split blocks that were too large for insertions,
 * but those insertions were in a distant context and we don't bother
 * communicating the val_len back here.  We just try to insert a max
 * value.
 *
 * This always dirties all the way to the leaf.  It could be made more
 * efficient with more btree walk flags to walk and check for blocks
 * that need balancing, and then walks that don't dirty unless they need
 * to join/split.
 */
int scoutfs_btree_rebalance(struct super_block *sb,
			    struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri,
			    struct scoutfs_btree_root *root,
			    struct scoutfs_key *key)
{
	return btree_walk(sb, alloc, wri, root,
			  BTW_DIRTY | BTW_INSERT | BTW_DELETE,
			  key, SCOUTFS_BTREE_MAX_VAL_LEN, NULL, NULL, NULL);
}

struct merged_range {
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct rb_root root;
	int size;
};

struct merged_item {
	struct rb_node node;
	struct scoutfs_key key;
	u64 seq;
	u8 flags;
	unsigned int val_len;
	u8 val[];
};

static inline struct merged_item *mitem_container(struct rb_node *node)
{
	return node ? container_of(node, struct merged_item, node) : NULL;
}

static inline struct merged_item *first_mitem(struct rb_root *root)
{
	return mitem_container(rb_first(root));
}

static inline struct merged_item *last_mitem(struct rb_root *root)
{
	return mitem_container(rb_last(root));
}

static inline struct merged_item *next_mitem(struct merged_item *mitem)
{
	return mitem_container(mitem ? rb_next(&mitem->node) : NULL);
}

static inline struct merged_item *prev_mitem(struct merged_item *mitem)
{
	return mitem_container(mitem ? rb_prev(&mitem->node) : NULL);
}

static struct merged_item *find_mitem(struct rb_root *root, struct scoutfs_key *key,
				      struct rb_node **parent_ret, struct rb_node ***link_ret)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct merged_item *mitem;
	int cmp;

	while (*node) {
		parent = *node;
		mitem = container_of(*node, struct merged_item, node);

		cmp = scoutfs_key_compare(key, &mitem->key);

		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			*parent_ret = NULL;
			*link_ret = NULL;
			return mitem;
		}
	}

	*parent_ret = parent;
	*link_ret = node;
	return NULL;
}

static void insert_mitem(struct merged_range *rng, struct merged_item *mitem,
			 struct rb_node *parent, struct rb_node **link)
{
	rb_link_node(&mitem->node, parent, link);
	rb_insert_color(&mitem->node, &rng->root);
	rng->size += item_len_bytes(mitem->val_len);
}

static void replace_mitem(struct merged_range *rng, struct merged_item *victim,
				struct merged_item *new)
{
	rb_replace_node(&victim->node, &new->node, &rng->root);
	RB_CLEAR_NODE(&victim->node);
	rng->size -= item_len_bytes(victim->val_len);
	rng->size += item_len_bytes(new->val_len);
}

static void free_mitem(struct merged_range *rng, struct merged_item *mitem)
{
	if (IS_ERR_OR_NULL(mitem))
		return;

	if (!RB_EMPTY_NODE(&mitem->node)) {
		rng->size -= item_len_bytes(mitem->val_len);
		rb_erase(&mitem->node, &rng->root);
	}

	kfree(mitem);
}

static void trim_range_size(struct merged_range *rng, int merge_window)
{
	struct merged_item *mitem;
	struct merged_item *tmp;

	mitem = last_mitem(&rng->root);
	while (mitem && rng->size > merge_window) {

		rng->end = mitem->key;
		scoutfs_key_dec(&rng->end);

		tmp = mitem;
		mitem = prev_mitem(mitem);
		free_mitem(rng, tmp);
	}
}

static void trim_range_end(struct merged_range *rng)
{
	struct merged_item *mitem;
	struct merged_item *tmp;

	mitem = last_mitem(&rng->root);
	while (mitem && scoutfs_key_compare(&mitem->key, &rng->end) > 0) {
		tmp = mitem;
		mitem = prev_mitem(mitem);
		free_mitem(rng, tmp);
	}
}

/*
 * Record and combine logged items from log roots for merging with the
 * writable destination root.  The caller is responsible for trimming
 * the range if it gets too large or if the key range shrinks.
 */
static int merge_read_item(struct super_block *sb, struct scoutfs_key *key, u64 seq, u8 flags,
			   void *val, int val_len, void *arg)
{
	struct merged_range *rng = arg;
	struct merged_item *mitem;
	struct merged_item *found;
	struct rb_node *parent;
	struct rb_node **link;
	int ret;

	found = find_mitem(&rng->root, key, &parent, &link);
	if (found) {
		ret = scoutfs_forest_combine_deltas(key, found->val, found->val_len, val, val_len);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			if (ret == SCOUTFS_DELTA_COMBINED) {
				scoutfs_inc_counter(sb, btree_merge_delta_combined);
			} else if (ret == SCOUTFS_DELTA_COMBINED_NULL) {
				scoutfs_inc_counter(sb, btree_merge_delta_null);
				free_mitem(rng, found);
			}
			ret = 0;
			goto out;
		}

		if (found->seq >= seq) {
			ret = 0;
			goto out;
		}
	}

	mitem = kmalloc(offsetof(struct merged_item, val[val_len]), GFP_NOFS);
	if (!mitem) {
		ret = -ENOMEM;
		goto out;
	}

	mitem->key = *key;
	mitem->seq = seq;
	mitem->flags = flags;
	mitem->val_len = val_len;
	if (val_len)
		memcpy(&mitem->val[0], val, val_len);

	if (found) {
		replace_mitem(rng, found, mitem);
		free_mitem(rng, found);
	} else {
		insert_mitem(rng, mitem, parent, link);
	}

	ret = 0;
out:
	return ret;
}

/*
 * Read a range of merged items.  The caller has set the key bounds of
 * the range.  We read a merge window's worth of items from blocks in
 * each input btree.
 *
 * The caller can only use the smallest range that overlaps with all the
 * blocks that we read.  We start reading from the range's start key so
 * it will always be present and we don't need to adjust it.  The final
 * block we read from each input might not cover the range's end so it
 * needs to be adjusted.
 *
 * The end range can also shrink if we have to drop items because the
 * items exceeded the merge window size.
 */
static int read_merged_range(struct super_block *sb, struct merged_range *rng,
			     struct list_head *inputs, int merge_window)
{
	struct scoutfs_btree_root_head *rhead;
	struct scoutfs_key start;
	struct scoutfs_key end;
	struct scoutfs_key key;
	int ret = 0;
	int i;

	list_for_each_entry(rhead, inputs, head) {
		key = rng->start;

		for (i = 0; i < merge_window; i += SCOUTFS_BLOCK_LG_SIZE) {
			start = key;
			end = rng->end;
			ret = scoutfs_btree_read_items(sb, &rhead->root, &key, &start, &end,
						       merge_read_item, rng);
			if (ret < 0)
				goto out;

			if (scoutfs_key_compare(&end, &rng->end) >= 0)
				break;

			key = end;
			scoutfs_key_inc(&key);
		}

		if (scoutfs_key_compare(&end, &rng->end) < 0) {
			rng->end = end;
			trim_range_end(rng);
		}

		if (rng->size > merge_window)
			trim_range_size(rng, merge_window);
	}

	trace_scoutfs_btree_merge_read_range(sb, &rng->start, &rng->end, rng->size);
	ret = 0;
out:
	return ret;
}

/*
 * Merge items from a number of read-only input roots into a writable
 * destination root.  The order of the input roots doesn't matter, the
 * items are merged in sorted key order.
 *
 * subtree indicates that the destination root is in fact one of many
 * parent blocks and shouldn't be split or allowed to fall below the
 * join low water mark.
 *
 * -ERANGE is returned if the merge doesn't fully exhaust the range, due
 * to allocators running low or needing to join/split the parent.
 * *next_ret is set to the next key which hasn't been merged so that the
 * caller can retry with a new allocator and subtree.
 *
 * The number of input roots can be immense.  The merge_window specifies
 * the size of the set of merged items that we'll maintain as we iterate
 * over all the input roots.  Once we've merged items into the window
 * from all the input roots the merged input items are then merged to
 * the writable destination root.  It may take multiple passes of
 * windows of merged items to cover the input key range.
 */
int scoutfs_btree_merge(struct super_block *sb,
			struct scoutfs_alloc *alloc,
			struct scoutfs_block_writer *wri,
			struct scoutfs_key *start,
			struct scoutfs_key *end,
			struct scoutfs_key *next_ret,
			struct scoutfs_btree_root *root,
			struct list_head *inputs,
			bool subtree, int dirty_limit, int alloc_low, int merge_window)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block *bl = NULL;
	struct btree_walk_key_range kr;
	struct scoutfs_avl_node *par;
	struct merged_item *mitem;
	struct merged_item *tmp;
	struct merged_range rng;
	int walk_val_len;
	int walk_flags;
	bool is_del;
	int delta;
	int cmp;
	int ret;

	trace_scoutfs_btree_merge(sb, root, start, end);
	scoutfs_inc_counter(sb, btree_merge);

	walk_flags = BTW_DIRTY;
	if (subtree)
		walk_flags |= BTW_SUBTREE;
	walk_val_len = 0;

	rng.start = *start;
	rng.end = *end;
	rng.root = RB_ROOT;
	rng.size = 0;

	ret = read_merged_range(sb, &rng, inputs, merge_window);
	if (ret < 0)
		goto out;

	for (;;) {
		/* read next window as it empties (and it is possible to read an empty range) */
		mitem = first_mitem(&rng.root);
		if (!mitem) {
			/* done if the read range hit the end */
			if (scoutfs_key_compare(&rng.end, end) >= 0)
				break;

			/* read next batch of merged items */
			rng.start = rng.end;
			scoutfs_key_inc(&rng.start);
			rng.end = *end;
			ret = read_merged_range(sb, &rng, inputs, merge_window);
			if (ret < 0)
				break;
			continue;
		}

		if (scoutfs_block_writer_dirty_bytes(sb, wri) >= dirty_limit) {
			scoutfs_inc_counter(sb, btree_merge_dirty_limit);
			ret = -ERANGE;
			*next_ret = mitem->key;
			goto out;
		}

		if (scoutfs_alloc_meta_low(sb, alloc, alloc_low)) {
			scoutfs_inc_counter(sb, btree_merge_alloc_low);
			ret = -ERANGE;
			*next_ret = mitem->key;
			goto out;
		}

		scoutfs_block_put(sb, bl);
		bl = NULL;
		ret = btree_walk(sb, alloc, wri, root, walk_flags,
			         &mitem->key, walk_val_len, &bl, &kr, NULL);
		if (ret < 0) {
			if (ret == -ERANGE)
				*next_ret = mitem->key;
			goto out;
		}
		bt = bl->data;
		scoutfs_inc_counter(sb, btree_merge_walk);

		/* catch non-root blocks that fell under low, maybe from null deltas */
		if (root->ref.blkno != bt->hdr.blkno && !total_above_join_low_water(bt)) {
			walk_flags |= BTW_DELETE;
			continue;
		}

		while (mitem) {
			/* walk to new leaf if we exceed parent ref key */
			if (scoutfs_key_compare(&mitem->key, &kr.end) > 0)
				break;

			/* see if there's an existing item */
			item = leaf_item_hash_search(sb, bt, &mitem->key);
			is_del = !!(mitem->flags & SCOUTFS_ITEM_FLAG_DELETION);

			/* see if we're merging delta items */
			if (item && !is_del)
				delta = scoutfs_forest_combine_deltas(&mitem->key,
								      item_val(bt, item),
								      item_val_len(item),
								      mitem->val, mitem->val_len);
			else
				delta = 0;
			if (delta < 0) {
				ret = delta;
				goto out;
			} else if (delta == SCOUTFS_DELTA_COMBINED) {
				scoutfs_inc_counter(sb, btree_merge_delta_combined);
			} else if (delta == SCOUTFS_DELTA_COMBINED_NULL) {
				scoutfs_inc_counter(sb, btree_merge_delta_null);
			}

			trace_scoutfs_btree_merge_items(sb, &mitem->key, mitem->val_len,
					item ? root : NULL,
					item ? item_key(item) : NULL,
					item ? item_val_len(item) : 0, is_del);

			/* rewalk and split if ins/update needs room */
			if (!is_del && !delta && !mid_free_item_room(bt, mitem->val_len)) {
				walk_flags |= BTW_INSERT;
				walk_val_len = mitem->val_len;
				break;
			}

			/* insert missing non-deletion merge items */
			if (!item && !is_del) {
				scoutfs_avl_search(&bt->item_root, cmp_key_item, &mitem->key,
						   &cmp, &par, NULL, NULL);
				create_item(bt, &mitem->key, mitem->seq, mitem->flags,
					    mitem->val, mitem->val_len, par, cmp);
				scoutfs_inc_counter(sb, btree_merge_insert);
			}

			/* update existing items */
			if (item && !is_del && !delta) {
				item->seq = cpu_to_le64(mitem->seq);
				item->flags = mitem->flags;
				update_item_value(bt, item, mitem->val, mitem->val_len);
				scoutfs_inc_counter(sb, btree_merge_update);
			}

			/* update combined delta item seq */
			if (delta == SCOUTFS_DELTA_COMBINED) {
				item->seq = cpu_to_le64(mitem->seq);
			}

			/*
			 * combined delta items that aren't needed are
			 * immediately dropped.  We don't back off if
			 * the deletion would fall under the low water
			 * mark because we've already modified the
			 * value, we don't want to retry after a join
			 * and apply the value a second time.
			 */
			if (delta == SCOUTFS_DELTA_COMBINED_NULL) {
				delete_item(bt, item, NULL);
				scoutfs_inc_counter(sb, btree_merge_delta_null);
			}

			/* delete if merge item was deletion */
			if (item && is_del) {
				/* rewalk and join if non-root falls under low water mark */
				if (root->ref.blkno != bt->hdr.blkno &&
				    !total_above_join_low_water(bt)) {
					walk_flags |= BTW_DELETE;
					break;
				}
				delete_item(bt, item, NULL);
				scoutfs_inc_counter(sb, btree_merge_delete);
			}

			/* reset walk args now that we're not split/join */
			walk_flags &= ~(BTW_INSERT | BTW_DELETE);
			walk_val_len = 0;

			/* finished with this merged item */
			tmp = mitem;
			mitem = next_mitem(mitem);
			free_mitem(&rng, tmp);
		}
	}

	ret = 0;
out:
	scoutfs_block_put(sb, bl);
	rbtree_postorder_for_each_entry_safe(mitem, tmp, &rng.root, node)
		free_mitem(&rng, mitem);

	return ret;
}

/*
 * Free all the blocks referenced by a btree.  The btree is only read,
 * this does not update the blocks as it frees.  The caller ensures that
 * these btrees aren't been modified.
 *
 * The caller's key tracks which blocks have been freed.  It must be
 * initialized to zeros before the first call to start freeing blocks.
 * Once a block is freed the key is updated such that the freed block
 * will not be read again.
 *
 * Returns 0 when progress has been made successfully, which includes
 * partial progress.  The key is set to all ones once we've freed all
 * the blocks.
 *
 * This works by descending to the last parent block and freeing all its
 * leaf blocks without reading them.  As it descends it remembers the
 * number of parent blocks which were traversed through their final
 * child ref.  If we free all the leaf blocks then all these parent
 * blocks are no longer needed and can be freed.  The caller's key is
 * updated to past the subtree that we just freed and we retry the
 * descent from the root through the next set of parents to the next set
 * of leaf blocks to free.
 */
int scoutfs_btree_free_blocks(struct super_block *sb,
			      struct scoutfs_alloc *alloc,
			      struct scoutfs_block_writer *wri,
			      struct scoutfs_key *key,
			      struct scoutfs_btree_root *root, int free_budget)
{
	u64 blknos[SCOUTFS_BTREE_MAX_HEIGHT];
	struct scoutfs_block *bl = NULL;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block_ref ref;
	struct scoutfs_avl_node *node;
	struct scoutfs_avl_node *next;
	struct scoutfs_key par_next;
	int nr_freed = 0;
	int nr_par;
	int level;
	int ret;
	int i;

	if (WARN_ON_ONCE(free_budget <= 0))
		return -EINVAL;

	if (WARN_ON_ONCE(root->height > ARRAY_SIZE(blknos)))
		return -EIO; /* XXX corruption */

	if (root->height == 0) {
		scoutfs_key_set_ones(key);
		return 0;
	}

	if (scoutfs_key_is_ones(key))
		return 0;

	/* just free a single leaf block */
	if (root->height == 1) {
		ret = scoutfs_free_meta(sb, alloc, wri,
					le64_to_cpu(root->ref.blkno));
		if (ret == 0) {
			trace_scoutfs_btree_free_blocks_single(sb, root,
						le64_to_cpu(root->ref.blkno));
			scoutfs_key_set_ones(key);
		}
		goto out;
	}

	for (;;) {
		/* start the walk at the root block */
		level = root->height - 1;
		ref = root->ref;
		scoutfs_key_set_ones(&par_next);
		nr_par = 0;

		/* read blocks until we read the last parent */
		for (;;) {
			scoutfs_block_put(sb, bl);
			bl = NULL;
			ret = get_ref_block(sb, alloc, wri, 0, &ref, &bl);
			if (ret < 0)
				goto out;
			bt = bl->data;

			node = scoutfs_avl_search(&bt->item_root, cmp_key_item,
						  key, NULL, NULL, &next, NULL);
			if (node == NULL)
				node = next;

			/* should never descend into parent with no more refs */
			if (WARN_ON_ONCE(node == NULL)) {
				ret = -EIO;
				goto out;
			}

			/* we'll free refs in the last parent */
			if (level == 1)
				break;

			item = node_item(node);
			next = scoutfs_avl_next(&bt->item_root, node);
			if (next) {
				/* didn't take last ref, still need parents */
				nr_par = 0;
				par_next = *item_key(item);
				scoutfs_key_inc(&par_next);
			} else {
				/* final ref, could free after all leaves */
				blknos[nr_par++] = le64_to_cpu(bt->hdr.blkno);
			}

			memcpy(&ref, item_val(bt, item), sizeof(ref));
			level--;
		}

		/* free all leaf block refs in last parent */
		while (node) {

			/* make sure we can always free parents after leaves */
			if ((nr_freed + 1 + nr_par) > free_budget) {
				ret = 0;
				goto out;
			}

			item = node_item(node);
			memcpy(&ref, item_val(bt, item), sizeof(ref));

			trace_scoutfs_btree_free_blocks_leaf(sb, root,
							le64_to_cpu(ref.blkno));
			ret = scoutfs_free_meta(sb, alloc, wri,
						le64_to_cpu(ref.blkno));
			if (ret < 0)
				goto out;
			nr_freed++;

			node = scoutfs_avl_next(&bt->item_root, node);
			if (node) {
				/* done with keys in child we just freed */
				*key = *item_key(item);
				scoutfs_key_inc(key);
			}
		}

		/* now that leaves are freed, free any empty parents */
		for (i = 0; i < nr_par; i++) {
			trace_scoutfs_btree_free_blocks_parent(sb, root,
							       blknos[i]);
			ret = scoutfs_free_meta(sb, alloc, wri, blknos[i]);
			BUG_ON(ret); /* checked meta low, freed should fit */
			nr_freed++;
		}

		/* restart walk past the subtree we just freed */
		*key = par_next;

		/* but done if we just freed all parents down right spine */
		if (scoutfs_key_is_ones(&par_next)) {
			ret = 0;
			goto out;
		}
	}

out:
	scoutfs_block_put(sb, bl);
	return ret;
}
