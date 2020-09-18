#include <assert.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "key.h"
#include "avl.h"
#include "leaf_item_hash.h"
#include "btree.h"

static void init_block(struct scoutfs_btree_block *bt, int level)
{
	int free;

	free = SCOUTFS_BLOCK_LG_SIZE - sizeof(struct scoutfs_btree_block);
	if (level == 0)
		free -= SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES;

	bt->level = level;
	bt->mid_free_len = cpu_to_le16(free);
}

/*
 * Point the root at the single leaf block that makes up a btree.
 */
void btree_init_root_single(struct scoutfs_btree_root *root,
			    struct scoutfs_btree_block *bt,
			    u64 blkno, u64 seq, __le64 fsid)
{
	root->ref.blkno = cpu_to_le64(blkno);
	root->ref.seq = cpu_to_le64(1);
	root->height = 1;

	memset(bt, 0, SCOUTFS_BLOCK_LG_SIZE);
	bt->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BTREE);
	bt->hdr.fsid = fsid;
	bt->hdr.blkno = cpu_to_le64(blkno);
	bt->hdr.seq = cpu_to_le64(1);

	init_block(bt, 0);
}

static void *alloc_val(struct scoutfs_btree_block *bt, int len)
{
	le16_add_cpu(&bt->mid_free_len, -len);
	le16_add_cpu(&bt->total_item_bytes, len);
	return (void *)bt + le16_to_cpu(bt->mid_free_len);
}

/*
 * Add a sorted item after all the items in the block.
 *
 * We simply implement the special case of a wildly imbalanced avl tree.
 * Mkfs only ever inserts a handful of items and they'll be rebalanced
 * over time.
 */
void btree_append_item(struct scoutfs_btree_block *bt,
		       struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *prev;
	__le16 *own_buf;
	__le16 own;
	void *val_buf;

	item = &bt->items[le16_to_cpu(bt->nr_items)];

	if (bt->nr_items) {
		assert(scoutfs_key_compare(key, &(item - 1)->key) > 0);
		prev = &(item - 1)->node;

		item->node.height = prev->height++;
		item->node.left = avl_node_off(&bt->item_root, prev);
		prev->parent = avl_node_off(&bt->item_root, &item->node);
	}

	bt->item_root.node = avl_node_off(&bt->item_root, &item->node);
	le16_add_cpu(&bt->nr_items, 1);
	le16_add_cpu(&bt->mid_free_len,
		     -(u16)sizeof(struct scoutfs_btree_item));
	le16_add_cpu(&bt->total_item_bytes, sizeof(struct scoutfs_btree_item));

	item->key = *key;
	leaf_item_hash_insert(bt, &item->key,
			      cpu_to_le16((void *)item - (void *)bt));
	if (val_len == 0)
		return;

	own_buf = alloc_val(bt, SCOUTFS_BTREE_VAL_OWNER_BYTES);
	own = cpu_to_le16((void *)item - (void *)bt);
	memcpy(own_buf, &own, sizeof(own));

	val_buf = alloc_val(bt, val_len);
	item->val_off = cpu_to_le16((void *)val_buf - (void *)bt);
	item->val_len = cpu_to_le16(val_len);
	memcpy(val_buf, val, val_len);
}
