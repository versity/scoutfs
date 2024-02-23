#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "key.h"
#include "avl.h"

#include "block.h"
#include "btree.h"
#include "extent.h"
#include "iter.h"
#include "sns.h"
#include "meta.h"
#include "problem.h"

static inline void *item_val(struct scoutfs_btree_block *bt, struct scoutfs_btree_item *item)
{
	return (void *)bt + le16_to_cpu(item->val_off);
}

static void readahead_refs(struct scoutfs_btree_block *bt)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *node;
	struct scoutfs_block_ref *ref;
	u64 *blknos;
	u64 blkno;
	u16 valid = 0;
	u16 nr = le16_to_cpu(bt->nr_items);
	int i;

	blknos = calloc(nr, sizeof(blknos[0]));
	if (!blknos)
		return;

	node = avl_first(&bt->item_root);

	for (i = 0; i < nr; i++) {
		item = container_of(node, struct scoutfs_btree_item, node);
		ref = item_val(bt, item);
		blkno = le64_to_cpu(ref->blkno);

		if (valid_meta_blkno(blkno))
			blknos[valid++] = blkno;

		node = avl_next(&bt->item_root, &item->node);
	}

	if (valid > 0)
		block_readahead(blknos, valid);
	free(blknos);
}

/*
 * Call the callback on the referenced block.  Then if the block
 * contains referneces read it and recurse into all its references.
 */
static int btree_ref_meta_iter(struct scoutfs_block_ref *ref, unsigned level, extent_cb_t cb,
			       void *cb_arg)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_avl_node *node;
	struct block *blk = NULL;
	u64 blkno;
	int ret;
	int i;

	blkno = le64_to_cpu(ref->blkno);
	if (!blkno)
		return 0;

	ret = cb(blkno, 1, cb_arg);
	if (ret < 0) {
		ret = xlate_iter_errno(ret);
		return 0;
	}

	if (level == 0)
		return 0;

	ret = block_get(&blk, blkno, 0);
	if (ret < 0)
		return ret;

	sns_push("btree_parent", blkno, 0);

	bt = block_buf(blk);

	/* XXX integrate verification with block cache */
	if (bt->level != level) {
		problem(PB_BTREE_BLOCK_BAD_LEVEL, "expected %u level %u", level, bt->level);
		ret = -EINVAL;
		goto out;
	}

	/* read-ahead last level of parents */
	if (level == 2)
		readahead_refs(bt);

	node = avl_first(&bt->item_root);

	for (i = 0; i < le16_to_cpu(bt->nr_items); i++) {
		item = container_of(node, struct scoutfs_btree_item, node);
		ref = item_val(bt, item);

		ret = btree_ref_meta_iter(ref, level - 1, cb, cb_arg);
		if (ret < 0)
			goto out;

		node = avl_next(&bt->item_root, &item->node);
	}

	ret = 0;
out:
	block_put(&blk);
	sns_pop();

	return ret;
}

int btree_meta_iter(struct scoutfs_btree_root *root, extent_cb_t cb, void *cb_arg)
{
	/* XXX check root */
	if (root->height == 0)
		return 0;

	return btree_ref_meta_iter(&root->ref, root->height - 1, cb, cb_arg);
}

static int btree_ref_item_iter(struct scoutfs_block_ref *ref, unsigned level,
			       btree_item_cb_t cb, void *cb_arg)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_avl_node *node;
	struct block *blk = NULL;
	u64 blkno;
	int ret;
	int i;

	blkno = le64_to_cpu(ref->blkno);
	if (!blkno)
		return 0;

	ret = block_get(&blk, blkno, 0);
	if (ret < 0)
		return ret;

	if (level)
		sns_push("btree_parent", blkno, 0);
	else
		sns_push("btree_leaf", blkno, 0);

	bt = block_buf(blk);

	/* XXX integrate verification with block cache */
	if (bt->level != level) {
		problem(PB_BTREE_BLOCK_BAD_LEVEL, "expected %u level %u", level, bt->level);
		ret = -EINVAL;
		goto out;
	}

	/* read-ahead leaves that contain items */
	if (level == 1)
		readahead_refs(bt);

	node = avl_first(&bt->item_root);

	for (i = 0; i < le16_to_cpu(bt->nr_items); i++) {
		item = container_of(node, struct scoutfs_btree_item, node);

		if (level) {
			ref = item_val(bt, item);
			ret = btree_ref_item_iter(ref, level - 1, cb, cb_arg);
		} else {
			ret = cb(&item->key, item_val(bt, item),
				 le16_to_cpu(item->val_len), cb_arg);
			debug("free item key "SK_FMT" ret %d", SK_ARG(&item->key), ret);
		}
		if (ret < 0) {
			ret = xlate_iter_errno(ret);
			goto out;
		}

		node = avl_next(&bt->item_root, &item->node);
	}

	ret = 0;
out:
	block_put(&blk);
	sns_pop();

	return ret;
}

int btree_item_iter(struct scoutfs_btree_root *root, btree_item_cb_t cb, void *cb_arg)
{
	/* XXX check root */
	if (root->height == 0)
		return 0;

	return btree_ref_item_iter(&root->ref, root->height - 1, cb, cb_arg);
}
