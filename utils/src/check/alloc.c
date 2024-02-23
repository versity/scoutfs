#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "bitmap.h"
#include "key.h"

#include "alloc.h"
#include "block.h"
#include "btree.h"
#include "extent.h"
#include "iter.h"
#include "sns.h"

/*
 * We check the list blocks serially.
 *
 * XXX:
 *  - compare ref seqs
 *  - detect cycles?
 */
int alloc_list_meta_iter(struct scoutfs_alloc_list_head *lhead, extent_cb_t cb, void *cb_arg)
{
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block_ref ref;
	struct block *blk = NULL;
	u64 blkno;
	int ret;

	ref = lhead->ref;

	while (ref.blkno) {
		blkno = le64_to_cpu(ref.blkno);

		ret = cb(blkno, 1, cb_arg);
		if (ret < 0) {
			ret = xlate_iter_errno(ret);
			goto out;
		}

		ret = block_get(&blk, blkno, 0);
		if (ret < 0)
			goto out;

		lblk = block_buf(blk);
		/* XXX verify block */
		/* XXX sort?   maybe */

		ref = lblk->next;

		block_put(&blk);
	}

	ret = 0;
out:
	return ret;
}

int alloc_root_meta_iter(struct scoutfs_alloc_root *root, extent_cb_t cb, void *cb_arg)
{
	return btree_meta_iter(&root->root, cb, cb_arg);
}

int alloc_list_extent_iter(struct scoutfs_alloc_list_head *lhead, extent_cb_t cb, void *cb_arg)
{
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block_ref ref;
	struct block *blk = NULL;
	u64 blkno;
	int ret;
	int i;

	ref = lhead->ref;

	while (ref.blkno) {
		blkno = le64_to_cpu(ref.blkno);

		ret = block_get(&blk, blkno, 0);
		if (ret < 0)
			goto out;

		sns_push("alloc_list_block", blkno, 0);

		lblk = block_buf(blk);
		/* XXX verify block */
		/* XXX sort?   maybe */

		ret = 0;
		for (i = 0; i < le32_to_cpu(lblk->nr); i++) {
			blkno = le64_to_cpu(lblk->blknos[le32_to_cpu(lblk->start) + i]);

			ret = cb(blkno, 1, cb_arg);
			if (ret < 0)
				break;
		}

		ref = lblk->next;

		block_put(&blk);
		sns_pop();
		if (ret < 0) {
			ret = xlate_iter_errno(ret);
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

static bool valid_free_extent_key(struct scoutfs_key *key)
{
	return (key->sk_zone == SCOUTFS_FREE_EXTENT_BLKNO_ZONE ||
	        key->sk_zone == SCOUTFS_FREE_EXTENT_ORDER_ZONE) &&
	       (!key->_sk_fourth && !key->sk_type &&
		(key->sk_zone == SCOUTFS_FREE_EXTENT_ORDER_ZONE || !key->_sk_third));
}

static int free_item_cb(struct scoutfs_key *key, void *val, u16 val_len, void *cb_arg)
{
	struct extent_cb_arg_t *ecba = cb_arg;
	u64 start;
	u64 len;

	/* XXX not sure these eios are what we want */

	if (val_len != 0)
		return -EIO;

	if (!valid_free_extent_key(key))
		return -EIO;

	if (key->sk_zone == SCOUTFS_FREE_EXTENT_ORDER_ZONE)
		return -ECHECK_ITER_DONE;

	start = le64_to_cpu(key->skfb_end) - le64_to_cpu(key->skfb_len) + 1;
	len = le64_to_cpu(key->skfb_len);

	return ecba->cb(start, len, ecba->cb_arg);
}

/*
 * Call the callback with each of the primary BLKNO free extents stored
 * in item in the given alloc root.  It doesn't visit the secondary
 * ORDER extents.
 */
int alloc_root_extent_iter(struct scoutfs_alloc_root *root, extent_cb_t cb, void *cb_arg)
{
	struct extent_cb_arg_t ecba = { .cb = cb, .cb_arg = cb_arg };

	return btree_item_iter(&root->root, free_item_cb, &ecba);
}
