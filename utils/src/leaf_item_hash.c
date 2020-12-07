#include "sparse.h"
#include "util.h"
#include "format.h"
#include "hash.h"
#include "leaf_item_hash.h"

/*
 * A minimal extraction of the leaf item hash from the kernel's btree.
 */

int leaf_item_hash_ind(struct scoutfs_key *key)
{
	return scoutfs_hash32(key, sizeof(struct scoutfs_key)) %
	       SCOUTFS_BTREE_LEAF_ITEM_HASH_NR;
}

__le16 *leaf_item_hash_buckets(struct scoutfs_btree_block *bt)
{
	return (void *)bt + SCOUTFS_BLOCK_LG_SIZE -
		SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES;
}

void leaf_item_hash_insert(struct scoutfs_btree_block *bt,
			   struct scoutfs_key *key, __le16 off)
{
	__le16 *buckets = leaf_item_hash_buckets(bt);
	int i;

	if (bt->level > 0)
		return;

	for (i = leaf_item_hash_ind(key);
	     i < SCOUTFS_BTREE_LEAF_ITEM_HASH_NR; i++) {
		if (buckets[i] == 0) {
			buckets[i] = off;
			return;
		}
	}
}
