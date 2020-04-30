#ifndef _LEAF_ITEM_HASH_H_
#define _LEAF_ITEM_HASH_H_

int leaf_item_hash_ind(struct scoutfs_key *key);
__le16 *leaf_item_hash_buckets(struct scoutfs_btree_block *bt);
void leaf_item_hash_insert(struct scoutfs_btree_block *bt,
			   struct scoutfs_key *key, __le16 off);

#endif
