#ifndef _BTREE_H_
#define _BTREE_H_

void btree_init_block(struct scoutfs_btree_block *bt, int level);
void btree_init_root_single(struct scoutfs_btree_root *root,
			    struct scoutfs_btree_block *bt,
			    u64 seq, u64 blkno);

void btree_append_item(struct scoutfs_btree_block *bt,
		       struct scoutfs_key *key, void *val, int val_len);

#endif
