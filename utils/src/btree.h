#ifndef _BTREE_H_
#define _BTREE_H_

void btree_init_root_single(struct scoutfs_btree_root *root,
			    struct scoutfs_btree_block *bt,
			    u64 blkno, u64 seq, __le64 fsid);

void btree_append_item(struct scoutfs_btree_block *bt,
		       struct scoutfs_key *key, void *val, int val_len);

#endif
