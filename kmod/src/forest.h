#ifndef _SCOUTFS_FOREST_H_
#define _SCOUTFS_FOREST_H_

struct scoutfs_alloc;
struct scoutfs_block_writer;
struct scoutfs_block;
struct scoutfs_lock;

#include "btree.h"

/* caller gives an item to the callback */
enum {
	FIC_FS_ROOT = (1 << 0),
	FIC_FINALIZED = (1 << 1),
};
typedef int (*scoutfs_forest_item_cb)(struct super_block *sb, struct scoutfs_key *key, u64 seq,
				      u8 flags, void *val, int val_len, int fic, void *arg);

int scoutfs_forest_next_hint(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_key *next);
int scoutfs_forest_read_items(struct super_block *sb,
			      struct scoutfs_key *key,
			      struct scoutfs_key *bloom_key,
			      struct scoutfs_key *start,
			      struct scoutfs_key *end,
			      scoutfs_forest_item_cb cb, void *arg);
int scoutfs_forest_set_bloom_bits(struct super_block *sb,
				  struct scoutfs_lock *lock);
void scoutfs_forest_set_max_seq(struct super_block *sb, u64 max_seq);
int scoutfs_forest_get_max_seq(struct super_block *sb,
			       struct scoutfs_super_block *super,
			       u64 *seq);
int scoutfs_forest_insert_list(struct super_block *sb,
			       struct scoutfs_btree_item_list *lst);
int scoutfs_forest_srch_add(struct super_block *sb, u64 hash, u64 ino, u64 id);

void scoutfs_forest_inc_inode_count(struct super_block *sb);
void scoutfs_forest_dec_inode_count(struct super_block *sb);
int scoutfs_forest_inode_count(struct super_block *sb, struct scoutfs_super_block *super,
			       u64 *inode_count);

void scoutfs_forest_init_btrees(struct super_block *sb,
				struct scoutfs_alloc *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_log_trees *lt);
void scoutfs_forest_get_btrees(struct super_block *sb,
			       struct scoutfs_log_trees *lt);

/* > 0 error codes */
#define SCOUTFS_DELTA_COMBINED		1	/* src val was combined, drop src */
#define SCOUTFS_DELTA_COMBINED_NULL	2	/* combined val has no data, drop both */
int scoutfs_forest_combine_deltas(struct scoutfs_key *key, void *dst, int dst_len,
				  void *src, int src_len);

int scoutfs_forest_setup(struct super_block *sb);
void scoutfs_forest_start(struct super_block *sb);
void scoutfs_forest_stop(struct super_block *sb);
void scoutfs_forest_destroy(struct super_block *sb);

#endif
