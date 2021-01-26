#ifndef _SCOUTFS_FOREST_H_
#define _SCOUTFS_FOREST_H_

struct scoutfs_alloc;
struct scoutfs_block_writer;
struct scoutfs_block;

#include "btree.h"

/* caller gives an item to the callback */
typedef int (*scoutfs_forest_item_cb)(struct super_block *sb,
				      struct scoutfs_key *key,
				      struct scoutfs_log_item_value *liv,
				      void *val, int val_len, void *arg);

int scoutfs_forest_next_hint(struct super_block *sb, struct scoutfs_key *key,
			     struct scoutfs_key *next);
int scoutfs_forest_read_items(struct super_block *sb,
			      struct scoutfs_lock *lock,
			      struct scoutfs_key *key,
			      struct scoutfs_key *start,
			      struct scoutfs_key *end,
			      scoutfs_forest_item_cb cb, void *arg);
int scoutfs_forest_set_bloom_bits(struct super_block *sb,
				  struct scoutfs_lock *lock);
void scoutfs_forest_set_max_vers(struct super_block *sb, u64 max_vers);
int scoutfs_forest_get_max_vers(struct super_block *sb,
				struct scoutfs_super_block *super,
				u64 *vers);
int scoutfs_forest_insert_list(struct super_block *sb,
			       struct scoutfs_btree_item_list *lst);
int scoutfs_forest_srch_add(struct super_block *sb, u64 hash, u64 ino, u64 id);

void scoutfs_forest_init_btrees(struct super_block *sb,
				struct scoutfs_alloc *alloc,
				struct scoutfs_block_writer *wri,
				struct scoutfs_log_trees *lt);
void scoutfs_forest_get_btrees(struct super_block *sb,
			       struct scoutfs_log_trees *lt);

int scoutfs_forest_setup(struct super_block *sb);
void scoutfs_forest_shutdown(struct super_block *sb);
void scoutfs_forest_destroy(struct super_block *sb);

void scoutfs_forest_oino_inc(struct super_block *sb, u64 ino);
void scoutfs_forest_oino_dec(struct super_block *sb, u64 ino);
void scoutfs_forest_oino_new_orphan(struct super_block *sb);
struct scoutfs_block *scoutfs_forest_oino_alloc(struct super_block *sb,
						struct scoutfs_alloc *alloc,
						struct scoutfs_block_writer *wri,
						u64 trans_seq);
int scoutfs_forest_oino_newtrans_alloc(struct super_block *sb, u64 trans_seq);
int scoutfs_forest_oino_update(struct super_block *sb);
bool scoutfs_forest_oino_deletable(struct super_block *sb,
				   __le64 le_ino,
				   u64 orphan_seq,
				   struct scoutfs_bloom_block *bb);

#endif
