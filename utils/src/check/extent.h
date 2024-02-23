#ifndef _SCOUTFS_UTILS_CHECK_EXTENT_H_
#define _SCOUTFS_UTILS_CHECK_EXTENT_H_

#include "lk_rbtree_wrapper.h"

struct extent_root {
	struct rb_root rbroot;
	u64 total;
};

struct extent_node {
	struct rb_node rbnode;
	u64 start;
	u64 len;
};

typedef int (*extent_cb_t)(u64 start, u64 len, void *arg);

struct extent_cb_arg_t {
	extent_cb_t cb;
	void *cb_arg;
};

bool extents_overlap(u64 a_start, u64 a_len, u64 b_start, u64 b_len);

int extent_lookup(struct extent_root *root, u64 start, u64 len, struct extent_node *found);
struct extent_node *extent_first(struct extent_root *root);
struct extent_node *extent_next(struct extent_node *ext);
struct extent_node *extent_prev(struct extent_node *ext);
int extent_insert_new(struct extent_root *root, u64 start, u64 len);
int extent_insert_extend(struct extent_root *root, u64 start, u64 len);
int extent_remove(struct extent_root *root, u64 start, u64 len);

void extent_root_init(struct extent_root *root);
void extent_root_free(struct extent_root *root);
void extent_root_print(struct extent_root *root);

#endif
