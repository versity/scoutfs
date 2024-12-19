#ifndef _SCOUTFS_UTILS_CHECK_BTREE_H_
#define _SCOUTFS_UTILS_CHECK_BTREE_H_

#include "util.h"
#include "format.h"

#include "extent.h"

typedef int (*btree_item_cb_t)(struct scoutfs_key *key, void *val, u16 val_len, void *cb_arg);

int btree_meta_iter(struct scoutfs_btree_root *root, extent_cb_t cb, void *cb_arg);
int btree_item_iter(struct scoutfs_btree_root *root, btree_item_cb_t cb, void *cb_arg);

#endif
