#ifndef _SCOUTFS_UTILS_CHECK_ALLOC_H
#define _SCOUTFS_UTILS_CHECK_ALLOC_H

#include "extent.h"

int alloc_list_meta_iter(struct scoutfs_alloc_list_head *lhead, extent_cb_t cb, void *cb_arg);
int alloc_root_meta_iter(struct scoutfs_alloc_root *root, extent_cb_t cb, void *cb_arg);

int alloc_list_extent_iter(struct scoutfs_alloc_list_head *lhead, extent_cb_t cb, void *cb_arg);
int alloc_root_extent_iter(struct scoutfs_alloc_root *root, extent_cb_t cb, void *cb_arg);

#endif
