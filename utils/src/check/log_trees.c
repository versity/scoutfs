#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "key.h"

#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "extent.h"
#include "iter.h"
#include "sns.h"
#include "log_trees.h"
#include "super.h"

struct iter_args {
	extent_cb_t cb;
	void *cb_arg;
};

static int lt_meta_iter(struct scoutfs_key *key, void *val, u16 val_len, void *cb_arg)
{
	struct iter_args *ia = cb_arg;
	struct scoutfs_log_trees *lt;
	int ret;

	if (val_len != sizeof(struct scoutfs_log_trees))
		; /* XXX */

	lt = val;

	sns_push("log_trees", le64_to_cpu(lt->rid), le64_to_cpu(lt->nr));

	debug("lt rid 0x%16llx nr %llu", le64_to_cpu(lt->rid), le64_to_cpu(lt->nr));

	sns_push("meta_avail", 0, 0);
	ret = alloc_list_meta_iter(&lt->meta_avail, ia->cb, ia->cb_arg);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("meta_freed", 0, 0);
	ret = alloc_list_meta_iter(&lt->meta_freed, ia->cb, ia->cb_arg);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("item_root", 0, 0);
	ret = btree_meta_iter(&lt->item_root, ia->cb, ia->cb_arg);
	sns_pop();
	if (ret < 0)
		goto out;

	if (lt->bloom_ref.blkno) {
		sns_push("bloom_ref", 0, 0);
		ret = ia->cb(le64_to_cpu(lt->bloom_ref.blkno), 1, ia->cb_arg);
		sns_pop();
		if (ret < 0) {
			ret = xlate_iter_errno(ret);
			goto out;
		}
	}

	sns_push("data_avail", 0, 0);
	ret = alloc_root_meta_iter(&lt->data_avail, ia->cb, ia->cb_arg);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("data_freed", 0, 0);
	ret = alloc_root_meta_iter(&lt->data_freed, ia->cb, ia->cb_arg);
	sns_pop();
	if (ret < 0)
		goto out;

	ret = 0;
out:
	sns_pop();

	return ret;
}

/*
 * Call the callers callback with the extent of all the metadata block references contained
 * in log btrees.  We walk the logs_root btree items and walk all the metadata structures
 * they reference.
 */
int log_trees_meta_iter(extent_cb_t cb, void *cb_arg)
{
	struct scoutfs_super_block *super = global_super;
	struct iter_args ia = { .cb = cb, .cb_arg = cb_arg };

	return btree_item_iter(&super->logs_root, lt_meta_iter, &ia);
}
