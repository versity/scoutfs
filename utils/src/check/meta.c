#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "bitmap.h"
#include "key.h"

#include "alloc.h"
#include "btree.h"
#include "debug.h"
#include "extent.h"
#include "sns.h"
#include "log_trees.h"
#include "meta.h"
#include "problem.h"
#include "super.h"

static struct meta_data {
	struct extent_root meta_refed;
	struct extent_root meta_free;
	struct {
		u64 ref_blocks;
		u64 free_extents;
		u64 free_blocks;
	} stats;
} global_mdat;

bool valid_meta_blkno(u64 blkno)
{
	u64 tot = le64_to_cpu(global_super->total_meta_blocks);

	return blkno >= SCOUTFS_META_DEV_START_BLKNO && blkno < tot;
}

static bool valid_meta_extent(u64 start, u64 len)
{
	u64 tot = le64_to_cpu(global_super->total_meta_blocks);
	bool valid;

	valid = len > 0 &&
		start >= SCOUTFS_META_DEV_START_BLKNO &&
		start < tot &&
		len <= tot &&
		((start + len) <= tot) &&
		((start + len) > start);

	debug("start %llu len %llu valid %u", start, len, !!valid);

	if (!valid)
		problem(PB_META_EXTENT_INVALID, "start %llu len %llu", start, len);

	return valid;
}

/*
 * Track references to individual metadata blocks.  This uses the extent
 * callback type but is only ever called for single block references.
 * Any reference to a block that has already been referenced is
 * considered invalid and is ignored.  Later repair will resolve
 * duplicate references.
 */
static int insert_meta_ref(u64 start, u64 len, void *arg)
{
	struct meta_data *mdat = &global_mdat;
	struct extent_root *root = arg;
	int ret = 0;

	/* this is tracking single metadata block references */
	if (len != 1) {
		ret = -EINVAL;
		goto out;
	}

	if (valid_meta_blkno(start)) {
		ret = extent_insert_new(root, start, len);
		if (ret == 0)
			mdat->stats.ref_blocks++;
		else if (ret == -EEXIST)
			problem(PB_META_REF_OVERLAPS_EXISTING, "blkno %llu", start);
	}

out:
	return ret;
}

static int insert_meta_free(u64 start, u64 len, void *arg)
{
	struct meta_data *mdat = &global_mdat;
	struct extent_root *root = arg;
	int ret = 0;

	if (valid_meta_extent(start, len)) {
		ret = extent_insert_new(root, start, len);
		if (ret == 0) {
			mdat->stats.free_extents++;
			mdat->stats.free_blocks++;

		} else if (ret == -EEXIST) {
			problem(PB_META_FREE_OVERLAPS_EXISTING,
				"start %llu llen %llu", start, len);
		}

	}

	return ret;
}

/*
 * Walk all metadata references in the system.  This walk doesn't need
 * to read metadata that doesn't contain any metadata references so it
 * can skip the bulk of metadata blocks.  This gives us the set of
 * referenced metadata blocks which we can then use to repair metadata
 * allocator structures.
 */
static int get_meta_refs(void)
{
	struct meta_data *mdat = &global_mdat;
	struct scoutfs_super_block *super = global_super;
	int ret;

	extent_root_init(&mdat->meta_refed);

	/* XXX record reserved blocks around super as referenced */

	sns_push("meta_alloc", 0, 0);
	ret = alloc_root_meta_iter(&super->meta_alloc[0], insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("meta_alloc", 1, 0);
	ret = alloc_root_meta_iter(&super->meta_alloc[1], insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("data_alloc", 1, 0);
	ret = alloc_root_meta_iter(&super->data_alloc, insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_avail", 0, 0);
	ret = alloc_list_meta_iter(&super->server_meta_avail[0],
				   insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_avail", 1, 0);
	ret = alloc_list_meta_iter(&super->server_meta_avail[1],
				   insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_freed", 0, 0);
	ret = alloc_list_meta_iter(&super->server_meta_freed[0],
				   insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_freed", 1, 0);
	ret = alloc_list_meta_iter(&super->server_meta_freed[1],
				   insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("fs_root", 0, 0);
	ret = btree_meta_iter(&super->fs_root, insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("logs_root", 0, 0);
	ret = btree_meta_iter(&super->logs_root, insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("log_merge", 0, 0);
	ret = btree_meta_iter(&super->log_merge, insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("mounted_clients", 0, 0);
	ret = btree_meta_iter(&super->mounted_clients, insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("srch_root", 0, 0);
	ret = btree_meta_iter(&super->srch_root, insert_meta_ref, &mdat->meta_refed);
	sns_pop();
	if (ret < 0)
		goto out;

	ret = log_trees_meta_iter(insert_meta_ref, &mdat->meta_refed);
	if (ret < 0)
		goto out;

	debug("found %llu referenced metadata blocks", mdat->stats.ref_blocks);
	ret = 0;
out:
	return ret;
}

static int get_meta_free(void)
{
	struct meta_data *mdat = &global_mdat;
	struct scoutfs_super_block *super = global_super;
	int ret;

	extent_root_init(&mdat->meta_free);

	sns_push("meta_alloc", 0, 0);
	ret = alloc_root_extent_iter(&super->meta_alloc[0], insert_meta_free, &mdat->meta_free);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("meta_alloc", 1, 0);
	ret = alloc_root_extent_iter(&super->meta_alloc[1], insert_meta_free, &mdat->meta_free);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_avail", 0, 0);
	ret = alloc_list_extent_iter(&super->server_meta_avail[0],
				     insert_meta_free, &mdat->meta_free);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_avail", 1, 0);
	ret = alloc_list_extent_iter(&super->server_meta_avail[1],
				     insert_meta_free, &mdat->meta_free);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_freed", 0, 0);
	ret = alloc_list_extent_iter(&super->server_meta_freed[0],
				     insert_meta_free, &mdat->meta_free);
	sns_pop();
	if (ret < 0)
		goto out;

	sns_push("server_meta_freed", 1, 0);
	ret = alloc_list_extent_iter(&super->server_meta_freed[1],
				     insert_meta_free, &mdat->meta_free);
	sns_pop();
	if (ret < 0)
		goto out;

	debug("found %llu free metadata blocks in %llu extents",
	       mdat->stats.free_blocks, mdat->stats.free_extents);
	ret = 0;
out:
	return ret;
}

/*
 * All the space between referenced blocks must be recorded in the free
 * extents.  The free extent walk didn't check that the extents
 * overlapped with references, we do that here.  Remember that metadata
 * block references were merged into extents here, the refed extents
 * aren't necessarily all a single block.
 */
static int compare_refs_and_free(void)
{
	struct meta_data *mdat = &global_mdat;
	struct extent_node *ref;
	struct extent_node *free;
	struct extent_node *next;
	struct extent_node *prev;
	u64 expect;
	u64 start;
	u64 end;

	expect = 0;
	ref = extent_first(&mdat->meta_refed);
	free = extent_first(&mdat->meta_free);
	while (ref || free) {

		debug("exp %llu ref %llu.%llu free %llu.%llu",
			expect, ref ? ref->start : 0, ref ? ref->len : 0,
			free ? free->start : 0, free ? free->len : 0);

		/* referenced marked free, remove ref from free and continue from same point */
		if (ref && free && extents_overlap(ref->start, ref->len, free->start, free->len)) {
			debug("ref extent %llu.%llu overlaps free %llu %llu",
				ref->start, ref->len, free->start, free->len);

			start = max(ref->start, free->start);
			end = min(ref->start + ref->len, free->start + free->len);

			prev = extent_prev(free);

			extent_remove(&mdat->meta_free, start, end - start);

			if (prev)
				free = extent_next(prev);
			else
				free = extent_first(&mdat->meta_free);
			continue;
		}

		/* see which extent starts earlier */
		if (!free || (ref && ref->start <= free->start))
			next = ref;
		else
			next = free;

		/* untracked region before next extent */
		if (expect < next->start) {
			debug("missing free extent %llu.%llu", expect, next->start - expect);
			expect = next->start;
			continue;
		}


		/* didn't overlap, advance past next extent */
		expect = next->start + next->len;
		if (next == ref)
			ref = extent_next(ref);
		else
			free = extent_next(free);
	}

	return 0;
}

/*
 * Check the metadata allocators by comparing the set of referenced
 * blocks with the set of free blocks that are stored in free btree
 * items and alloc list blocks.
 */
int check_meta_alloc(void)
{
	int ret;

	ret = get_meta_refs();
	if (ret < 0)
		goto out;

	ret = get_meta_free();
	if (ret < 0)
		goto out;

	ret = compare_refs_and_free();
	if (ret < 0)
		goto out;

	ret = 0;
out:
	return ret;
}
