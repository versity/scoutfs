#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>

#include "super.h"
#include "format.h"
#include "block.h"
#include "msg.h"
#include "avl.h"
#include "check.h"

struct bit_map {
	unsigned long *addr;
	long size;
	long bytes;
};

static bool enabled = true;

#define warn_once_disable(sb, cond, fmt, args...)	\
({							\
	bool cond_ = (cond);				\
	static bool warned_ = false;			\
							\
	if (cond_ && !warned_) {			\
		scoutfs_err(sb, "check: " fmt, ##args);	\
		warned_ = true;				\
		enabled = false;			\
	}						\
							\
	cond_;						\
})

static void check_blkno(struct super_block *sb, struct bit_map *map, long nr)
{
	if (nr != 0 && !warn_once_disable(sb, nr < 0 || nr >= map->size,
					  "nr %ld outside map->size %ld", nr, map->size))
		warn_once_disable(sb, test_and_set_bit(nr, map->addr),
			           "nr %ld already set", nr);
}

static void check_extent(struct super_block *sb, struct bit_map *map, u64 start, u64 len)
{
	unsigned long nr;

	if (!warn_once_disable(sb, start >= map->size || len > map->size ||
				   (start + len) > map->size,
				   "start %llu len %llu oustdie map->size %ld",
				   start, len, map->size)) {

		nr = find_next_bit(map->addr, map->size, start);
		warn_once_disable(sb, nr < start + len,
				  "start %llu len %llu has bits already set, first %lu",
				  start, len, nr);

		bitmap_set(map->addr, start, len);
	}
}

static void check_block_ref(struct super_block *sb, struct bit_map *map,
			    struct scoutfs_block_ref *ref)
{
	check_blkno(sb, map, le64_to_cpu(ref->blkno));
}

/*
 * As long as we're not handling errors, we can have this return the
 * pointer to the block data if it was read successfully.  Everything
 * else returns null and the caller backs off.
 */
static void *read_block_ref(struct super_block *sb, struct bit_map *map,
			    struct scoutfs_block_ref *ref, u32 magic,
			    struct scoutfs_block **bl_ret)
{
	check_block_ref(sb, map, ref);

	if (ref->blkno != 0 && scoutfs_block_read_ref(sb, ref, magic, bl_ret) == 0)
		return (*bl_ret)->data;

	return NULL;
}

/* returns false if caller should stop iterating */
typedef bool (*check_btree_item_cb)(struct super_block *sb, struct bit_map *map,
				    struct scoutfs_key *key, void *val, u16 val_len);

/*
 * We walk the items in key order via the avl so that the item callbacks
 * can have us stop iterating based on their knowledge of key ordering.
 */
static void check_btree_block_ref(struct super_block *sb, struct bit_map *map,
				  u8 level, struct scoutfs_block_ref *ref,
				  check_btree_item_cb item_cb)
{
	struct scoutfs_block *bl = NULL;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *node;
	void *val;
	u16 val_off;
	u16 val_len;

	if (!(bt = read_block_ref(sb, map, ref, SCOUTFS_BLOCK_MAGIC_BTREE, &bl)))
		return;

	if (bt->level != level)
		goto out;

	for (node = scoutfs_avl_first(&bt->item_root);
	     node != NULL;
	     node = scoutfs_avl_next(&bt->item_root, node)) {
		item = container_of(node, struct scoutfs_btree_item, node);

		val_off = le16_to_cpu(item->val_off);
		val_len = le16_to_cpu(item->val_len);
		val = (void *)bt + val_off;

		if (bt->level > 0)
			check_btree_block_ref(sb, map, bt->level - 1, val, item_cb);
		else if (item_cb && !item_cb(sb, map, &item->key, val, val_len))
			break;
	}
out:
	scoutfs_block_put(sb, bl);
}

static void check_btree_root(struct super_block *sb, struct bit_map *map,
			     struct scoutfs_btree_root *root, check_btree_item_cb item_cb)
{
	if (root->height > 0)
		check_btree_block_ref(sb, map, root->height - 1, &root->ref, item_cb);
}

static bool check_alloc_extent_item(struct super_block *sb, struct bit_map *map,
				    struct scoutfs_key *key, void *val, u16 val_len)
{
	/* XXX only checking primary blkno items */
	if (key->sk_zone == SCOUTFS_FREE_EXTENT_BLKNO_ZONE) {
		check_extent(sb, map, le64_to_cpu(key->skfb_end) - le64_to_cpu(key->skfb_len) + 1,
				      le64_to_cpu(key->skfb_len));
		return true;
	}

	/* otherwise stop iterating over items */
	return false;
}

static void check_alloc_root(struct super_block *sb, struct bit_map *map,
			     struct scoutfs_alloc_root *root)
{
	check_btree_root(sb, map, &root->root, check_alloc_extent_item);
}

static void check_alloc_list_block_ref(struct super_block *sb, struct bit_map *map,
				       struct scoutfs_block_ref *caller_ref)
{
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block_ref ref;
	struct scoutfs_block *bl;
	u32 start;
	u32 nr;
	u32 i;

	ref = *caller_ref;

	while ((lblk = read_block_ref(sb, map, &ref, SCOUTFS_BLOCK_MAGIC_ALLOC_LIST, &bl))) {

		start = le32_to_cpu(lblk->start);
		nr = le32_to_cpu(lblk->nr);

		/* could sort and combine into extents */
		for (i = 0; i < nr; i++)
			check_blkno(sb, map, le64_to_cpu(lblk->blknos[start + i]));

		ref = lblk->next;
		scoutfs_block_put(sb, bl);
	}
}

static void check_alloc_list_head(struct super_block *sb, struct bit_map *map,
				  struct scoutfs_alloc_list_head *lhead)
{
	check_alloc_list_block_ref(sb, map, &lhead->ref);
}

static bool check_log_merge_item(struct super_block *sb, struct bit_map *map,
				 struct scoutfs_key *key, void *val, u16 val_len)
{
	struct scoutfs_log_merge_request *req;
	struct scoutfs_log_merge_complete *comp;
	struct scoutfs_log_merge_freeing *fr;

	switch(key->sk_zone) {
	case SCOUTFS_LOG_MERGE_REQUEST_ZONE:
		req = val;
		check_alloc_list_head(sb, map, &req->meta_avail);
		check_alloc_list_head(sb, map, &req->meta_freed);
		/* logs_root and root are shared refs */
		break;

	case SCOUTFS_LOG_MERGE_COMPLETE_ZONE:
		comp = val;
		check_alloc_list_head(sb, map, &comp->meta_avail);
		check_alloc_list_head(sb, map, &comp->meta_freed);
		/* XXX merged subtree?   hmm. */
		break;

	case SCOUTFS_LOG_MERGE_FREEING_ZONE:
		fr = val;
		check_btree_root(sb, map, &fr->root, NULL);
		break;
	}

	return true;
}

static void check_srch_file_block_ref(struct super_block *sb, struct bit_map *map,
				      u8 level, struct scoutfs_block_ref *ref)
{
	struct scoutfs_block *bl = NULL;
	struct scoutfs_srch_parent *srp;
	int i;

	if (level == 0) {
		check_block_ref(sb, map, ref);
		return;
	}

	if (!(srp = read_block_ref(sb, map, ref, SCOUTFS_BLOCK_MAGIC_SRCH_PARENT, &bl)))
		return;

	for (i = 0; i < SCOUTFS_SRCH_PARENT_REFS; i++)
		check_srch_file_block_ref(sb, map, level - 1, &srp->refs[i]);

	scoutfs_block_put(sb, bl);
}

static void check_srch_file(struct super_block *sb, struct bit_map *map,
			    struct scoutfs_srch_file *sfl)
{
	if (sfl->height > 0)
		check_srch_file_block_ref(sb, map, sfl->height - 1, &sfl->ref);
}

static bool check_srch_item(struct super_block *sb, struct bit_map *map,
			    struct scoutfs_key *key, void *val, u16 val_len)
{
	struct scoutfs_srch_file *sfl;
	struct scoutfs_srch_compact *sc;

	switch(key->sk_type) {
	case SCOUTFS_SRCH_BLOCKS_TYPE:
	case SCOUTFS_SRCH_LOG_TYPE:
		sfl = val;
		check_srch_file(sb, map, sfl);
		break;
	case SCOUTFS_SRCH_PENDING_TYPE:
	case SCOUTFS_SRCH_BUSY_TYPE:
		sc = val;
		check_alloc_list_head(sb, map, &sc->meta_avail);
		check_alloc_list_head(sb, map, &sc->meta_freed);
		check_srch_file(sb, map, &sc->out);
		break;
	}

	return true;
}

static bool check_log_trees_item(struct super_block *sb, struct bit_map *map,
				 struct scoutfs_key *key, void *val, u16 val_len)
{
	struct scoutfs_log_trees *lt = val;

	check_alloc_list_head(sb, map, &lt->meta_avail);
	check_alloc_list_head(sb, map, &lt->meta_freed);
	check_btree_root(sb, map, &lt->item_root, NULL);
	check_block_ref(sb, map, &lt->bloom_ref);
	check_btree_root(sb, map, &lt->data_avail.root, NULL);
	check_btree_root(sb, map, &lt->data_freed.root, NULL);
	check_srch_file(sb, map, &lt->srch_file);

	return true;
}

static void check_super(struct super_block *sb, struct bit_map *map,
			struct scoutfs_super_block *super)
{
	check_alloc_root(sb, map, &super->meta_alloc[0]);
	check_alloc_root(sb, map, &super->meta_alloc[1]);
	check_btree_root(sb, map, &super->data_alloc.root, NULL);
	check_alloc_list_head(sb, map, &super->server_meta_avail[0]);
	check_alloc_list_head(sb, map, &super->server_meta_avail[1]);
	check_alloc_list_head(sb, map, &super->server_meta_freed[0]);
	check_alloc_list_head(sb, map, &super->server_meta_freed[1]);
	check_btree_root(sb, map, &super->fs_root, NULL);
	check_btree_root(sb, map, &super->logs_root, check_log_trees_item);
	check_btree_root(sb, map, &super->log_merge, check_log_merge_item);
	check_btree_root(sb, map, &super->mounted_clients, NULL);
	check_btree_root(sb, map, &super->srch_root, check_srch_item);
}

static void check_map(struct super_block *sb, struct bit_map *map)
{
	unsigned long nr = find_next_zero_bit(map->addr, map->size, 0);

	warn_once_disable(sb, nr < map->size,
			  "final map has missing bits, first %lu", nr);
}

/*
 * This is called while the persistent block structures are stable.
 * While we might have to drop stale cache as we read these blocks, we
 * should be able to walk stable block references from the super.
 */
void scoutfs_check_meta_refs(struct super_block *sb, struct scoutfs_super_block *super)
{
	static struct bit_map map = {NULL,};
	unsigned long bytes;
	u64 size;

	if (!enabled)
		return;

	size = le64_to_cpu(super->total_meta_blocks);

	if (warn_once_disable(sb, size <= SCOUTFS_META_DEV_START_BLKNO,
			       "total_meta %llu too small", size) ||
	    warn_once_disable(sb, size > LONG_MAX,
			       "total_meta %llu too large", size))
		return;

	bytes = DIV_ROUND_UP(size, 8);
	if (size != map.size) {
		if (map.addr) {
			vfree(map.addr);
			map.addr = NULL;
		}

		map.addr = vmalloc(bytes);
		if (warn_once_disable(sb, !map.addr, "couldn't alloc %lu byte vmalloc", bytes))
			return;

		map.size = size;
	}

	memset(map.addr, 0, bytes);
	/* initial large block numbers used by padding and 4k super and quorum blocks */
	bitmap_set(map.addr, 0, SCOUTFS_META_DEV_START_BLKNO);

	check_super(sb, &map, super);
	check_map(sb, &map);

	if (!enabled)
		panic("found inconsistent meta refs");
}
