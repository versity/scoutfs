#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <math.h>
#include <sys/uio.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "crc.h"
#include "rand.h"
#include "key.h"
#include "bitops.h"
#include "btree.h"
#include "leaf_item_hash.h"
#include "name_hash.h"
#include "mode_types.h"
#include "srch.h"
#include "bloom.h"

#include "parallel_restore.h"

#include "list.h"
#include "lk_rbtree_wrapper.h"

/*
 * XXX
 *  - interface versioning?
 *  - next seq and next ino are both max ino + 1
 *  - fix writer builder layout to match super, users except for build order
 *  - look into zeroing buffers consistently
 *  - init_alb looks weird?  naming consistency?
 *  - make sure inode_count makes sense (fs root, log deltas)
 *  - audit file types
 */

#define dprintf(fmt, args...)		\
do {					\
	if (0)				\
		printf(fmt, ##args);	\
} while (0)

struct btree_item {
	struct rb_node node;
	struct scoutfs_key key;
	unsigned int val_len;
	void *val;
};

struct srch_node {
	struct rb_node node;
	u64 hash;
	u64 ino;
	u64 id;
};

struct block_builder;
typedef bool (*bld_empty_t)(struct block_builder *bld);
typedef void (*bld_reset_t)(struct block_builder *bld);
typedef spr_err_t (*bld_build_t)(struct scoutfs_parallel_restore_writer *wri,
				 struct block_builder *bld, void *buf, u64 blkno);
typedef spr_err_t (*bld_post_t)(struct scoutfs_parallel_restore_writer *wri,
				struct block_builder *bld);

struct block_builder {
	struct list_head head;
	bld_empty_t empty;
	bld_reset_t reset;
	bld_build_t build;
	bld_post_t post;
};

struct btree_builder {
	struct block_builder bld;

	/* track all items */
	u64 total_items;
	/* track total length of extent items */
	u64 total_len;

	/* eventual root that references built blocks */
	struct scoutfs_btree_root btroot;

	/* blocks are built as levels accumulate sufficient items */
	struct {
		struct rb_root root;
		unsigned long nr;
	} items[SCOUTFS_BTREE_MAX_HEIGHT];
};

struct alloc_list_builder {
	struct block_builder bld;
	u64 start;
	u64 len;
	struct scoutfs_alloc_list_head lhead;
};

/*
 * srch parent radix fanout is really wide, it doesn't take many to have
 * 2^64 bytes in entry blocks.
 */
#define MAX_SRCH_HEIGHT 6

struct srch_builder {
	struct block_builder bld;

	/* accumulates blocks/entries as we build */
	struct scoutfs_srch_file sfl;

	/* no parents at level 0, [0] never used */
	u64 total_parent_refs;
	struct {
		struct scoutfs_block_ref *refs;
		unsigned long nr;
	} parents[MAX_SRCH_HEIGHT];

	struct rb_root entries;
};

struct bloom_builder {
	struct block_builder bld;
	struct scoutfs_bloom_block *bloom;
};

struct scoutfs_parallel_restore_writer {
	u64 inode_count;
	u64 max_ino;

	__le64 fsid;
	u64 meta_start;
	u64 meta_len;
	struct list_head meta_extents;

	struct list_head builders;
	struct btree_builder meta_btb[2];
	struct btree_builder data_btb;
	struct alloc_list_builder meta_alb[2];
	struct btree_builder root_btb;
	struct btree_builder fs_btb;
	struct btree_builder srch_btb;
	struct btree_builder log_btb;

	struct srch_builder srch_sbld;
	struct bloom_builder bloom_bbld;

	struct scoutfs_btree_root root_items;
	struct scoutfs_super_block super;
};

struct extent_head {
	struct list_head head;
	u64 start;
	u64 len;
};

static void init_builder(struct block_builder *bld, bld_empty_t empty, bld_reset_t reset,
			 bld_build_t build)
{
	INIT_LIST_HEAD(&bld->head);
	bld->empty = empty;
	bld->reset = reset;
	bld->build = build;
	bld->post = NULL;
}

static spr_err_t meta_alloc_add(struct scoutfs_parallel_restore_writer *wri,
				u64 start, u64 len)
{
	struct extent_head *eh;

	if (len == 0)
		return 0;

	if (wri->meta_len == 0) {
		wri->meta_start = start;
		wri->meta_len = len;
	} else {
		eh = malloc(sizeof(struct extent_head));
		if  (!eh)
			return ENOMEM;
		eh->start = start;
		eh->len = len;
		list_add_tail(&eh->head, &wri->meta_extents);
	}

	return 0;
}

static spr_err_t meta_alloc_contig(struct scoutfs_parallel_restore_writer *wri,
				   u64 prev, u64 *blkno_ret)
{
	struct extent_head *eh;

	if (prev && wri->meta_len && (wri->meta_start != prev + 1)) {
		*blkno_ret = 0;
		return 0;
	}

	if (!wri->meta_len) {
		*blkno_ret = 0;
		return ENOSPC;
	}

	*blkno_ret = wri->meta_start++;

	if (--wri->meta_len == 0 && !list_empty(&wri->meta_extents)) {
		eh = list_entry(wri->meta_extents.next, struct extent_head, head);
		wri->meta_start = eh->start;
		wri->meta_len = eh->len;
		free(eh);
	}

	return 0;
}

static spr_err_t bti_alloc(int val_len, struct btree_item **bti_ret)
{
	struct btree_item *bti;
	spr_err_t err;

	bti = malloc(sizeof(struct btree_item) + val_len);
	if (bti) {
		bti->val = (void *)(bti + 1);
		bti->val_len = val_len;
		err = 0;
	} else {
		err = ENOMEM;
	}

	*bti_ret = bti;
	return err;
}

static struct btree_item *bti_walk(struct rb_root *root, struct scoutfs_key *key,
				   struct btree_item *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct btree_item *found = NULL;
	struct btree_item *bti;
	int cmp;

	while (*node) {
		parent = *node;
		bti = container_of(*node, struct btree_item, node);

		cmp = scoutfs_key_compare(key, &bti->key);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			found = bti;
			break;
		}
	}

	if (ins && !found) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, root);
	}

	return found;
}

static struct btree_item *node_bti(struct rb_node *node)
{
	return node ? container_of(node, struct btree_item, node) : NULL;
}

static struct btree_item *bti_first(struct rb_root *root)
{
	return node_bti(rb_first(root));
}

static struct btree_item *bti_next(struct btree_item *bti)
{
	return bti ? node_bti(rb_next(&bti->node)) : NULL;
}

#define for_each_bti_safe(root, bti, tmp) \
	for (bti = bti_first(root); bti && ((tmp = bti_next(bti)), 1); bti = tmp)

/*
 * It's always an error to try and insert a key that was already tracked
 * in a btree level.
 */
static spr_err_t btb_insert(struct btree_builder *btb, struct btree_item *bti, int level)
{
	struct btree_item *found;

	found = bti_walk(&btb->items[level].root, &bti->key, bti);
	if (found) {
		return EEXIST;
	} else {
		btb->items[level].nr++;
		btb->total_items++;
		return 0;
	}
}

static void btb_erase(struct btree_builder *btb, struct btree_item *bti, int level)
{
	rb_erase(&bti->node, &btb->items[level].root);
	btb->items[level].nr--;
	btb->total_items--;
}

static void btb_destroy(struct btree_builder *btb)
{
	struct btree_item *bti;
	struct btree_item *tmp;
	int i;

	for (i = 0; i < array_size(btb->items); i++) {
		for_each_bti_safe(&btb->items[i].root, bti, tmp) {
			btb_erase(btb, bti, i);
			free(bti);
		}
	}
}

static void init_key(struct scoutfs_key *key, u8 zone, u8 type, u64 first, u64 second,
		     u64 third, u8 fourth)
{
	key->_sk_first = cpu_to_le64(first);
	key->_sk_second = cpu_to_le64(second);
	key->_sk_third = cpu_to_le64(third);
	key->_sk_fourth = fourth;
	key->sk_zone = zone;
	key->sk_type = type;
	memset(&key->__pad, 0, sizeof(key->__pad));
}

static u64 free_extent_order(u64 len)
{
	return (fls64(len | 1) - 1) / 3;
}

static int insert_free_items(struct btree_builder *btb, u64 start, u64 len)
{
	struct scoutfs_key keys[2];
	struct btree_item *bti;
	spr_err_t err;
	u64 order;
	u64 end;
	int i;

	end = start + len - 1;
	order = U64_MAX - free_extent_order(len);

	init_key(&keys[0], SCOUTFS_FREE_EXTENT_BLKNO_ZONE, 0, end, len, 0, 0);
	init_key(&keys[1], SCOUTFS_FREE_EXTENT_ORDER_ZONE, 0, order, end, len, 0);

	for (i = 0; i < array_size(keys); i++) {
		err = bti_alloc(0, &bti);
		if (err)
			goto out;

		bti->key = keys[i];

		err = btb_insert(btb, bti, 0);
		if (err) {
			free(bti);
			goto out;
		}
	}

	btb->total_len += len;

	err = 0;
out:
	return err;
}

static void set_alloc_root(struct scoutfs_alloc_root *root, struct btree_builder *btb)
{
	root->total_len = cpu_to_le64(btb->total_len);
	root->flags = 0;
	root->_pad = 0;
	root->root = btb->btroot;
}

static spr_err_t map_start_key(struct scoutfs_key *start, struct scoutfs_key *key)
{
	if (key->sk_zone == SCOUTFS_FS_ZONE) {
		init_key(start, SCOUTFS_FS_ZONE, 0,
			 le64_to_cpu(key->_sk_first) & ~(u64)SCOUTFS_LOCK_INODE_GROUP_MASK,
			 0, 0, 0);

	} else if (key->sk_zone == SCOUTFS_XATTR_TOTL_ZONE) {
		init_key(start, SCOUTFS_XATTR_TOTL_ZONE, 0, 0, 0, 0, 0);

	} else if (key->sk_zone == SCOUTFS_INODE_INDEX_ZONE) {
		init_key(start, SCOUTFS_INODE_INDEX_ZONE, 0, 0,
			 le64_to_cpu(key->_sk_second) & ~(u64)SCOUTFS_LOCK_SEQ_GROUP_MASK,
			 0, 0);

	} else {
		return EINVAL;
	}

	return 0;
}

static spr_err_t update_bloom(struct bloom_builder *bbld, struct scoutfs_key *key)
{
	struct scoutfs_bloom_block *bb = bbld->bloom;
	unsigned int nrs[SCOUTFS_FOREST_BLOOM_NRS];
	struct scoutfs_key start;
	spr_err_t err;
	int i;

	err = map_start_key(&start, key);
	if (err)
		goto out;

	calc_bloom_nrs(&start, nrs);

	for (i = 0; i < SCOUTFS_FOREST_BLOOM_NRS; i++) {
		if (!test_and_set_bit_le(nrs[i], bb->bits))
			le64_add_cpu(&bb->total_set, 1);
	}

	err = 0;
out:
	return err;
}

static spr_err_t insert_fs_item(struct scoutfs_parallel_restore_writer *wri,
				struct btree_item *bti)
{
	spr_err_t err;

	if (bti->key.sk_zone == SCOUTFS_FS_ZONE && bti->key.sk_type == SCOUTFS_INODE_TYPE &&
	    le64_to_cpu(bti->key.ski_ino) == SCOUTFS_ROOT_INO) {
		err = btb_insert(&wri->root_btb, bti, 0);
	} else {
		err = btb_insert(&wri->fs_btb, bti, 0) ?:
		      update_bloom(&wri->bloom_bbld, &bti->key);
	}

	return err;
}

static spr_err_t insert_entry_items(struct scoutfs_parallel_restore_writer *wri,
				    struct scoutfs_parallel_restore_entry *entry)
{
	struct scoutfs_dirent *dent = NULL;
	struct scoutfs_key keys[3];
	struct btree_item *bti;
	unsigned int bytes;
	spr_err_t err = 0;
	u64 dir_ino;
	u64 hash;
	u64 ino;
	u64 pos;
	int i;

	bytes = offsetof(struct scoutfs_dirent, name[entry->name_len]);
	dent = malloc(bytes);
	if (!dent) {
		err = ENOMEM;
		goto out;
	}

	dir_ino = entry->dir_ino;
	ino = entry->ino;
	hash = dirent_name_hash(entry->name, entry->name_len);
	pos = entry->pos;

	dent->ino = cpu_to_le64(ino);
	dent->hash = cpu_to_le64(hash);
	dent->pos = cpu_to_le64(pos);
	dent->type = mode_to_type(entry->mode);
	memset(&dent->__pad, 0, sizeof(dent->__pad));
	memcpy(dent->name, entry->name, entry->name_len);

	init_key(&keys[0], SCOUTFS_FS_ZONE, SCOUTFS_DIRENT_TYPE, dir_ino, hash, pos, 0);
	init_key(&keys[1], SCOUTFS_FS_ZONE, SCOUTFS_READDIR_TYPE, dir_ino, pos, 0, 0);
	init_key(&keys[2], SCOUTFS_FS_ZONE, SCOUTFS_LINK_BACKREF_TYPE, ino, dir_ino, pos, 0);

	for (i = 0; i < array_size(keys); i++) {
		err = bti_alloc(bytes, &bti);
		if (err)
			goto out;

		bti->key = keys[i];
		memcpy(bti->val, dent, bytes);

		err = insert_fs_item(wri, bti);
		if (err) {
			free(bti);
			goto out;
		}
	}

	err = 0;
out:
	free(dent);
	return err;
}

static spr_err_t insert_extent_item(struct scoutfs_parallel_restore_writer *wri, u64 ino, u64 len)
{
	struct scoutfs_data_extent_val *dv;
	struct scoutfs_key key;
	struct btree_item *bti;
	spr_err_t err;

	init_key(&key, SCOUTFS_FS_ZONE, SCOUTFS_DATA_EXTENT_TYPE, ino, 0 + len - 1, len, 0);

	err = bti_alloc(sizeof(struct scoutfs_data_extent_val), &bti);
	if (!err) {
		bti->key = key;
		dv = bti->val;
		dv->blkno = 0;
		dv->flags = SEF_OFFLINE;

		err = insert_fs_item(wri, bti);
		if (err)
			free(bti);
	}

	return err;
}

/*
 * We're trusting that the caller hasn't made up garbage xattrs.
 * All we have to do is check for the scoutfs prefix and then
 * identify the sequence of known tags.  There can be a lot more
 * xattrs than files so this is a surprisingly hot path.
 */
#define HIDE_BE32 cpu_to_be32(0x68696465)
#define SRCH_BE32 cpu_to_be32(0x73726368)
#define TOTL_BE32 cpu_to_be32(0x746f746c)
#define TAG_LEN 5
#define XTAG_SRCH (1 << 1)
#define XTAG_TOTL (1 << 2)
static int get_xattr_tags(char *name, int name_len)
{
	static const char prefix[] = "scoutfs.";
	static const size_t prefix_len = array_size(prefix) - 1;
	__be32 betag;
	int xtags = 0;

	if (name_len < prefix_len || strncmp(name, prefix, prefix_len))
		return 0;

	name += prefix_len;
	name_len -= prefix_len;

	while (name_len >= TAG_LEN && name[TAG_LEN - 1] == '.') {
		memcpy(&betag, name, sizeof(betag));

		dprintf("tag 0x%08x\n", be32_to_cpu(betag));

		if (betag == HIDE_BE32)
			;
		else if (betag == SRCH_BE32)
			xtags |= XTAG_SRCH;
		else if (betag == TOTL_BE32)
			xtags |= XTAG_TOTL;
		else
			break;

		name += TAG_LEN;
		name_len -= TAG_LEN;
	}

	dprintf("xat name %.*s tags 0x%x\n", name_len, name, xtags);

	return xtags;
}

static spr_err_t insert_xattr_items(struct scoutfs_parallel_restore_writer *wri,
				    struct scoutfs_parallel_restore_xattr *xattr, u32 hash)
{
	struct scoutfs_xattr xat;
	struct iovec value[3] = {
		{ &xat, sizeof(xat) },
		{ xattr->name, xattr->name_len, },
		{ xattr->value, xattr->value_len, },
	};
	struct iovec *iov = value;
	struct scoutfs_key key;
	struct btree_item *bti;
	unsigned int total;
	unsigned int bytes;
	unsigned int piece;
	spr_err_t err;
	char *buf;

	init_key(&key, SCOUTFS_FS_ZONE, SCOUTFS_XATTR_TYPE, xattr->ino, hash, xattr->pos, 0);
	total = value[0].iov_len + value[1].iov_len + value[2].iov_len;

	xat.val_len = cpu_to_le16(xattr->value_len);
	xat.name_len = xattr->name_len;
	memset(xat.__pad, 0, sizeof(xat.__pad));

	while (total > 0) {
		bytes = min(total, SCOUTFS_XATTR_MAX_PART_SIZE);

		err = bti_alloc(bytes, &bti);
		if (err)
			goto out;

		bti->key = key;
		buf = bti->val;

		while (bytes) {
			piece = min(bytes, iov->iov_len);
			memcpy(buf, iov->iov_base, piece);
			buf += piece;
			bytes -= piece;
			total -= piece;
			iov->iov_base += piece;
			iov->iov_len -= piece;
			if (iov->iov_len == 0)
				iov++; /* falls off array when done */
		}

		err = insert_fs_item(wri, bti);
		if (err) {
			free(bti);
			goto out;
		}

		key._sk_fourth++;
	}

	err = 0;
out:
	return err;
}

static spr_err_t insert_symlink_items(struct scoutfs_parallel_restore_writer *wri,
				      u64 ino, char *target, int target_len)
{
	struct scoutfs_key key;
	struct btree_item *bti;
	spr_err_t err;
	int bytes;
	int off = 0;

	init_key(&key, SCOUTFS_FS_ZONE, SCOUTFS_SYMLINK_TYPE, ino, 0, 0, 0);

	while (off < target_len) {
		bytes = min(target_len - off, SCOUTFS_MAX_VAL_SIZE);

		err = bti_alloc(bytes, &bti);
		if (err)
			goto out;

		bti->key = key;
		memcpy(bti->val, target + off, bytes);

		err = insert_fs_item(wri, bti);
		if (err) {
			free(bti);
			goto out;
		}

		off += bytes;
		le64_add_cpu(&key._sk_second, 1);
	}

	err = 0;
out:
	return err;
}

/* forbid the leading + that strtoull allows */
static spr_err_t totl_strtoull(char *s, int len, unsigned long long *res)
{
	char str[SCOUTFS_XATTR_MAX_TOTL_U64 + 1];

	if (len <= 0 || len >= array_size(str) || s[0] == '+')
		return EINVAL;

	memcpy(str, s, len);
	str[len] = '\0';

	errno = 0;
	*res = strtoull(str, NULL, 0);
	return errno;
}

/*
 * .totl. xattrs turn into items with the key based on dotted u64s at the end of the
 * name and a value in the .. value.
 */
static spr_err_t insert_totl_item(struct scoutfs_parallel_restore_writer *wri,
				  struct scoutfs_parallel_restore_xattr *xattr)
{
	static const char prefix[] = "scoutfs.totl.";
	static const int prefix_len = sizeof(prefix) - 1;
	struct scoutfs_xattr_totl_val *found_tval;
	struct scoutfs_xattr_totl_val *tval;
	struct btree_item *found;
	struct btree_item *bti;
	unsigned long long longs[3];
	unsigned long long v;
	spr_err_t err;
	int nr = 0;
	int prev;
	int i;

	prev = xattr->name_len;
	for (i = xattr->name_len - 1; i > prefix_len; i--) {
		if (xattr->name[i] == '.') {
			err = totl_strtoull(&xattr->name[i + 1], prev - (i + 1), &longs[nr]);
			if (err)
				goto out;
			if (++nr == array_size(longs))
				break;
			prev = i;
		}
	}
	if (nr != array_size(longs)) {
		err = EINVAL;
		goto out;
	}

	err = totl_strtoull(xattr->value, xattr->value_len, &v);
	if (err)
		goto out;

	if (v == 0) {
		err = 0;
		goto out;
	}

	err = bti_alloc(sizeof(struct scoutfs_xattr_totl_val), &bti);
	if (err)
		goto out;

	init_key(&bti->key, SCOUTFS_XATTR_TOTL_ZONE, 0, longs[2], longs[1], longs[0], 0);
	tval = bti->val;
	tval->total = cpu_to_le64(v);
	tval->count = cpu_to_le64(1);

	found = bti_walk(&wri->fs_btb.items[0].root, &bti->key, NULL);
	if (found) {
		found_tval = found->val;
		le64_add_cpu(&found_tval->total, le64_to_cpu(tval->total));
		le64_add_cpu(&found_tval->count, le64_to_cpu(tval->count));
		if (found_tval->total == 0)
			btb_erase(&wri->fs_btb, found, 0);
		free(bti);
	} else {
		err = insert_fs_item(wri, bti);
		if (err) {
			free(bti);
			goto out;
		}
	}

	err = 0;
out:
	return err;
}

static spr_err_t insert_inode_index_item(struct scoutfs_parallel_restore_writer *wri,
					 u8 type, u64 major, u64 ino)
{
	struct btree_item *bti;
	spr_err_t err;

	err = bti_alloc(0, &bti);
	if (!err) {
		init_key(&bti->key, SCOUTFS_INODE_INDEX_ZONE, type, 0, major, ino, 0);
		err = insert_fs_item(wri, bti);
		if (err)
			free(bti);
	}

	return err;
}

static spr_err_t insert_inode_items(struct scoutfs_parallel_restore_writer *wri,
				    struct scoutfs_parallel_restore_inode *inode)
{
	struct scoutfs_inode *si;
	struct btree_item *bti;
	spr_err_t err;

	err = bti_alloc(sizeof(struct scoutfs_inode), &bti);
	if (err)
		goto out;

	init_key(&bti->key, SCOUTFS_FS_ZONE, SCOUTFS_INODE_TYPE, inode->ino, 0, 0, 0);

	si = bti->val;

	si->size = 0;
	si->meta_seq = cpu_to_le64(inode->meta_seq);
	si->data_seq = cpu_to_le64(inode->data_seq);
	si->data_version = 0;
	si->online_blocks = 0;
	si->offline_blocks = 0;
	si->next_readdir_pos = 0;
	si->next_xattr_id = cpu_to_le64(inode->nr_xattrs + 1);
	si->version = cpu_to_le64(1);
	si->nlink = cpu_to_le32(1);
	si->uid = cpu_to_le32(inode->uid);
	si->gid = cpu_to_le32(inode->gid);
	si->mode = cpu_to_le32(inode->mode);
	si->rdev = cpu_to_le32(inode->rdev);
	si->flags = 0;
	si->flags = cpu_to_le32(inode->flags);
	si->atime.sec = cpu_to_le64(inode->atime.tv_sec);
	si->atime.nsec = cpu_to_le32(inode->atime.tv_nsec);
	si->ctime.sec = cpu_to_le64(inode->ctime.tv_sec);
	si->ctime.nsec = cpu_to_le32(inode->ctime.tv_nsec);
	si->mtime.sec = cpu_to_le64(inode->mtime.tv_sec);
	si->mtime.nsec = cpu_to_le32(inode->mtime.tv_nsec);
	si->crtime.sec = cpu_to_le64(inode->crtime.tv_sec);
	si->crtime.nsec = cpu_to_le32(inode->crtime.tv_nsec);
	si->proj = cpu_to_le64(inode->proj);

	err = insert_inode_index_item(wri, SCOUTFS_INODE_INDEX_META_SEQ_TYPE,
				      le64_to_cpu(si->meta_seq), inode->ino);
	if (err)
		goto out;

	if (S_ISREG(inode->mode)) {
		si->size = cpu_to_le64(inode->size);
		si->data_version = cpu_to_le64(inode->data_version);

		err = insert_inode_index_item(wri, SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE,
					      le64_to_cpu(si->data_seq), inode->ino);
		if (err)
			goto out;

		if (inode->offline) {
			si->offline_blocks = cpu_to_le64(DIV_ROUND_UP(inode->size,
								      SCOUTFS_BLOCK_SM_SIZE));
			err = insert_extent_item(wri, inode->ino, le64_to_cpu(si->offline_blocks));
			if (err)
				goto out;
		}

	} else if (S_ISDIR(inode->mode)) {
		si->size = cpu_to_le64(inode->total_entry_name_bytes);
		si->next_readdir_pos = cpu_to_le64(SCOUTFS_DIRENT_FIRST_POS + inode->nr_subdirs);
		si->nlink = cpu_to_le32(2 + inode->nr_subdirs);

	} else if (S_ISLNK(inode->mode)) {
		si->size = cpu_to_le64(inode->target_len);

		err = insert_symlink_items(wri, inode->ino, inode->target, inode->target_len);
		if (err)
			goto out;
	}

	err = insert_fs_item(wri, bti);
out:
	return err;
}

static spr_err_t insert_log_trees_item(struct scoutfs_parallel_restore_writer *wri,
				       struct scoutfs_parallel_restore_progress *prog)
{
	struct scoutfs_log_trees *lt;
	struct btree_item *bti;
	spr_err_t err;

	err = bti_alloc(sizeof(struct scoutfs_log_trees), &bti);
	if (err)
		goto out;

	lt = bti->val;
	memset(lt, 0, sizeof(struct scoutfs_log_trees));
	lt->item_root = prog->fs_items;
	lt->bloom_ref = prog->bloom_ref;
	/* lt srch_file is blank once finalized, moved to srch_root items */
	lt->inode_count_delta = prog->inode_count;
	lt->get_trans_seq = cpu_to_le64(1);
	lt->commit_trans_seq = cpu_to_le64(1);
	lt->max_item_seq = cpu_to_le64(1);
	lt->finalize_seq = cpu_to_le64(1);
	lt->rid = prog->max_ino;
	lt->nr = cpu_to_le64(1);
	lt->flags = cpu_to_le64(SCOUTFS_LOG_TREES_FINALIZED);

	init_key(&bti->key, SCOUTFS_LOG_TREES_ZONE, 0,
		 le64_to_cpu(lt->rid), le64_to_cpu(lt->nr), 0, 0);

	err = btb_insert(&wri->log_btb, bti, 0);
out:
	return err;
}

static spr_err_t insert_srch_item(struct scoutfs_parallel_restore_writer *wri,
				  struct scoutfs_srch_file *sfl)
{
	struct btree_item *bti;
	spr_err_t err;

	err = bti_alloc(sizeof(struct scoutfs_srch_file), &bti);
	if (!err) {
		init_key(&bti->key, SCOUTFS_SRCH_ZONE, SCOUTFS_SRCH_BLOCKS_TYPE,
			 0, le64_to_cpu(sfl->blocks), le64_to_cpu(sfl->ref.blkno), 0);
		memcpy(bti->val, sfl, sizeof(struct scoutfs_srch_file));
		err = btb_insert(&wri->srch_btb, bti, 0);
	}

	return err;
}

#define UNLINKED_AVL_HEIGHT 255

static void link_avl_nodes(struct scoutfs_btree_block *bt, __le16 *parent, __le16 parent_off,
			   u8 height, int first, int last)
{
	int ind = (first + last) / 2;
	struct scoutfs_avl_node *node = &bt->items[ind].node;
	u64 off = (long)node - (long)&bt->item_root;

	dprintf("first %d ind %d last %d height %u\n", first, ind, last, height);

	if (ind < first || ind > last || node->height != UNLINKED_AVL_HEIGHT)
		return;

	*parent = cpu_to_le16(off);
	node->parent = parent_off;
	node->height = height;
	node->left = 0;
	node->right = 0;
	memset(node->__pad, 0, sizeof(node->__pad));

	if (height > 1) {
		link_avl_nodes(bt, &node->left, cpu_to_le16(off), height - 1, first, ind - 1);
		link_avl_nodes(bt, &node->right, cpu_to_le16(off), height - 1, ind + 1, last);
	}
}

#define DEFINE_BUILDER_CONTAINER(type, name, ptr) \
	type *name = container_of(ptr, type, bld)

static bool btree_empty(struct block_builder *bld)
{
	DEFINE_BUILDER_CONTAINER(struct btree_builder, btb, bld);

	return btb->total_items == 0;
}

static void btree_reset(struct block_builder *bld)
{
	DEFINE_BUILDER_CONTAINER(struct btree_builder, btb, bld);

	btb->total_items = 0;
	btb->total_len = 0;
	memset(&btb->btroot, 0, sizeof(btb->btroot));
}

/*
 * Incrementally build btrees.  By the time we're called the builder has
 * all the sorted leaf items in an rbtree at their level.  We streaem
 * them into blocks and store parent items at the next highest level.
 * Once we're out of leaf items we stream the parent items into blocks
 * and store their parent items at the next highest level.  Eventually
 * we drain all the items and are left with the root's reference to the
 * first block in the tree.
 */
static spr_err_t build_btree_block(struct scoutfs_parallel_restore_writer *wri,
				   struct block_builder *bld, void *buf, u64 blkno)
{
	DEFINE_BUILDER_CONTAINER(struct btree_builder, btb, bld);
	struct scoutfs_block_header *hdr;
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block_ref *ref;
	struct btree_item *bti;
	struct btree_item *tmp;
	unsigned long val_align;
	unsigned long bytes;
	unsigned long nr;
	void *val_buf;
	spr_err_t err;
	u8 height;
	int level;
	int i;

	/* find next highest level to build items from */
	for (i = 0; i < SCOUTFS_BTREE_MAX_HEIGHT; i++) {
		if (btb->items[i].nr == 0)
			continue;

		level = i;
		break;
	}

	/* shouldn't be possible */
	if (i >= SCOUTFS_BTREE_MAX_HEIGHT) {
		err = ENOBUFS;
		goto out;
	}

	dprintf("building btree blkno %llu level %u nr %lu tot %llu \n",
		blkno, level, btb->items[level].nr, btb->total_items);

	/*
	 * XXX Be more careful about item filling.. can parents be entirely
	 * full?  Should we let the last nodes on the right be under the
	 * min?  We can see that there are < (nr + min) left and emit
	 * half the remaining in each.
	 */

	/* initialize the non-item parts of the block */
	bt = buf;
	memset(bt, 0, sizeof(struct scoutfs_btree_block));
	hdr = &bt->hdr;
	hdr->magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BTREE);
	hdr->fsid = wri->fsid;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = cpu_to_le64(1);
	bt->level = level;
	btree_init_block(bt, level);
	if (level == 0)
		memset((char *)bt + SCOUTFS_BLOCK_LG_SIZE - SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES, 0,
		       SCOUTFS_BTREE_LEAF_ITEM_HASH_BYTES);

	/* find the items that fit in the leaf */
	item = &bt->items[0];
	nr = 0;
	val_buf = (void *)item + le16_to_cpu(bt->mid_free_len);

	for_each_bti_safe(&btb->items[level].root, bti, tmp) {
		val_align = round_up(bti->val_len, SCOUTFS_BTREE_VALUE_ALIGN);
		bytes = sizeof(struct scoutfs_btree_item) + val_align;

		if (le16_to_cpu(bt->mid_free_len) < bytes)
			break;

		item->node.height = UNLINKED_AVL_HEIGHT;
		item->key = bti->key;
		item->seq = cpu_to_le64(1);
		item->val_len = cpu_to_le16(bti->val_len);
		item->flags = 0;
		memset(item->node.__pad, 0, sizeof(item->node.__pad));

		if (bti->val_len) {
			val_buf -= val_align;
			item->val_off = cpu_to_le16((long)val_buf - (long)bt);
			memcpy(val_buf, bti->val, bti->val_len);
		} else {
			item->val_off = 0;
		}

		le16_add_cpu(&bt->nr_items, 1);
		le16_add_cpu(&bt->total_item_bytes, bytes);
		le16_add_cpu(&bt->mid_free_len, -bytes);
		if (level == 0)
			leaf_item_hash_insert(bt, &item->key,
					      cpu_to_le16((void *)item - (void *)bt));

		item++;
		nr++;

		btb_erase(btb, bti, level);
		free(bti);
	}

	/* zero the middle of the block without items */
	if (bt->mid_free_len)
		memset(&bt->items[nr], 0, le16_to_cpu(bt->mid_free_len));

	height = (int)ceil(log2(nr)) + 2; /* leaves are height 1 */
	link_avl_nodes(bt, &bt->item_root.node, 0, height - 1, 0, nr - 1);

	/* finish block */
	hdr->crc = cpu_to_le32(crc_block(hdr, SCOUTFS_BLOCK_LG_SIZE));

	if (btb->total_items == 0) {
		/* root refs hightest/last block we build */
		btb->btroot.ref.blkno = hdr->blkno;
		btb->btroot.ref.seq = hdr->seq;
		btb->btroot.height = level +1;
	} else {
		/* parent ref items will be built into parent blocks */
		/* we'll always need a parent ref for the block we're building */
		err = bti_alloc(sizeof(struct scoutfs_block_ref), &bti);
		if (err)
			goto out;

		/* refs to right spine blocks has all ones key */
		if (btb->items[level].nr == 0)
			scoutfs_key_set_ones(&bti->key);
		else
			bti->key = bt->items[nr - 1].key;
		ref = bti->val;
		ref->blkno = hdr->blkno;
		ref->seq = hdr->seq;
		btb_insert(btb, bti, level + 1);
	}

	err = 0;
out:
	return err;
}

static void btb_init(struct btree_builder *btb)
{
	int i;

	init_builder(&btb->bld, btree_empty, btree_reset, build_btree_block);

	for (i = 0; i < array_size(btb->items); i++)
		btb->items[i].root = RB_ROOT;
}

/*
 * This is how we get around the recursion of allocating blocks to write blocks that
 * store the allocators.  After we've written all other metadata blocks we know precisely
 * how many allocation blocks we'll need.  We modify the writer to only have that many
 * free blocks remaining and put the rest in the alloc block builders.
 */
static spr_err_t prepare_alloc_builders(struct scoutfs_parallel_restore_writer *wri,
					struct block_builder *bld)
{
#define ALLOC_BLOCKS 5 /* 2 meta list, 2 meta btree, 1 data btree */
	struct extent_head *eh_tmp;
	struct extent_head *eh;
	spr_err_t err;
	u64 start;
	u64 skip;
	u64 len;
	int ind;

	dprintf("starting prepare with start %llu len %llu\n", wri->meta_start, wri->meta_len);

	skip = ALLOC_BLOCKS + (SCOUTFS_ALLOC_LIST_MAX_BLOCKS * 2);
	if (wri->meta_len <= skip)
		return ENOSPC;

	/* store remainder of meta alloc as a free extent */
	start = wri->meta_start + skip;
	len = wri->meta_len - skip;
	err = insert_free_items(&wri->meta_btb[0], start, len);
	if (err)
		goto out;
	wri->meta_len -= len;

	/* the rest of the meta extents are items in the two meta trees */
	ind = 1;
	list_for_each_entry_safe(eh, eh_tmp, &wri->meta_extents, head) {
		err = insert_free_items(&wri->meta_btb[ind], eh->start, eh->len);
		if (err)
			goto out;
		list_del_init(&eh->head);
		free(eh);
		ind ^= 1;
	}

	/* fill the two server avail alloc list blocks */
	wri->meta_alb[0].start = wri->meta_start + ALLOC_BLOCKS;
	wri->meta_alb[0].len = SCOUTFS_ALLOC_LIST_MAX_BLOCKS;
	wri->meta_alb[1].start = wri->meta_alb[0].start + wri->meta_alb[0].len;
	wri->meta_alb[1].len = wri->meta_alb[0].len;

	/* writer left with only meta allocation for remaining alloc blocks */
	wri->meta_len = ALLOC_BLOCKS;

	err = 0;
out:
	return err;
}

static bool alloc_list_empty(struct block_builder *bld)
{
	DEFINE_BUILDER_CONTAINER(struct alloc_list_builder, alb, bld);

	return alb->len == 0;
}

static spr_err_t build_alloc_list_block(struct scoutfs_parallel_restore_writer *wri,
					struct block_builder *bld, void *buf, u64 blkno)
{
	DEFINE_BUILDER_CONTAINER(struct alloc_list_builder, alb, bld);
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block_header *hdr;
	int i;

	if (alb->len > SCOUTFS_ALLOC_LIST_MAX_BLOCKS)
		return EOVERFLOW;

	lblk = buf;
	memset(&lblk->next, 0, sizeof(lblk->next));
	lblk->start = 0;
	lblk->nr = cpu_to_le32(alb->len);

	for (i = 0; i < alb->len; i++)
		lblk->blknos[i] = cpu_to_le64(alb->start + i);

	hdr = &lblk->hdr;
	hdr->magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_ALLOC_LIST);
	hdr->fsid = wri->fsid;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = cpu_to_le64(1);
	hdr->crc = cpu_to_le32(crc_block(hdr, SCOUTFS_BLOCK_LG_SIZE));

	alb->lhead.ref.blkno = hdr->blkno;
	alb->lhead.ref.seq = hdr->seq;
	alb->lhead.first_nr = cpu_to_le32(alb->len);
	alb->lhead.total_nr = cpu_to_le64(alb->len);

	alb->start = 0;
	alb->len = 0;

	return 0;
}

static void init_alb(struct alloc_list_builder *alb)
{
	init_builder(&alb->bld, alloc_list_empty, NULL, build_alloc_list_block);
}

static struct srch_node *node_srn(struct rb_node *node)
{
	return node ? container_of(node, struct srch_node, node) : NULL;
}

static struct srch_node *srn_first(struct rb_root *root)
{
	return node_srn(rb_first(root));
}

static struct srch_node *srn_next(struct srch_node *srn)
{
	return srn ? node_srn(rb_next(&srn->node)) : NULL;
}

static spr_err_t insert_srch_entry(struct srch_builder *sbld, u64 hash, u64 ino, u64 id)
{
	struct rb_root *root = &sbld->entries;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct srch_node *ins;
	struct srch_node *srn;
	int cmp;

	ins = malloc(sizeof(struct srch_node));
	if (!ins)
		return ENOMEM;

	ins->hash = hash;
	ins->ino = ino;
	ins->id = id;

	while (*node) {
		parent = *node;
		srn = node_srn(*node);

		cmp = scoutfs_cmp(ins->hash, srn->hash) ?:
		      scoutfs_cmp(ins->ino, srn->ino) ?:
		      scoutfs_cmp(ins->id, srn->id);
		if (cmp < 0)
			node = &(*node)->rb_left;
		else if (cmp > 0)
			node = &(*node)->rb_right;
		else
			return EEXIST;
	}

	rb_link_node(&ins->node, parent, node);
	rb_insert_color(&ins->node, root);

	return 0;
}

static bool srch_empty(struct block_builder *bld)
{
	DEFINE_BUILDER_CONTAINER(struct srch_builder, sbld, bld);

	return RB_EMPTY_ROOT(&sbld->entries) && sbld->total_parent_refs == 0;
}

static void srch_reset(struct block_builder *bld)
{
	DEFINE_BUILDER_CONTAINER(struct srch_builder, sbld, bld);

	memset(&sbld->sfl, 0, sizeof(sbld->sfl));
}

#define for_each_sbld_parent(sbld, i) \
	for (i = 1; i < array_size(sbld->parents); i++)

static spr_err_t build_srch_block(struct scoutfs_parallel_restore_writer *wri,
				   struct block_builder *bld, void *buf, u64 blkno)
{
	DEFINE_BUILDER_CONTAINER(struct srch_builder, sbld, bld);
	struct scoutfs_block_header *hdr;
	struct scoutfs_srch_parent *par;
	struct scoutfs_srch_block *srb;
	struct scoutfs_srch_entry sre;
	struct scoutfs_block_ref *ref;
	struct srch_node *srn_tmp;
	struct srch_node *srn;
	unsigned int nr;
	spr_err_t err;
	u32 magic;
	int level;
	int tail;
	int ret;

	dprintf("building srch blkno %llu empty_entries %u tot refs %llu parent nrs: ",
		blkno, RB_EMPTY_ROOT(&sbld->entries), sbld->total_parent_refs);
	for_each_sbld_parent(sbld, level)
		dprintf("%u:%lu ", level, sbld->parents[level].nr);
	dprintf("\n");

	/* build parents with refs that are full or when we're out of entries */
	for_each_sbld_parent(sbld, level) {

		nr = sbld->parents[level].nr;
		if (nr == 0 || (nr < SCOUTFS_SRCH_PARENT_REFS && !RB_EMPTY_ROOT(&sbld->entries)))
			continue;

		/* copy parent refs */
		par = buf;
		memcpy(par->refs, sbld->parents[level].refs, nr * sizeof(par->refs[0]));
		sbld->total_parent_refs -= nr;
		sbld->parents[level].nr = 0;

		/* zero the tail of the block */
		tail = SCOUTFS_BLOCK_LG_SIZE - offsetof(struct scoutfs_srch_parent, refs[nr]);
		if (tail > 0)
			memset(buf + SCOUTFS_BLOCK_LG_SIZE - tail, 0, tail);

		magic = SCOUTFS_BLOCK_MAGIC_SRCH_PARENT;
		hdr = &par->hdr;
		goto finish_hdr;
	}

	/* no built parent, must have entries to build */
	level = 0;
	if (RB_EMPTY_ROOT(&sbld->entries)) {
		err = EINVAL;
		goto out;
	}

	srn = srn_first(&sbld->entries);
	sre.hash = cpu_to_le64(srn->hash);
	sre.ino = cpu_to_le64(srn->ino);
	sre.id = cpu_to_le64(srn->id);

	srb = buf;
	srb->entry_nr = 0;
	srb->entry_bytes = 0;
	srb->first = sre;
	memset(&srb->tail, 0, sizeof(srb->tail));

	if (sbld->sfl.blocks == 0)
		sbld->sfl.first = sre;

	do {
		if (le32_to_cpu(srb->entry_bytes) > SCOUTFS_SRCH_BLOCK_SAFE_BYTES)
			break;

		ret = srch_encode_entry(srb->entries + le32_to_cpu(srb->entry_bytes),
					&sre, &srb->tail);

		dprintf("%llu.%llu.%llu ret %d\n", srn->hash, srn->ino, srn->id, ret);

		le32_add_cpu(&srb->entry_bytes, ret);
		le32_add_cpu(&srb->entry_nr, 1);
		srb->tail = sre;

		srn_tmp = srn_next(srn);
		rb_erase(&srn->node, &sbld->entries);
		free(srn);

		if ((srn = srn_tmp)) {
			sre.hash = cpu_to_le64(srn->hash);
			sre.ino = cpu_to_le64(srn->ino);
			sre.id = cpu_to_le64(srn->id);
		}
	} while (srn);

	srb->last = srb->tail;
	sbld->sfl.last = srb->tail;

	le64_add_cpu(&sbld->sfl.blocks, 1);
	le64_add_cpu(&sbld->sfl.entries, le32_to_cpu(srb->entry_nr));

	magic = SCOUTFS_BLOCK_MAGIC_SRCH_BLOCK;
	hdr = &srb->hdr;

finish_hdr:
	hdr->magic = cpu_to_le32(magic);
	hdr->fsid = wri->fsid;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = cpu_to_le64(1);
	hdr->crc = cpu_to_le32(crc_block(hdr, SCOUTFS_BLOCK_LG_SIZE));

	if (srch_empty(&sbld->bld)) {
		/* the last block is referenced by the root */
		sbld->sfl.ref.blkno = hdr->blkno;
		sbld->sfl.ref.seq = hdr->seq;
		sbld->sfl.height = level + 1;
		memset(sbld->sfl.__pad, 0, sizeof(sbld->sfl.__pad));
	} else {
		/* store the parent ref to our block */
		nr = sbld->parents[level + 1].nr++;
		ref = &sbld->parents[level + 1].refs[nr];
		ref->blkno = hdr->blkno;
		ref->seq = hdr->seq;
		sbld->total_parent_refs++;
	}

	err = 0;
out:
	return err;
}

static spr_err_t sbld_create(struct srch_builder *sbld)
{
	spr_err_t err = 0;
	int i;

	init_builder(&sbld->bld, srch_empty, srch_reset, build_srch_block);

	for_each_sbld_parent(sbld, i) {
		sbld->parents[i].refs = malloc(SCOUTFS_SRCH_PARENT_REFS *
					       sizeof(struct scoutfs_block_ref));
		if (!sbld->parents[i].refs) {
			while (--i >= 1) {
				free(sbld->parents[i].refs);
				sbld->parents[i].refs = NULL;
			}
			err = ENOMEM;
			break;
		}
	}

	return err;
}

static void sbld_destroy(struct srch_builder *sbld)
{
	int i;

	for_each_sbld_parent(sbld, i) {
		free(sbld->parents[i].refs);
		sbld->parents[i].refs = NULL;
	}
}

/*
 * We've written the bloom block if we've filled out its header.
 */
static bool bloom_empty(struct block_builder *bld)
{
	DEFINE_BUILDER_CONTAINER(struct bloom_builder, bbld, bld);

	return bbld->bloom->hdr.seq != 0;
}

static void bloom_reset(struct block_builder *bld)
{
	DEFINE_BUILDER_CONTAINER(struct bloom_builder, bbld, bld);

	memset(bbld->bloom, 0, SCOUTFS_BLOCK_LG_SIZE);
}

static spr_err_t build_bloom_block(struct scoutfs_parallel_restore_writer *wri,
				   struct block_builder *bld, void *buf, u64 blkno)
{
	DEFINE_BUILDER_CONTAINER(struct bloom_builder, bbld, bld);
	struct scoutfs_block_header *hdr;

	hdr = &bbld->bloom->hdr;
	hdr->magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BLOOM);
	hdr->fsid = wri->fsid;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = cpu_to_le64(1);
	hdr->crc = cpu_to_le32(crc_block(hdr, SCOUTFS_BLOCK_LG_SIZE));

	memcpy(buf, bbld->bloom, SCOUTFS_BLOCK_LG_SIZE);

	return 0;
}

static spr_err_t bbld_create(struct bloom_builder *bbld)
{
	init_builder(&bbld->bld, bloom_empty, bloom_reset, build_bloom_block);

	bbld->bloom = malloc(SCOUTFS_BLOCK_LG_SIZE);
	if (!bbld->bloom)
		return ENOMEM;

	memset(&bbld->bloom->hdr, 0, sizeof(bbld->bloom->hdr));

	return 0;
}

static void bbld_destroy(struct bloom_builder *bbld)
{
	free(bbld->bloom);
}

static bool wri_has_super(struct scoutfs_parallel_restore_writer *wri)
{
	return wri->super.hdr.blkno != 0;
}

static void reset_builders(struct scoutfs_parallel_restore_writer *wri)
{
	/* define block build order, different than struct layout order */
	struct block_builder *builders[] = {
		/* fs items written in parallel by writers */
		&wri->fs_btb.bld,
		&wri->bloom_bbld.bld,
		&wri->srch_sbld.bld,

		/* global items written finally by global super writer */
		&wri->root_btb.bld,
		&wri->srch_btb.bld,
		/* log .post() prepares final allocators */
		&wri->log_btb.bld,
		&wri->meta_alb[0].bld,
		&wri->meta_alb[1].bld,
		&wri->meta_btb[0].bld,
		&wri->meta_btb[1].bld,
		&wri->data_btb.bld,
	};
	struct block_builder *bld;
	int i;

	for (i = 0; i < array_size(builders); i++) {
		bld = builders[i];

		if (bld->reset)
			bld->reset(bld);

		if (!list_empty(&bld->head))
			list_del_init(&bld->head);
		list_add_tail(&bld->head, &wri->builders);
	}
}

spr_err_t scoutfs_parallel_restore_create_writer(struct scoutfs_parallel_restore_writer **wrip)
{
	struct scoutfs_parallel_restore_writer *wri;
	spr_err_t err;

	wri = calloc(1, sizeof(struct scoutfs_parallel_restore_writer));
	if (!wri) {
		err = ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&wri->meta_extents);
	INIT_LIST_HEAD(&wri->builders);
	btb_init(&wri->root_btb);
	btb_init(&wri->fs_btb);
	btb_init(&wri->srch_btb);
	btb_init(&wri->log_btb);
	btb_init(&wri->meta_btb[0]);
	btb_init(&wri->meta_btb[1]);
	btb_init(&wri->data_btb);
	init_alb(&wri->meta_alb[0]);
	init_alb(&wri->meta_alb[1]);

	err = sbld_create(&wri->srch_sbld) ?:
	      bbld_create(&wri->bloom_bbld);
	if (err)
		goto out;

	reset_builders(wri);
	err = 0;
out:
	if (err) {
		if (wri) {
			sbld_destroy(&wri->srch_sbld);
			bbld_destroy(&wri->bloom_bbld);
			free(wri);
		}
		wri = NULL;
	}
	*wrip = wri;
	return err;
}

void scoutfs_parallel_restore_destroy_writer(struct scoutfs_parallel_restore_writer **wrip)
{
	struct scoutfs_parallel_restore_writer *wri = *wrip;
	struct extent_head *eh;
	struct extent_head *eh_tmp;

	if (!wri)
		return;

	btb_destroy(&wri->root_btb);
	btb_destroy(&wri->fs_btb);
	btb_destroy(&wri->srch_btb);
	btb_destroy(&wri->log_btb);
	btb_destroy(&wri->meta_btb[0]);
	btb_destroy(&wri->meta_btb[1]);
	btb_destroy(&wri->data_btb);
	sbld_destroy(&wri->srch_sbld);
	bbld_destroy(&wri->bloom_bbld);

	list_for_each_entry_safe(eh, eh_tmp, &wri->meta_extents, head) {
		list_del_init(&eh->head);
		free(eh);
	}

	free(wri);
	*wrip = NULL;
}

spr_err_t scoutfs_parallel_restore_init_slices(struct scoutfs_parallel_restore_writer *wri,
					       struct scoutfs_parallel_restore_slice *slices,
					       int nr)
{
	u64 total = le64_to_cpu(wri->super.total_meta_blocks);
	u64 start = SCOUTFS_META_DEV_START_BLKNO;
	u64 each = (total - start) / nr;
	int i;

	if (!wri_has_super(wri))
		return EINVAL;

	for (i = 0; i < nr - 1; i++) {
		slices[i].fsid = wri->super.hdr.fsid;
		slices[i].meta_start = cpu_to_le64(start);
		slices[i].meta_len = cpu_to_le64(each);
		start += each;
	}

	slices[i].fsid = wri->super.hdr.fsid;
	slices[i].meta_start = cpu_to_le64(start);
	slices[i].meta_len = cpu_to_le64(total - start);

	return 0;
}

spr_err_t scoutfs_parallel_restore_add_slice(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_slice *slice)
{
	wri->fsid = slice->fsid;

	return meta_alloc_add(wri, le64_to_cpu(slice->meta_start), le64_to_cpu(slice->meta_len));
}

spr_err_t scoutfs_parallel_restore_get_slice(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_slice *slice)
{
	slice->fsid = wri->fsid;
	slice->meta_start = cpu_to_le64(wri->meta_start);
	slice->meta_len = cpu_to_le64(wri->meta_len);
	return 0;
}

spr_err_t scoutfs_parallel_restore_add_inode(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_inode *inode)
{
	spr_err_t err;

	if (wri_has_super(wri))
		return EINVAL;

	err = insert_inode_items(wri, inode);
	if (err)
		goto out;

	wri->inode_count++;
	wri->max_ino = max(wri->max_ino, inode->ino);
	err = 0;
out:
	return err;
}

spr_err_t scoutfs_parallel_restore_add_entry(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_entry *entry)
{

	if (wri_has_super(wri))
		return EINVAL;

	return insert_entry_items(wri, entry);
}

spr_err_t scoutfs_parallel_restore_add_xattr(struct scoutfs_parallel_restore_writer *wri,
					     struct scoutfs_parallel_restore_xattr *xattr)
{
	spr_err_t err;
	int xtags;
	u32 xat_hash;
	u64 srch_hash;

	xat_hash = crc32c(U32_MAX, xattr->name, xattr->name_len);
	srch_hash = scoutfs_hash64(xattr->name, xattr->name_len);
	xtags = get_xattr_tags(xattr->name, xattr->name_len);

	err = insert_xattr_items(wri, xattr, xat_hash);
	if (!err) {
		if (xtags & XTAG_SRCH)
			err = insert_srch_entry(&wri->srch_sbld, srch_hash, xattr->ino, xattr->pos);
		if (!err && (xtags & XTAG_TOTL))
			err = insert_totl_item(wri, xattr);
	}

	return err;
}

spr_err_t scoutfs_parallel_restore_get_progress(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_parallel_restore_progress *prog)
{
	if (wri_has_super(wri))
		return EINVAL;

	memset(prog, 0, sizeof(struct scoutfs_parallel_restore_progress));
	prog->fs_items = wri->fs_btb.btroot;
	prog->root_items = wri->root_btb.btroot;
	prog->sfl = wri->srch_sbld.sfl;
	prog->bloom_ref.blkno = wri->bloom_bbld.bloom->hdr.blkno;
	prog->bloom_ref.seq = wri->bloom_bbld.bloom->hdr.seq;
	prog->inode_count = cpu_to_le64(wri->inode_count);
	prog->max_ino = cpu_to_le64(wri->max_ino);

	reset_builders(wri);
	wri->inode_count = 0;
	wri->max_ino = 0;

	return 0;
}

spr_err_t scoutfs_parallel_restore_add_progress(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_parallel_restore_progress *prog)
{
	spr_err_t err;

	if (!wri_has_super(wri))
		return EINVAL;

	/*
	 * Only one writer's progress should contain the root inode.
	 */
	if (prog->root_items.ref.blkno) {
		if (wri->root_items.ref.blkno)
			return EEXIST;
		wri->root_items = prog->root_items;
	}

	wri->max_ino = max(wri->max_ino, le64_to_cpu(prog->max_ino));

	err = insert_log_trees_item(wri, prog);
	if (!err && prog->sfl.ref.blkno)
	      err = insert_srch_item(wri, &prog->sfl);

	return err;
}

spr_err_t scoutfs_parallel_restore_write_buf(struct scoutfs_parallel_restore_writer *wri,
					     void *buf, size_t len, off_t *off_ret,
					     size_t *count_ret)
{
	struct block_builder *bld;
	off_t count = 0;
	off_t off = 0;
	u64 blkno = 0;
	spr_err_t err;

	if (len < SCOUTFS_BLOCK_LG_SIZE) {
		err = EINVAL;
		goto out;
	}

	while (len >= SCOUTFS_BLOCK_LG_SIZE) {
		bld = list_first_entry_or_null(&wri->builders, struct block_builder, head);
		if (!bld) {
			err = 0;
			break;
		}

		if (bld->empty(bld)) {
			if (bld->post && ((err = bld->post(wri, bld))))
				break;
			list_del_init(&bld->head);
			continue;
		}

		err = meta_alloc_contig(wri, blkno, &blkno);
		if (err || blkno == 0)
			break;

		if (off == 0)
			off = blkno << SCOUTFS_BLOCK_LG_SHIFT;

		err = bld->build(wri, bld, buf, blkno);
		if (err)
			break;

		buf += SCOUTFS_BLOCK_LG_SIZE;
		len -= SCOUTFS_BLOCK_LG_SIZE;
		count += SCOUTFS_BLOCK_LG_SIZE;

		dprintf("built blkno %llu off %llu count %llu\n", blkno, (u64)off, (u64)count);
	}

out:
	*off_ret = off;
	*count_ret = count;
	return count > 0 ? 0 : err;
}

/*
 * Here we take in a dev's fd an read its quorum blocks to see if the dev has
 * been mounted before
 */
static spr_err_t scoutfs_check_if_previous_mount(int fd)
{
	struct scoutfs_quorum_block *blk = NULL;
	struct scoutfs_quorum_block_event *ev;
	u64 blkno;
	int i, j;
	spr_err_t err;

	for (i = 0; i <  SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		blkno = SCOUTFS_QUORUM_BLKNO + i;
		err = read_block(fd, blkno, SCOUTFS_BLOCK_SM_SHIFT, (void **)&blk);
		if (!blk)
			return EINVAL;

		dprintf("quorum block read; quorum bklno: %llu, err_val: %d\n", blkno, err);
		if (err) {
			free(blk);
			return err;
		}

		for (j = 0; j < SCOUTFS_QUORUM_EVENT_NR; j++) {
			ev = &blk->events[j];
			if (ev->ts.sec || ev->ts.nsec) {
				free(blk);
				return EINVAL;
			}
		}

		free(blk);
	}

	return err;
}

spr_err_t scoutfs_parallel_restore_import_super(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_super_block *super, int fd)
{
	spr_err_t err;
	u64 start;
	u64 len;

	/*
	 * check the device we are restoring into to make sure
	 * that it has has never been mounted
	 */
	if (scoutfs_check_if_previous_mount(fd))
		return EINVAL;

	if (le64_to_cpu(super->fmt_vers) < 2)
		return EINVAL;

	if ((le64_to_cpu(super->flags) & SCOUTFS_FLAG_IS_META_BDEV) == 0)
		return EINVAL;

	if (wri_has_super(wri))
		return EINVAL;

	start = SCOUTFS_DATA_DEV_START_BLKNO;
	len = le64_to_cpu(super->total_data_blocks) - start;

	/* make sure all data extents are free */
	if (le64_to_cpu(super->data_alloc.total_len) != len)
		return ENOTEMPTY;

	/* we write new allocator blocks so that we don't have to read exiting */
	err = insert_free_items(&wri->data_btb, start, len);
	if (err)
		return err;

	wri->super = *super;

	/* prepare alloc block builders only after other metadata blocks are built */
	wri->log_btb.bld.post = prepare_alloc_builders;

	return 0;
}

spr_err_t scoutfs_parallel_restore_export_super(struct scoutfs_parallel_restore_writer *wri,
						struct scoutfs_super_block *super)
{
	if (!wri_has_super(wri))
		return EINVAL;

	*super = wri->super;

	super->seq = cpu_to_le64(wri->max_ino + 1);
	super->next_ino = cpu_to_le64(wri->max_ino + 1);
	super->inode_count = cpu_to_le64(wri->inode_count);
	set_alloc_root(&super->meta_alloc[0], &wri->meta_btb[0]);
	set_alloc_root(&super->meta_alloc[1], &wri->meta_btb[1]);
	set_alloc_root(&super->data_alloc, &wri->data_btb);
	super->server_meta_avail[0] = wri->meta_alb[0].lhead;
	super->server_meta_avail[1] = wri->meta_alb[1].lhead;
	memset(super->server_meta_freed, 0, sizeof(super->server_meta_freed));
	super->fs_root = wri->root_items;
	super->logs_root = wri->log_btb.btroot;
	memset(&super->log_merge, 0, sizeof(super->log_merge));
	memset(&super->mounted_clients, 0, sizeof(super->mounted_clients));
	super->srch_root = wri->srch_btb.btroot;
	/* test volopt? */

	super->hdr.crc = cpu_to_le32(crc_block(&super->hdr, SCOUTFS_BLOCK_SM_SIZE));

	return 0;
}
