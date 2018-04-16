#include <unistd.h>
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

#include "sparse.h"
#include "cmd.h"
#include "util.h"
#include "format.h"
#include "crc.h"
#include "rand.h"
#include "dev.h"
#include "key.h"

static int write_raw_block(int fd, u64 blkno, void *blk)
{
	ssize_t ret;

	ret = pwrite(fd, blk, SCOUTFS_BLOCK_SIZE, blkno << SCOUTFS_BLOCK_SHIFT);
	if (ret != SCOUTFS_BLOCK_SIZE) {
		fprintf(stderr, "write to blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		return -errno;
	}

	return 0;
}

/*
 * Update the block's header and write it out.
 */
static int write_block(int fd, u64 blkno, struct scoutfs_super_block *super,
		       struct scoutfs_block_header *hdr)
{
	if (super)
		*hdr = super->hdr;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->crc = cpu_to_le32(crc_block(hdr));

	return write_raw_block(fd, blkno, hdr);
}

/*
 * Calculate the greatest number of btree blocks that might be needed to
 * store the given item population.  At most all blocks will be half
 * full.  All keys will be the max size including parent items which
 * determines the fanout.
 *
 * We will never hit this in practice.  But some joker *could* fill a
 * filesystem with empty files with enormous file names.
 */
static u64 calc_btree_blocks(u64 nr, u64 max_key, u64 max_val)
{
	u64 item_bytes;
	u64 fanout;
	u64 block_items;
	u64 leaf_blocks;
	u64 level_blocks;
	u64 total_blocks;

	/* figure out the parent fanout for these silly huge possible items */
	item_bytes = sizeof(struct scoutfs_btree_item_header) +
			    sizeof(struct scoutfs_btree_item) +
			    max_key + sizeof(struct scoutfs_btree_ref);
	fanout = ((SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_btree_block) -
		   SCOUTFS_BTREE_PARENT_MIN_FREE_BYTES) / 2) / item_bytes;

	/* figure out how many items we have to store */
	item_bytes = sizeof(struct scoutfs_btree_item_header) +
			    sizeof(struct scoutfs_btree_item) +
			    max_key + max_val;
	block_items = ((SCOUTFS_BLOCK_SIZE -
		       sizeof(struct scoutfs_btree_block)) / 2) / item_bytes;
	leaf_blocks = DIV_ROUND_UP(nr, block_items);

	/* then calc total blocks as we grow to have enough blocks for items */
	level_blocks = 1;
	total_blocks = level_blocks;
	while (level_blocks < leaf_blocks) {
		level_blocks *= fanout;
		level_blocks = min(leaf_blocks, level_blocks);
		total_blocks += level_blocks;
	}

	return total_blocks;
}

/*
 * Figure out how many btree ring blocks we'll need for all the btree
 * items that could be needed to describe this many segments.
 *
 * We can have either a free extent or manifest ref for every segment in
 * the system.  Free extent items are smaller than manifest refs, and
 * they merge if they're adjacent, so the largest possible tree is a ref
 * for every segment.
 */
static u64 calc_btree_ring_blocks(u64 total_segs)
{
	u64 blocks;

	/* key is smaller for wider parent fanout */
	assert(sizeof(struct scoutfs_extent_btree_key) <=
		     sizeof(struct scoutfs_manifest_btree_key));

	/* 2 extent items is smaller than a manifest ref */
	assert((2 * sizeof(struct scoutfs_extent_btree_key)) <=
	       (sizeof(struct scoutfs_manifest_btree_key) +
		sizeof(struct scoutfs_manifest_btree_val)));

	blocks = calc_btree_blocks(total_segs,
				sizeof(struct scoutfs_manifest_btree_key),
				sizeof(struct scoutfs_manifest_btree_val));

	return round_up(blocks * 4, SCOUTFS_SEGMENT_BLOCKS);
}

static float size_flt(u64 nr, unsigned size)
{
	float x = (float)nr * (float)size;

	while (x >= 1024)
		x /= 1024;

	return x;
}

static char *size_str(u64 nr, unsigned size)
{
	float x = (float)nr * (float)size;
	static char *suffixes[] = {
		"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB",
	};
	int i = 0;

	while (x >= 1024) {
		x /= 1024;
		i++;
	}

	return suffixes[i];
}

#define SIZE_FMT "%llu (%.2f %s)"
#define SIZE_ARGS(nr, sz) (nr), size_flt(nr, sz), size_str(nr, sz)

/*
 * Make a new file system by writing:
 *  - super blocks
 *  - btree ring blocks with manifest and allocator btree blocks
 *  - segment with root inode items
 */
static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_key *ino_key;
	struct scoutfs_key *idx_key;
	struct scoutfs_inode *inode;
	struct scoutfs_segment_block *sblk;
	struct scoutfs_manifest_btree_key *mkey;
	struct scoutfs_manifest_btree_val *mval;
	struct scoutfs_extent_btree_key *ebk;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *btitem;
	struct scoutfs_segment_item *item;
	struct scoutfs_key key;
	__le32 *prev_link;
	struct timeval tv;
	char uuid_str[37];
	u64 blkno;
	u64 limit;
	u64 size;
	u64 ring_blocks;
	u64 total_segs;
	u64 total_blocks;
	u64 first_segno;
	u64 free_start;
	u64 free_len;
	int ret;
	u64 i;

	gettimeofday(&tv, NULL);

	super = calloc(1, SCOUTFS_BLOCK_SIZE);
	bt = calloc(1, SCOUTFS_BLOCK_SIZE);
	sblk = calloc(1, SCOUTFS_SEGMENT_SIZE);
	if (!super || !bt || !sblk) {
		ret = -errno;
		fprintf(stderr, "failed to allocate block mem: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	ret = device_size(path, fd, &size);
	if (ret) {
		fprintf(stderr, "failed to stat '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	/* arbitrarily require space for a handful of segments */
	limit = SCOUTFS_SEGMENT_SIZE * 16;
	if (size < limit) {
		fprintf(stderr, "%llu byte device too small for min %llu byte fs\n",
			size, limit);
		goto out;
	}

	total_segs = size / SCOUTFS_SEGMENT_SIZE;
	total_blocks = size / SCOUTFS_BLOCK_SIZE;

	/* partially initialize the super so we can use it to init others */
	memset(super, 0, SCOUTFS_BLOCK_SIZE);
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.seq = cpu_to_le64(1);
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	super->format_hash = cpu_to_le64(SCOUTFS_FORMAT_HASH);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(SCOUTFS_ROOT_INO + 1);
	super->next_seq = cpu_to_le64(1);
	super->total_blocks = cpu_to_le64(total_blocks);
	super->next_seg_seq = cpu_to_le64(2);

	/* align the btree ring to the segment after the supers */
	blkno = round_up(SCOUTFS_SUPER_BLKNO + SCOUTFS_SUPER_NR,
			 SCOUTFS_SEGMENT_BLOCKS);
	/* first usable segno follows manifest ring */
	ring_blocks = calc_btree_ring_blocks(total_segs);
	first_segno = (blkno + ring_blocks) / SCOUTFS_SEGMENT_BLOCKS;
	free_start = ((first_segno + 1) << SCOUTFS_SEGMENT_BLOCK_SHIFT);
	free_len = total_blocks - free_start;

	super->free_blocks = cpu_to_le64(free_len);
	super->bring.first_blkno = cpu_to_le64(blkno);
	super->bring.nr_blocks = cpu_to_le64(ring_blocks);
	super->bring.next_block = cpu_to_le64(2);
	super->bring.next_seq = cpu_to_le64(2);

	/* allocator btree has item with space after first segno */
	super->alloc_root.ref.blkno = cpu_to_le64(blkno);
	super->alloc_root.ref.seq = cpu_to_le64(1);
	super->alloc_root.height = 1;

	memset(bt, 0, SCOUTFS_BLOCK_SIZE);
	bt->fsid = super->hdr.fsid;
	bt->blkno = cpu_to_le64(blkno);
	bt->seq = cpu_to_le64(1);
	bt->nr_items = cpu_to_le16(2);

	/* btree item allocated from the back of the block */
	ebk = (void *)bt + SCOUTFS_BLOCK_SIZE - sizeof(*ebk);
	btitem = (void *)ebk - sizeof(*btitem);

	bt->item_hdrs[0].off = cpu_to_le16((long)btitem - (long)bt);
	bt->free_end = bt->item_hdrs[0].off;
	btitem->key_len = cpu_to_le16(sizeof(*ebk));
	btitem->val_len = cpu_to_le16(0);

	ebk->type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE;
	ebk->major = cpu_to_be64(free_start + free_len - 1);
	ebk->minor = cpu_to_be64(free_len);

	ebk = (void *)btitem - sizeof(*ebk);
	btitem = (void *)ebk - sizeof(*btitem);

	bt->item_hdrs[1].off = cpu_to_le16((long)btitem - (long)bt);
	bt->free_end = bt->item_hdrs[1].off;
	btitem->key_len = cpu_to_le16(sizeof(*ebk));
	btitem->val_len = cpu_to_le16(0);

	ebk->type = SCOUTFS_FREE_EXTENT_BLOCKS_TYPE;
	ebk->major = cpu_to_be64(free_len);
	ebk->minor = cpu_to_be64(free_start + free_len - 1);

	bt->crc = cpu_to_le32(crc_btree_block(bt));

	ret = write_raw_block(fd, blkno, bt);
	if (ret)
		goto out;
	blkno++;

	/* manifest btree has a block with an item for the segment */
	super->manifest.root.ref.blkno = cpu_to_le64(blkno);
	super->manifest.root.ref.seq = cpu_to_le64(1);
	super->manifest.root.height = 1;
	super->manifest.level_counts[1] = cpu_to_le64(1);

	memset(bt, 0, SCOUTFS_BLOCK_SIZE);
	bt->fsid = super->hdr.fsid;
	bt->blkno = cpu_to_le64(blkno);
	bt->seq = cpu_to_le64(1);
	bt->nr_items = cpu_to_le16(1);

	/* btree item allocated from the back of the block */
	mval = (void *)bt + SCOUTFS_BLOCK_SIZE - sizeof(*mval);
	ino_key = &mval->last_key;
	mkey = (void *)mval - sizeof(*mkey);
	btitem = (void *)mkey - sizeof(*btitem);

	bt->item_hdrs[0].off = cpu_to_le16((long)btitem - (long)bt);
	bt->free_end = bt->item_hdrs[0].off;

	btitem->key_len = cpu_to_le16(sizeof(*mkey));
	btitem->val_len = cpu_to_le16(sizeof(*mval));

	mkey->level = 1;
	mkey->seq = cpu_to_be64(1);
	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_INODE_INDEX_ZONE;
	key.sk_type = SCOUTFS_INODE_INDEX_META_SEQ_TYPE;
	key.skii_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	scoutfs_key_to_be(&mkey->first_key, &key);

	mval->segno = cpu_to_le64(first_segno);
	ino_key->sk_zone = SCOUTFS_FS_ZONE;
	ino_key->ski_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	ino_key->sk_type = SCOUTFS_INODE_TYPE;

	bt->crc = cpu_to_le32(crc_btree_block(bt));

	ret = write_raw_block(fd, blkno, bt);
	if (ret)
		goto out;
	blkno += ring_blocks;

	/* write seg with root inode */
	sblk->segno = cpu_to_le64(first_segno);
	sblk->seq = cpu_to_le64(1);
	prev_link = &sblk->skip_links[0];

	item = (void *)(sblk + 1);
	*prev_link = cpu_to_le32((long)item -(long)sblk);
	prev_link = &item->skip_links[0];

	item->val_len = 0;
	item->nr_links = 1;
	le32_add_cpu(&sblk->nr_items, 1);

	idx_key = &item->key;
	idx_key->sk_zone = SCOUTFS_INODE_INDEX_ZONE;
	idx_key->sk_type = SCOUTFS_INODE_INDEX_META_SEQ_TYPE;
	idx_key->skii_ino = cpu_to_le64(SCOUTFS_ROOT_INO);

	item = (void *)&item->skip_links[1];
	*prev_link = cpu_to_le32((long)item -(long)sblk);
	prev_link = &item->skip_links[0];

	sblk->last_item_off = cpu_to_le32((long)item - (long)sblk);

	ino_key = (void *)&item->key;
	inode = (void *)&item->skip_links[1];

	item->val_len = cpu_to_le16(sizeof(struct scoutfs_inode));
	item->nr_links = 1;
	le32_add_cpu(&sblk->nr_items, 1);

	ino_key->sk_zone = SCOUTFS_FS_ZONE;
	ino_key->ski_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	ino_key->sk_type = SCOUTFS_INODE_TYPE;

	inode->next_readdir_pos = cpu_to_le64(2);
	inode->nlink = cpu_to_le32(SCOUTFS_DIRENT_FIRST_POS);
	inode->mode = cpu_to_le32(0755 | 0040000);
	inode->atime.sec = cpu_to_le64(tv.tv_sec);
	inode->atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode->ctime.sec = inode->atime.sec;
	inode->ctime.nsec = inode->atime.nsec;
	inode->mtime.sec = inode->atime.sec;
	inode->mtime.nsec = inode->atime.nsec;

	item = (void *)(inode + 1);
	sblk->total_bytes = cpu_to_le32((long)item - (long)sblk);

	ret = pwrite(fd, sblk, SCOUTFS_SEGMENT_SIZE,
		     first_segno << SCOUTFS_SEGMENT_SHIFT);
	if (ret != SCOUTFS_SEGMENT_SIZE) {
		ret = -EIO;
		goto out;
	}

	/* write the two super blocks */
	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {
		super->hdr.seq = cpu_to_le64(i + 1);
		ret = write_block(fd, SCOUTFS_SUPER_BLKNO + i, NULL,
				  &super->hdr);
		if (ret)
			goto out;
	}

	if (fsync(fd)) {
		ret = -errno;
		fprintf(stderr, "failed to fsync '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	uuid_unparse(super->uuid, uuid_str);

	printf("Created scoutfs filesystem:\n"
	       "  device path:        %s\n"
	       "  fsid:               %llx\n"
	       "  format hash:        %llx\n"
	       "  uuid:               %s\n"
	       "  device bytes:       "SIZE_FMT"\n"
	       "  device blocks:      "SIZE_FMT"\n"
	       "  btree ring blocks:  "SIZE_FMT"\n"
	       "  free blocks:        "SIZE_FMT"\n",
		path,
		le64_to_cpu(super->hdr.fsid),
		le64_to_cpu(super->format_hash),
		uuid_str,
		SIZE_ARGS(size, 1),
		SIZE_ARGS(total_blocks, SCOUTFS_BLOCK_SIZE),
		SIZE_ARGS(le64_to_cpu(super->bring.nr_blocks),
			  SCOUTFS_BLOCK_SIZE),
		SIZE_ARGS(le64_to_cpu(super->free_blocks),
			  SCOUTFS_BLOCK_SIZE));

	ret = 0;
out:
	if (super)
		free(super);
	if (bt)
		free(bt);
	if (sblk)
		free(sblk);
	return ret;
}

static int mkfs_func(int argc, char *argv[])
{
	char *path = argv[1];
	int ret;
	int fd;

	if (argc != 2) {
		printf("scoutfs: mkfs: a single path argument is required\n");
		return -EINVAL;
	}

	fd = open(path, O_RDWR | O_EXCL);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	ret = write_new_fs(path, fd);
	close(fd);

	return ret;
}

static void __attribute__((constructor)) mkfs_ctor(void)
{
	cmd_register("mkfs", "<path>", "write a new file system", mkfs_func);

	/* for lack of some other place to put these.. */
	build_assert(sizeof(uuid_t) == SCOUTFS_UUID_BYTES);
}
