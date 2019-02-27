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
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

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
static int write_new_fs(char *path, int fd, struct scoutfs_quorum_config *conf)
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
	struct scoutfs_quorum_slot *slot;
	struct scoutfs_key key;
	struct in_addr in;
	__le32 *prev_link;
	struct timeval tv;
	char uuid_str[37];
	void *zeros;
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
	int i;

	gettimeofday(&tv, NULL);

	super = calloc(1, SCOUTFS_BLOCK_SIZE);
	bt = calloc(1, SCOUTFS_BLOCK_SIZE);
	sblk = calloc(1, SCOUTFS_SEGMENT_SIZE);
	zeros = calloc(1, SCOUTFS_SEGMENT_SIZE);
	if (!super || !bt || !sblk || !zeros) {
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
	super->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_SUPER);
	super->hdr.seq = cpu_to_le64(1);
	super->format_hash = cpu_to_le64(SCOUTFS_FORMAT_HASH);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(SCOUTFS_ROOT_INO + 1);
	super->next_trans_seq = cpu_to_le64(1);
	super->total_blocks = cpu_to_le64(total_blocks);
	super->next_seg_seq = cpu_to_le64(2);
	super->next_node_id = cpu_to_le64(1);
	super->next_compact_id = cpu_to_le64(1);

	super->quorum_config = *conf;
	super->quorum_config.gen = cpu_to_le64(1);

	/* align the btree ring to the segment after the super */
	blkno = round_up(SCOUTFS_SUPER_BLKNO + 1, SCOUTFS_SEGMENT_BLOCKS);
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
	bt->hdr.fsid = super->hdr.fsid;
	bt->hdr.blkno = cpu_to_le64(blkno);
	bt->hdr.seq = cpu_to_le64(1);
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

	bt->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BTREE);
	bt->hdr.crc = cpu_to_le32(crc_block(&bt->hdr));

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
	bt->hdr.fsid = super->hdr.fsid;
	bt->hdr.blkno = cpu_to_le64(blkno);
	bt->hdr.seq = cpu_to_le64(1);
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

	bt->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BTREE);
	bt->hdr.crc = cpu_to_le32(crc_block(&bt->hdr));

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
	sblk->crc = cpu_to_le32(crc_segment(sblk));

	ret = pwrite(fd, sblk, SCOUTFS_SEGMENT_SIZE,
		     first_segno << SCOUTFS_SEGMENT_SHIFT);
	if (ret != SCOUTFS_SEGMENT_SIZE) {
		ret = -EIO;
		goto out;
	}

	/* zero out quorum blocks */
	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		ret = write_raw_block(fd, SCOUTFS_QUORUM_BLKNO + i, zeros);
		if (ret < 0) {
			fprintf(stderr, "error zeroing quorum block: %s (%d)\n",
				strerror(-errno), -errno);
			goto out;
		}
	}

	/* write the super block */
	super->hdr.seq = cpu_to_le64(1);
	ret = write_block(fd, SCOUTFS_SUPER_BLKNO, NULL, &super->hdr);
	if (ret)
		goto out;

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

	printf("  quorum slots:\n");
	for (i = 0; i < array_size(super->quorum_config.slots); i++) {
		slot = &super->quorum_config.slots[i];
		if (slot->flags == 0)
			continue;

		in.s_addr = htonl(le32_to_cpu(slot->addr.addr));

		printf("    [%2u]: name %s priority %u addr:port %s:%u\n",
		       i, slot->name, slot->vote_priority,
		       inet_ntoa(in), le16_to_cpu(slot->addr.port));
	}

	ret = 0;
out:
	if (super)
		free(super);
	if (bt)
		free(bt);
	if (sblk)
		free(sblk);
	if (zeros)
		free(zeros);
	return ret;
}

static struct option long_ops[] = {
	{ "quorum_slot", 1, NULL, 'Q' },
	{ NULL, 0, NULL, 0}
};

enum { NAME, PRIORITY, ADDR, PORT };

static int parse_quorum_slot(struct scoutfs_quorum_config *conf, char *arg)
{
	struct scoutfs_quorum_slot *slot;
	struct scoutfs_quorum_slot *sl;
	struct in_addr in;
	unsigned long port;
	int free_slot;
	char *save;
	char *tok;
	char *dup;
	char *s;
	int ret;
	int i;

	dup = strdup(arg);
	if (!dup) {
		printf("allocation failure while parsing quorum slot '%s'\n",
		       arg);
		return -EINVAL;
	}

	for (i = 0; i < array_size(conf->slots); i++) {
		if (conf->slots[i].flags == 0)
			break;
	}
	if (i == array_size(conf->slots)) {
		printf("too many quorum slots provided\n");
		ret = -EINVAL;
		goto out;
	}
	slot = &conf->slots[i];
	free_slot = i;

	slot->addr.port = cpu_to_le16(23853); /* randomly chosen */

	for (save = NULL, s = dup, i = NAME; i <= PORT; i++, s = NULL) {
		tok = strtok_r(s, ":", &save);

		if (tok == NULL)
			break;

		/* assume flags and a default port */
		if (i == PORT && !isdigit(tok[0]))
			i = PRIORITY;

		switch(i) {
		case NAME:
			if (strlen(tok) >= SCOUTFS_UNIQUE_NAME_MAX_BYTES) {
				printf("quorum slot name too long: %s\n", tok);
				return -EINVAL;
			}
			strcpy((char *)slot->name, tok);
			break;

		case PRIORITY:
			slot->vote_priority = strtoul(tok, NULL, 0);
			if (slot->vote_priority > 255) {
				printf("invalid quorum slot priority: %s\n",
				       tok);
				ret = -EINVAL;
				goto out;
			}
			break;

		case ADDR:
			if (inet_aton(tok, &in) == 0) {
				printf("invalid quorum slot address: %s\n", tok);
				ret = -EINVAL;
				goto out;
			}
			slot->addr.addr = cpu_to_le32(htonl(in.s_addr));
			break;

		case PORT:
			port = strtoul(tok, NULL, 0);
			if (port == 0 || port >= 65535) {
				printf("invalid quorum slot port: %s\n", tok);
				ret = -EINVAL;
				goto out;
			}
			slot->addr.port = cpu_to_le16(port);
			break;

		}
	}

	if (slot->name[0] == '\0') {
		printf("quorum slot must specify name: %s\n", arg);
		ret = -EINVAL;
		goto out;
	}

	if (slot->addr.addr == 0) {
		printf("quorum slot must specify address: %s\n", arg);
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < free_slot; i++) {
		sl = &conf->slots[i];

		if (strcmp((char *)slot->name, (char *)sl->name) == 0) {
			printf("duplicate quorum slot name: %s\n", arg);
			ret = -EINVAL;
			goto out;
		}

		if (memcmp(&slot->addr, &sl->addr, sizeof(slot->addr)) == 0) {
			printf("duplicate quorum slot addr: %s\n", arg);
			ret = -EINVAL;
			goto out;
		}
	}

	slot->flags = SCOUTFS_QUORUM_SLOT_ACTIVE;
	ret = 0;
out:
	free(dup);
	return ret;
}

static int mkfs_func(int argc, char *argv[])
{
	struct scoutfs_quorum_config conf = {0,};
	bool have_quorum = false;
	char *path = argv[1];
	int ret;
	int fd;
	int c;

	while ((c = getopt_long(argc, argv, "Q:", long_ops, NULL)) != -1) {
		switch (c) {
		case 'Q':
			ret = parse_quorum_slot(&conf, optarg);
			if (ret)
				return ret;
			have_quorum = true;
			break;
		case '?':
		default:
			return -EINVAL;
		}
	}

	if (optind >= argc) {
		printf("scoutfs: mkfs: a single path argument is required\n");
		return -EINVAL;
	}

	path = argv[optind];

	if (!have_quorum) {
		printf("must configure quorum with --quorum_slot|-Q options\n");
		return -EINVAL;
	}

	fd = open(path, O_RDWR | O_EXCL);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	ret = write_new_fs(path, fd, &conf);
	close(fd);

	return ret;
}

static void __attribute__((constructor)) mkfs_ctor(void)
{
	cmd_register("mkfs", "<path>", "write a new file system", mkfs_func);

	/* for lack of some other place to put these.. */
	build_assert(sizeof(uuid_t) == SCOUTFS_UUID_BYTES);
}
