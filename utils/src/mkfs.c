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

#include "sparse.h"
#include "cmd.h"
#include "util.h"
#include "format.h"
#include "crc.h"
#include "rand.h"
#include "dev.h"
#include "buddy.h"

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
 * Figure out how many blocks the ring will need.  The ring has to hold:
 *
 *  - manifest entries for every segment with largest keys
 *  - allocator regions for bits to reference every segment
 *  - empty space at the end of blocks so nodes don't cross blocks
 *  - double that to account for repeatedly duplicating entries
 *  - double that so we can migrate everything before wrapping
 */
static u64 calc_ring_blocks(u64 segs)
{
	u64 alloc_blocks;
	u64 ment_blocks;
	u64 block_bytes;
	u64 node_bytes;
	u64 regions;

	node_bytes = sizeof(struct scoutfs_treap_node) +
		     sizeof(struct scoutfs_manifest_entry) +
		     (2 * SCOUTFS_MAX_KEY_SIZE);
	block_bytes = SCOUTFS_BLOCK_SIZE - (node_bytes - 1);
	ment_blocks = DIV_ROUND_UP(segs * node_bytes, block_bytes);

	node_bytes = sizeof(struct scoutfs_treap_node) +
		     sizeof(struct scoutfs_alloc_region);
	regions = DIV_ROUND_UP(segs, SCOUTFS_ALLOC_REGION_BITS);
	block_bytes = SCOUTFS_BLOCK_SIZE - (node_bytes - 1);
	alloc_blocks = DIV_ROUND_UP(regions * node_bytes, block_bytes);

	return ALIGN((ment_blocks + alloc_blocks) * 4, SCOUTFS_SEGMENT_BLOCKS);
}

/*
 * Make a new file system by writing:
 *  - super blocks
 *  - ring block with manifest node
 *  - segment with root inode
 */
static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_inode_key root_ikey;
	struct scoutfs_inode_key *ikey;
	struct scoutfs_inode *inode;
	struct scoutfs_segment_block *sblk;
	struct scoutfs_manifest_entry *ment;
	struct scoutfs_treap_node *node;
	struct scoutfs_segment_item *item;
	struct timeval tv;
	char uuid_str[37];
	void *ring;
	u64 limit;
	u64 size;
	u64 total_blocks;
	u64 ring_blocks;
	u64 total_segs;
	u64 first_segno;
	int ret;
	u64 i;

	gettimeofday(&tv, NULL);

	super = calloc(1, SCOUTFS_BLOCK_SIZE);
	ring = calloc(1, SCOUTFS_BLOCK_SIZE);
	sblk = calloc(1, SCOUTFS_SEGMENT_SIZE);
	if (!super || !ring || !sblk) {
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

	/* require space for one segment */
	limit = SCOUTFS_SEGMENT_SIZE * 2;
	if (size < limit) {
		fprintf(stderr, "%llu byte device too small for min %llu byte fs\n",
			size, limit);
		goto out;
	}

	total_blocks = size / SCOUTFS_BLOCK_SIZE;
	total_segs = size / SCOUTFS_SEGMENT_SIZE;
	ring_blocks = calc_ring_blocks(total_segs);

	/* first initialize the super so we can use it to build structures */
	memset(super, 0, SCOUTFS_BLOCK_SIZE);
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.seq = cpu_to_le64(1);
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(SCOUTFS_ROOT_INO + 1);
	super->total_blocks = cpu_to_le64(total_blocks);
	super->total_segs = cpu_to_le64(total_segs);
	super->ring_blkno = cpu_to_le64(SCOUTFS_SUPER_BLKNO + 2);
	super->ring_blocks = cpu_to_le64(ring_blocks);
	super->ring_tail_block = cpu_to_le64(1);
	super->ring_gen = cpu_to_le64(1);
	super->next_seg_seq = cpu_to_le64(2);

	first_segno = DIV_ROUND_UP(le64_to_cpu(super->ring_blkno) +
		                   le64_to_cpu(super->ring_blocks),
				   SCOUTFS_SEGMENT_BLOCKS);

	/* alloc from uninit, don't need regions yet */
	super->alloc_uninit = cpu_to_le64(first_segno + 1);

	/* write seg with root inode */
	sblk->segno = cpu_to_le64(first_segno);
	sblk->seq = cpu_to_le64(1);
	sblk->nr_items = cpu_to_le32(1);

	root_ikey.type = SCOUTFS_INODE_KEY;
	root_ikey.ino = cpu_to_be64(SCOUTFS_ROOT_INO);

	item = &sblk->items[0];
	ikey = (void *)&sblk->items[1];
	inode = (void *)(ikey + 1);

	item->seq = cpu_to_le64(1);
	item->key_off = cpu_to_le32((long)ikey - (long)sblk);
	item->val_off = cpu_to_le32((long)inode - (long)sblk);
	item->key_len = cpu_to_le16(sizeof(struct scoutfs_inode_key));
	item->val_len = cpu_to_le16(sizeof(struct scoutfs_inode));

	*ikey = root_ikey;

	inode->nlink = cpu_to_le32(2);
	inode->mode = cpu_to_le32(0755 | 0040000);
	inode->atime.sec = cpu_to_le64(tv.tv_sec);
	inode->atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode->ctime.sec = inode->atime.sec;
	inode->ctime.nsec = inode->atime.nsec;
	inode->mtime.sec = inode->atime.sec;
	inode->mtime.nsec = inode->atime.nsec;

	ret = pwrite(fd, sblk, SCOUTFS_SEGMENT_SIZE,
		     first_segno << SCOUTFS_SEGMENT_SHIFT);
	if (ret != SCOUTFS_SEGMENT_SIZE) {
		ret = -EIO;
		goto out;
	}

	/* a single manifest entry points to the single segment */
	node = ring;
	node->off = cpu_to_le64((char *)node - (char *)ring);
	node->gen = cpu_to_le64(1);
	node->bytes = cpu_to_le16(sizeof(struct scoutfs_manifest_entry) +
				  (2 * sizeof(struct scoutfs_inode_key)));
	pseudo_random_bytes(&node->prio, sizeof(node->prio));

	ment = (void *)node->data;
	ment->segno = sblk->segno;
	ment->seq = cpu_to_le64(1);
	ment->first_key_len = cpu_to_le16(sizeof(struct scoutfs_inode_key));
	ment->last_key_len = cpu_to_le16(sizeof(struct scoutfs_inode_key));
	ment->level = 1;
	ikey = (void *)ment->keys;
	ikey[0] = root_ikey;
	ikey[1] = root_ikey;

	node->crc = crc_node(node);

	super->manifest.root.ref.off = node->off;
	super->manifest.root.ref.gen = node->gen;
	super->manifest.root.ref.aug_bits = SCOUTFS_TREAP_AUG_LESSER;
	super->manifest.level_counts[1] = cpu_to_le64(1);

	ret = write_raw_block(fd, le64_to_cpu(super->ring_blkno), ring);
	if (ret)
		goto out;

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
	       "  total blocks: %llu\n"
	       "  ring blocks: %llu\n"
	       "  fsid: %llx\n"
	       "  uuid: %s\n",
		total_blocks, ring_blocks, le64_to_cpu(super->hdr.fsid),
		uuid_str);

	ret = 0;
out:
	if (super)
		free(super);
	if (ring)
		free(ring);
	if (sblk)
		free(sblk);
	return ret;
}

static int mkfs_func(int argc, char *argv[])
{
	char *path = argv[0];
	int ret;
	int fd;

	if (argc != 1) {
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
