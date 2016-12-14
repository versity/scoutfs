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
#include "bitops.h"
#include "buddy.h"
#include "item.h"

/*
 * Update the block's header and write it out.
 */
static int write_block(int fd, u64 blkno, struct scoutfs_super_block *super,
		       struct scoutfs_block_header *hdr)
{
	ssize_t ret;

	if (super)
		*hdr = super->hdr;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->crc = cpu_to_le32(crc_block(hdr));

	ret = pwrite(fd, hdr, SCOUTFS_BLOCK_SIZE, blkno << SCOUTFS_BLOCK_SHIFT);
	if (ret != SCOUTFS_BLOCK_SIZE) {
		fprintf(stderr, "write to blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		return -errno;
	}

	return 0;
}

/*
 * Figure out how many blocks the ring will need.  This goes crazy
 * with the variables to make the calculation clear.
 *
 * XXX just a place holder.  The real calculation is more like:
 *
 *  - max size add manifest entries for all segments
 *  - (some day) allocator entries for all segments
 *  - ring block header overhead
 *  - ring block unused tail space overhead
 *
 */
static u64 calc_ring_blocks(u64 size)
{
	u64 first_seg_blocks;
	u64 max_entry_bytes;
	u64 total_bytes;
	u64 blocks;
	u64 segs;

	segs = size >> SCOUTFS_SEGMENT_SHIFT;
	max_entry_bytes = sizeof(struct scoutfs_ring_add_manifest) +
		          (2 * SCOUTFS_MAX_KEY_SIZE);
	total_bytes = (segs * max_entry_bytes) * 4;
	blocks = DIV_ROUND_UP(total_bytes, SCOUTFS_BLOCK_SIZE);

	first_seg_blocks = SCOUTFS_SEGMENT_BLOCKS -
			   (SCOUTFS_SUPER_BLKNO + SCOUTFS_SUPER_NR);

	return max(first_seg_blocks, blocks);
}

/*
 * Make a new file system by writing:
 *  - super blocks
 *  - ring block with manifest entry
 *  - segment with root inode
 */
static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_inode_key *ikey;
	struct scoutfs_inode *inode;
	struct scoutfs_segment_block *sblk;
	struct scoutfs_ring_block *ring;
	struct scoutfs_ring_add_manifest *am;
	struct scoutfs_ring_alloc_region *reg;
	struct native_item item;
	struct timeval tv;
	char uuid_str[37];
	unsigned int i;
	u64 limit;
	u64 size;
	u64 total_blocks;
	u64 ring_blocks;
	u64 total_segs;
	u64 first_segno;
	__u8 *type;
	int ret;

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
	ring_blocks = calc_ring_blocks(size);

	/* first initialize the super so we can use it to build structures */
	memset(super, 0, SCOUTFS_BLOCK_SIZE);
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.seq = cpu_to_le64(1);
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(SCOUTFS_ROOT_INO + 1);
	super->total_blocks = cpu_to_le64(total_blocks);
	super->total_segs = cpu_to_le64(total_segs);
	super->alloc_uninit = cpu_to_le64(SCOUTFS_ALLOC_REGION_BITS);
	super->ring_blkno = cpu_to_le64(SCOUTFS_SUPER_BLKNO + 2);
	super->ring_blocks = cpu_to_le64(ring_blocks);
	super->ring_nr = cpu_to_le64(1);
	super->ring_seq = cpu_to_le64(1);

	first_segno = DIV_ROUND_UP(le64_to_cpu(super->ring_blkno) +
		                   le64_to_cpu(super->ring_blocks),
				   SCOUTFS_SEGMENT_BLOCKS);

	/* write seg with root inode */
	sblk->segno = cpu_to_le64(first_segno);
	sblk->max_seq = cpu_to_le64(1);
	sblk->nr_items = cpu_to_le32(1);

	ikey = (void *)&sblk->items[1];
	inode = (void *)(ikey + 1);

	item.seq = 1;
	item.key_off = (long)ikey - (long)sblk;
	item.val_off = (long)inode - (long)sblk;
	item.key_len = sizeof(struct scoutfs_inode_key);
	item.val_len = sizeof(struct scoutfs_inode);
	store_item(sblk, 0, &item);

	ikey->type = SCOUTFS_INODE_KEY;
	ikey->ino = cpu_to_be64(SCOUTFS_ROOT_INO);

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
	am = (void *)ring->entries;
	am->eh.type = SCOUTFS_RING_ADD_MANIFEST;
	am->eh.len = cpu_to_le16(sizeof(struct scoutfs_ring_add_manifest) + 1);
	am->segno = sblk->segno;
	am->seq = cpu_to_le64(1);
	am->first_key_len = 0;
	am->last_key_len = cpu_to_le16(1);
	am->level = 1;
	type = (void *)(am + 1);
	*type = SCOUTFS_MAX_UNUSED_KEY;

	/* a single alloc region records the first two segs as allocated */
	reg = (void *)am + le16_to_cpu(am->eh.len);
	reg->eh.type = SCOUTFS_RING_ADD_ALLOC;
	reg->eh.len = cpu_to_le16(sizeof(struct scoutfs_ring_alloc_region));
	/* initial super, ring, and first seg are all allocated */
	memset(reg->bits, 0xff, sizeof(reg->bits));
	for (i = 0; i <= first_segno; i++)
		clear_bit_le(i, reg->bits);

	/* block is already zeroed and so contains a 0 len terminating header */

	ret = write_block(fd, le64_to_cpu(super->ring_blkno), super,
			  &ring->hdr);
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
