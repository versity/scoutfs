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
 * Figure out how many blocks a given ring will need given a max number
 * of entries up to a given max size.  We figure out how many blocks it
 * could take to store these maximal entries given unused tail space and
 * block header overheads.  Then we (wastefully) multiply by three to
 * ensure that the ring won't consume itself as it wraps.  The caller
 * aligns the ring size to a segment size depending on where it starts.
 */
static u64 calc_ring_blocks(u64 max_nr, u64 max_size)
{
	u64 block_bytes;

	max_size += sizeof(struct scoutfs_ring_entry);

	block_bytes = SCOUTFS_BLOCK_SIZE - sizeof(struct scoutfs_ring_block) -
			(max_size - 1);

	return DIV_ROUND_UP(max_nr * max_size, block_bytes) * 3;
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
	struct scoutfs_inode_key *ikey;
	struct scoutfs_inode_index_key *idx_key;
	struct scoutfs_inode *inode;
	struct scoutfs_segment_block *sblk;
	struct scoutfs_manifest_entry *ment;
	struct scoutfs_ring_descriptor *rdesc;
	struct scoutfs_ring_block *rblk;
	struct scoutfs_ring_entry *rent;
	struct scoutfs_segment_item *item;
	__le32 *prev_link;
	struct timeval tv;
	char uuid_str[37];
	u64 blkno;
	u64 limit;
	u64 size;
	u64 ring_blocks;
	u64 total_segs;
	u64 first_segno;
	int ret;
	u64 i;

	gettimeofday(&tv, NULL);

	super = calloc(1, SCOUTFS_BLOCK_SIZE);
	rblk = calloc(1, SCOUTFS_BLOCK_SIZE);
	sblk = calloc(1, SCOUTFS_SEGMENT_SIZE);
	if (!super || !rblk || !sblk) {
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

	total_segs = size / SCOUTFS_SEGMENT_SIZE;

	/* partially initialize the super so we can use it to init others */
	memset(super, 0, SCOUTFS_BLOCK_SIZE);
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.seq = cpu_to_le64(1);
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(SCOUTFS_ROOT_INO + 1);
	super->next_seq = cpu_to_le64(1);
	super->total_segs = cpu_to_le64(total_segs);
	super->next_seg_seq = cpu_to_le64(2);

	/* start writing rings after the super */
	blkno = SCOUTFS_SUPER_BLKNO + SCOUTFS_SUPER_NR;

	/* allocator ring is empty, allocations start from super fields */
	ring_blocks = calc_ring_blocks(DIV_ROUND_UP(total_segs,
						SCOUTFS_ALLOC_REGION_BITS),
				       sizeof(struct scoutfs_alloc_region));
	ring_blocks = round_up(blkno + ring_blocks, SCOUTFS_SEGMENT_BLOCKS) -
			blkno;

	rdesc = &super->alloc_ring;
	rdesc->blkno = cpu_to_le64(blkno);
	rdesc->total_blocks = cpu_to_le64(ring_blocks);
	rdesc->first_block = cpu_to_le64(0);
	rdesc->first_seq = cpu_to_le64(0);
	rdesc->nr_blocks = cpu_to_le64(0);

	blkno += ring_blocks;

	/* manifest ring has a block with an entry for the segment */
	ring_blocks = calc_ring_blocks(total_segs,
				   sizeof(struct scoutfs_manifest_entry) +
				   (2 * SCOUTFS_MAX_KEY_SIZE));
	ring_blocks = round_up(ring_blocks, SCOUTFS_SEGMENT_BLOCKS);

	/* first usable segno follows manifest ring */
	first_segno = (blkno + ring_blocks) / SCOUTFS_SEGMENT_BLOCKS;

	super->manifest.level_counts[1] = cpu_to_le64(1);

	rdesc = &super->manifest.ring;
	rdesc->blkno = cpu_to_le64(blkno);
	rdesc->total_blocks = cpu_to_le64(ring_blocks);
	rdesc->first_seq = cpu_to_le64(1);
	rdesc->nr_blocks = cpu_to_le64(1);

	memset(rblk, 0, SCOUTFS_BLOCK_SIZE);
	rblk->pad = 0;
	rblk->fsid = super->hdr.fsid;
	rblk->seq = cpu_to_le64(1);
	rblk->block = 0;
	rblk->nr_entries = cpu_to_le32(1);

	rent = rblk->entries;
	rent->flags = 0;
	rent->data_len = cpu_to_le16(sizeof(struct scoutfs_manifest_entry) +
				     sizeof(struct scoutfs_inode_key) +
				     sizeof(struct scoutfs_inode_index_key));

	ment = (void *)rent->data;
	ment->segno = cpu_to_le64(first_segno);
	ment->seq = cpu_to_le64(1);
	ment->first_key_len = cpu_to_le16(sizeof(struct scoutfs_inode_key));
	ment->last_key_len = cpu_to_le16(sizeof(struct scoutfs_inode_index_key));
	ment->level = 1;
	ikey = (void *)ment->keys;
	ikey->type = SCOUTFS_INODE_KEY;
	ikey->ino = cpu_to_be64(SCOUTFS_ROOT_INO);
	idx_key = (void *)(ikey + 1);
	idx_key->type = SCOUTFS_INODE_INDEX_META_SEQ_KEY;
	idx_key->major = cpu_to_be64(0);
	idx_key->minor = 0;
	idx_key->ino = cpu_to_be64(SCOUTFS_ROOT_INO);

	rblk->crc = cpu_to_le32(crc_ring_block(rblk));

	ret = write_raw_block(fd, blkno, rblk);
	if (ret)
		goto out;
	blkno += ring_blocks;

	/* alloc from uninit, don't need regions yet */
	super->alloc_uninit = cpu_to_le64(first_segno + 1);
	super->free_segs = cpu_to_le64(total_segs - (first_segno + 1));

	/* write seg with root inode */
	sblk->segno = cpu_to_le64(first_segno);
	sblk->seq = cpu_to_le64(1);
	sblk->nr_items = cpu_to_le32(5);
	prev_link = &sblk->skip_links[0];

	item = (void *)(sblk + 1);
	ikey = (void *)&item->skip_links[1];
	inode = (void *)ikey + sizeof(struct scoutfs_inode_key);

	item->key_len = cpu_to_le16(sizeof(struct scoutfs_inode_key));
	item->val_len = cpu_to_le16(sizeof(struct scoutfs_inode));
	item->nr_links = 1;

	ikey->type = SCOUTFS_INODE_KEY;
	ikey->ino = cpu_to_be64(SCOUTFS_ROOT_INO);

	inode->next_readdir_pos = cpu_to_le64(2);
	inode->nlink = cpu_to_le32(SCOUTFS_DIRENT_FIRST_POS);
	inode->mode = cpu_to_le32(0755 | 0040000);
	inode->atime.sec = cpu_to_le64(tv.tv_sec);
	inode->atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode->ctime.sec = inode->atime.sec;
	inode->ctime.nsec = inode->atime.nsec;
	inode->mtime.sec = inode->atime.sec;
	inode->mtime.nsec = inode->atime.nsec;

	*prev_link = cpu_to_le32((long)item -(long)sblk);
	prev_link = &item->skip_links[0];

	item = (void *)inode + sizeof(struct scoutfs_inode);
	idx_key = (void *)&item->skip_links[1];

	/* write the root inode index keys */
	for (i = SCOUTFS_INODE_INDEX_CTIME_KEY;
	     i <= SCOUTFS_INODE_INDEX_META_SEQ_KEY; i++) {

		item->key_len = cpu_to_le16(sizeof(*idx_key));
		item->val_len = 0;
		item->nr_links = 1;

		idx_key->type = i;
		idx_key->ino = cpu_to_be64(SCOUTFS_ROOT_INO);

		switch(i) {
		case SCOUTFS_INODE_INDEX_CTIME_KEY:
		case SCOUTFS_INODE_INDEX_MTIME_KEY:
			idx_key->major = cpu_to_be64(tv.tv_sec);
			idx_key->minor = cpu_to_be32(tv.tv_usec * 1000);
			break;
		default:
			idx_key->major = cpu_to_be64(0);
			idx_key->minor = 0;
			break;
		}

		*prev_link = cpu_to_le32((long)item -(long)sblk);
		prev_link = &item->skip_links[0];

		sblk->last_item_off = cpu_to_le32((long)item - (long)sblk);

		item = (void *)(idx_key + 1);
		idx_key = (void *)&item->skip_links[1];
	}

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
	       "  fsid: %llx\n"
	       "  uuid: %s\n",
		le64_to_cpu(super->hdr.fsid),
		uuid_str);

	ret = 0;
out:
	if (super)
		free(super);
	if (rblk)
		free(rblk);
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
