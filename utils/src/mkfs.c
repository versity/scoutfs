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

/*
 * Update the block's header and write it out.
 */
static int write_block(int fd, u64 blkno, struct scoutfs_block_header *hdr)
{
	ssize_t ret;

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

static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_block_header hdr;
	struct scoutfs_inode *inode;
	struct scoutfs_ring_map_block *map;
	struct scoutfs_ring_block *ring;
	struct scoutfs_ring_entry *ent;
	struct scoutfs_ring_add_manifest *mani;
	struct scoutfs_ring_bitmap *bm;
	struct scoutfs_item_block *iblk;
	struct scoutfs_item_header *ihdr;
	struct scoutfs_key root_key;
	struct timeval tv;
	char uuid_str[37];
	unsigned int i;
	u64 size;
	u64 total_chunks;
	u64 blkno;
	void *buf;
	int ret;

	gettimeofday(&tv, NULL);
	/* crc and blkno written for each write */
	hdr._pad = 0;
	pseudo_random_bytes(&hdr.fsid, sizeof(hdr.fsid));
	hdr.seq = cpu_to_le64(1);

	buf = malloc(SCOUTFS_BLOCK_SIZE);
	if (!buf) {
		ret = -errno;
		fprintf(stderr, "failed to allocate a block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	ret = device_size(path, fd, &size);
	if (ret) {
		fprintf(stderr, "failed to stat '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	total_chunks = size >> SCOUTFS_CHUNK_SHIFT;

	root_key.inode = cpu_to_le64(SCOUTFS_ROOT_INO);
	root_key.type = SCOUTFS_INODE_KEY;
	root_key.offset = 0;

	/* super in log 0, first fs log block in log 1 */
	blkno = 1 << SCOUTFS_CHUNK_BLOCK_SHIFT;

	/* write a single log block with the root inode item */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	iblk = buf;
	iblk->hdr = hdr;
	iblk->first = root_key;
	iblk->last = root_key;
	iblk->nr_items = cpu_to_le32(1);
	ihdr = (void *)(iblk + 1);
	ihdr->key = root_key;
	ihdr->len = cpu_to_le16(sizeof(struct scoutfs_inode));
	inode = (void *)(ihdr + 1);
	inode->nlink = cpu_to_le32(2);
	inode->mode = cpu_to_le32(0755 | 0040000);
	inode->atime.sec = cpu_to_le64(tv.tv_sec);
	inode->atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode->ctime.sec = inode->atime.sec;
	inode->ctime.nsec = inode->atime.nsec;
	inode->mtime.sec = inode->atime.sec;
	inode->mtime.nsec = inode->atime.nsec;

	ret = write_block(fd, blkno, &iblk->hdr);
	if (ret)
		goto out;

	/* write the ring block whose manifest entry references the log block */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	ring = buf;
	ring->hdr = hdr;
	ring->nr_entries = cpu_to_le16(2);
	ent = (void *)(ring + 1);
	ent->type = SCOUTFS_RING_ADD_MANIFEST;
	ent->len = cpu_to_le16(sizeof(*mani));
	mani = (void *)(ent + 1);
	mani->blkno = cpu_to_le64(blkno);
	mani->seq = hdr.seq;
	mani->level = 0;
	mani->first = root_key;
	mani->last = root_key;
	ent = (void *)(mani + 1);
	ent->type = SCOUTFS_RING_BITMAP;
	ent->len = cpu_to_le16(sizeof(*bm));
	bm = (void *)(ent + 1);
	memset(bm->bits, 0xff, sizeof(bm->bits));
	/* the first three blocks are allocated */
	bm->bits[0] = cpu_to_le64(~7ULL);
	bm->bits[1] = cpu_to_le64(~0ULL);

	blkno += SCOUTFS_BLOCKS_PER_CHUNK;
	ret = write_block(fd, blkno, &ring->hdr);
	if (ret)
		goto out;

	/* the ring has a single chunk for now */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	map = buf;
	map->hdr = hdr;
	map->nr_chunks = cpu_to_le32(1);
	map->blknos[0] = cpu_to_le64(blkno);

	blkno += SCOUTFS_BLOCKS_PER_CHUNK;
	ret = write_block(fd, blkno, &map->hdr);
	if (ret)
		goto out;

	/* write the two super blocks */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	super = buf;
	super->hdr = hdr;
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	uuid_generate(super->uuid);
	super->total_chunks = cpu_to_le64(total_chunks);
	super->ring_map_blkno = cpu_to_le64(blkno);
	super->ring_map_seq = hdr.seq;
	super->ring_first_block = cpu_to_le64(0);
	super->ring_active_blocks = cpu_to_le64(1);
	super->ring_total_blocks = cpu_to_le64(SCOUTFS_BLOCKS_PER_CHUNK);
	super->ring_seq = hdr.seq;

	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {
		super->hdr.seq = cpu_to_le64(i + 1);
		ret = write_block(fd, SCOUTFS_SUPER_BLKNO + i, &super->hdr);
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
	       "  chunk bytes: %u\n"
	       "  total chunks: %llu\n"
	       "  fsid: %llx\n"
	       "  uuid: %s\n",
		SCOUTFS_CHUNK_SIZE, total_chunks,
		le64_to_cpu(super->hdr.fsid), uuid_str);

	ret = 0;
out:
	free(buf);
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
