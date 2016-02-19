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


/*
 * Update the buffer's header and write it out.
 */
static int write_header(int fd, u64 nr, struct scoutfs_header *hdr, size_t size)
{
	off_t off = nr * size;
	ssize_t ret;

	hdr->nr = cpu_to_le64(nr);
	hdr->crc = cpu_to_le32(crc_header(hdr, size));

	ret = pwrite(fd, hdr, size, off);
	if (ret != size) {
		fprintf(stderr, "write at nr %llu (offset %llu, size %zu) returned %zd: %s (%d)\n",
			nr, (long long)off, size, ret, strerror(errno), errno);
		return -errno;
	}

	return 0;
}

static int write_brick(int fd, u64 nr, struct scoutfs_header *hdr)
{
	return write_header(fd, nr, hdr, SCOUTFS_BRICK_SIZE);
}

static int write_block(int fd, u64 nr, struct scoutfs_header *hdr)
{
	return write_header(fd, nr, hdr, SCOUTFS_BLOCK_SIZE);
}

/*
 * - config blocks that describe ring
 * - ring entries for lots of free blocks
 * - manifest that references single block
 * - block with inode
 */
/*
 * So what does mkfs really need to do?
 *
 *  - super blocks that describe ring log
 *  - ring log with free bitmap entries
 *  - ring log with manifest entries
 *  - single item block with root dir
 */
static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super *super;
	struct scoutfs_inode *inode;
	struct scoutfs_ring_layout *rlo;
	struct scoutfs_ring_brick *ring;
	struct scoutfs_ring_entry *ent;
	struct scoutfs_ring_add_manifest *mani;
	struct scoutfs_ring_bitmap *bm;
	struct scoutfs_lsm_block *lblk;
	struct scoutfs_item_header *ihdr;
	struct scoutfs_key root_key;
	struct timeval tv;
	char uuid_str[37];
	struct stat st;
	unsigned int i;
	u64 total_blocks;
	void *buf;
	int ret;

	gettimeofday(&tv, NULL);

	super = malloc(SCOUTFS_BRICK_SIZE);
	buf = malloc(SCOUTFS_BLOCK_SIZE);
	if (!super || !buf) {
		ret = -errno;
		fprintf(stderr, "failed to allocate a block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	if (fstat(fd, &st)) {
		ret = -errno;
		fprintf(stderr, "failed to stat '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	total_blocks = st.st_size >> SCOUTFS_BLOCK_SHIFT;

	root_key.inode = cpu_to_le64(SCOUTFS_ROOT_INO);
	root_key.type = SCOUTFS_INODE_KEY;
	root_key.offset = 0;

	/* initialize the super */
	memset(super, 0, sizeof(struct scoutfs_super));
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.seq = cpu_to_le64(1);
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	uuid_generate(super->uuid);
	super->total_blocks = cpu_to_le64(total_blocks);
	super->ring_layout_block = cpu_to_le64(1);
	super->ring_layout_seq = cpu_to_le64(1);
	super->last_ring_brick = cpu_to_le64(1);
	super->last_ring_seq = cpu_to_le64(1);
	super->last_block_seq = cpu_to_le64(1);

	/* the ring has a single block for now */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	rlo = buf;
	rlo->hdr.fsid = super->hdr.fsid;
	rlo->hdr.seq = super->ring_layout_seq;
	rlo->nr_blocks = cpu_to_le32(1);
	rlo->blocks[0] = cpu_to_le64(2);

	ret = write_block(fd, 1, &rlo->hdr);
	if (ret)
		goto out;

	/* log the root inode block manifest and free bitmap */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	ring = buf;
	ring->hdr.fsid = super->hdr.fsid;
	ring->hdr.seq = super->last_ring_seq;
	ring->nr_entries = cpu_to_le16(2);
	ent = (void *)(ring + 1);
	ent->type = SCOUTFS_RING_ADD_MANIFEST;
	ent->len = cpu_to_le16(sizeof(*mani));
	mani = (void *)(ent + 1);
	mani->block = cpu_to_le64(3);
	mani->seq = super->last_block_seq;
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

	ret = write_brick(fd, 2 << SCOUTFS_BLOCK_BRICK, &ring->hdr);
	if (ret)
		goto out;

	/* write a single lsm block with the root inode item */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	lblk = buf;
	lblk->hdr.fsid = super->hdr.fsid;
	lblk->hdr.seq = super->last_block_seq;
	lblk->first = root_key;
	lblk->last = root_key;
	lblk->nr_items = cpu_to_le32(1);
	/* XXX set bloom */
	ihdr = (void *)((char *)(lblk + 1) + SCOUTFS_BLOOM_FILTER_BYTES);
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

	ret = write_block(fd, 3, &ring->hdr);
	if (ret)
		goto out;

	/* write the two super bricks */
	for (i = 0; i < 2; i++) {
		super->hdr.seq = cpu_to_le64(i);
		ret = write_brick(fd, SCOUTFS_SUPER_BRICK + i, &super->hdr);
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
	       "  fsid: %llx\n"
	       "  uuid: %s\n",
		total_blocks, le64_to_cpu(super->hdr.fsid), uuid_str);

	ret = 0;
out:
	free(super);
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
