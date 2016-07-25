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
 * Calculate the number of buddy blocks that are needed to manage
 * allocation of a device with the given number of total blocks.
 *
 * We need a little bit of overhead to write each transaction's dirty
 * buddy blocks to free space.  We chose 16MB for now which is wild
 * overkill and should be dependent on the max transaction size.
 */
static u32 calc_buddy_blocks(u64 total_blocks)
{
	return DIV_ROUND_UP(total_blocks, SCOUTFS_BUDDY_ORDER0_BITS) +
		((16 * 1024 * 1024) / SCOUTFS_BLOCK_SIZE);
}

static u32 first_blkno(struct scoutfs_super_block *super)
{
	return SCOUTFS_BUDDY_BM_BLKNO + SCOUTFS_BUDDY_BM_NR + 
	       le32_to_cpu(super->buddy_blocks);
}

/* the starting bit offset in the block bitmap of an order's bitmap */
static int order_off(int order)
{
	if (order == 0)
		return 0;

	return (2 * SCOUTFS_BUDDY_ORDER0_BITS) -
	       (SCOUTFS_BUDDY_ORDER0_BITS / (1 << (order - 1)));
}

/* the bit offset in the block bitmap of an order's bit */
static int order_nr(int order, int nr)
{
	return order_off(order) + nr;
}

static int test_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	return test_bit_le(order_nr(order, nr), bud->bits);
}

static void set_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (!test_and_set_bit_le(order_nr(order, nr), bud->bits))
		le32_add_cpu(&bud->order_counts[order], 1);
}

static void clear_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (test_and_clear_bit_le(order_nr(order, nr), bud->bits))
		le32_add_cpu(&bud->order_counts[order], -1);
}

/* merge lower orders buddies as we free up to the highest */
static void free_order_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	int i;

	for (i = order; i < SCOUTFS_BUDDY_ORDERS - 1; i++) {

		if (!test_buddy_bit(bud, i, nr ^ 1))
			break;

		clear_buddy_bit(bud, i, nr ^ 1);
		nr >>= 1;
	}

	set_buddy_bit(bud, i, nr);
}

static u8 calc_free_orders(struct scoutfs_buddy_block *bud)
{
	u8 free = 0;
	int i;

	for (i = 0; i < SCOUTFS_BUDDY_ORDERS; i++)
		free |= (!!bud->order_counts[i]) << i;

	return free;
}

static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_inode *inode;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *item;
	struct scoutfs_buddy_block *bud;
	struct scoutfs_buddy_indirect *ind;
	struct scoutfs_bitmap_block *bm;
	struct scoutfs_key root_key;
	struct timeval tv;
	char uuid_str[37];
	unsigned int i;
	u64 size;
	u64 blkno;
	u64 total_blocks;
	u64 buddy_blocks;
	u8 free_orders;
	void *buf;
	int ret;

	gettimeofday(&tv, NULL);

	buf = malloc(SCOUTFS_BLOCK_SIZE);
	super = malloc(SCOUTFS_BLOCK_SIZE);
	if (!buf || !super) {
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

	/* the block limit is totally arbitrary */
	total_blocks = size / SCOUTFS_BLOCK_SIZE;
	if (total_blocks < 32) {
		fprintf(stderr, "%llu byte device only has room for %llu %u byte blocks, needs at least 32 blocks\n",
			size, total_blocks, SCOUTFS_BLOCK_SIZE);
		goto out;
	}
	buddy_blocks = calc_buddy_blocks(total_blocks);

	root_key.inode = cpu_to_le64(SCOUTFS_ROOT_INO);
	root_key.type = SCOUTFS_INODE_KEY;
	root_key.offset = 0;

	/* first initialize the super so we can use it to build structures */
	memset(super, 0, SCOUTFS_BLOCK_SIZE);
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.seq = cpu_to_le64(1);
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(SCOUTFS_ROOT_INO + 1);
	super->total_blocks = cpu_to_le64(total_blocks);
	super->buddy_blocks = cpu_to_le32(buddy_blocks);

	blkno = first_blkno(super);

	/* write a btree leaf root inode item */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	bt = buf;
	bt->nr_items = cpu_to_le16(1);

	item = (void *)(bt + 1);
	item->seq = cpu_to_le64(1);
	item->key = root_key;
	item->tnode.parent = 0;
	item->tnode.left = 0;
	item->tnode.right = 0;
	pseudo_random_bytes(&item->tnode.prio, sizeof(item->tnode.prio));
	item->val_len = cpu_to_le16(sizeof(struct scoutfs_inode));

	inode = (void *)(item + 1);
	inode->nlink = cpu_to_le32(2);
	inode->mode = cpu_to_le32(0755 | 0040000);
	inode->atime.sec = cpu_to_le64(tv.tv_sec);
	inode->atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode->ctime.sec = inode->atime.sec;
	inode->ctime.nsec = inode->atime.nsec;
	inode->mtime.sec = inode->atime.sec;
	inode->mtime.nsec = inode->atime.nsec;

	bt->treap.off = cpu_to_le16((char *)&item->tnode - (char *)&bt->treap);
	bt->total_free = cpu_to_le16(SCOUTFS_BLOCK_SIZE -
				     ((char *)(inode + 1) - (char *)bt));
	bt->tail_free = bt->total_free;

	ret = write_block(fd, blkno, super, &bt->hdr);
	if (ret)
		goto out;

	/* the super references the btree block */
	super->btree_root.height = 1;
	super->btree_root.ref.blkno = bt->hdr.blkno;
	super->btree_root.ref.seq = bt->hdr.seq;

	/* free all the blocks in the first buddy block after btree block */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	bud = buf;
	for (i = 1; i < min(total_blocks - first_blkno(super),
			    SCOUTFS_BUDDY_ORDER0_BITS); i++)
		free_order_bit(bud, 0, i);
	free_orders = calc_free_orders(bud);

	blkno = SCOUTFS_BUDDY_BM_BLKNO + SCOUTFS_BUDDY_BM_NR;
	ret = write_block(fd, blkno, super, &bud->hdr);
	if (ret)
		goto out;

	/* an indirect buddy block references the buddy bitmap block */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	ind = buf;
	for (i = 0; i < SCOUTFS_BUDDY_SLOTS; i++) {
		ind->slots[i].free_orders = 0;
		ind->slots[i].ref = (struct scoutfs_block_ref){0,};
	}
	ind->slots[0].free_orders = free_orders;
	ind->slots[0].ref.seq = super->hdr.seq;
	ind->slots[0].ref.blkno = cpu_to_le64(blkno);

	blkno++;
	ret = write_block(fd, blkno, super, &ind->hdr);
	if (ret)
		goto out;

	/* the super references the buddy indirect block */
	super->buddy_ind_ref.blkno = ind->hdr.blkno;
	super->buddy_ind_ref.seq = ind->hdr.seq;

	/* a bitmap block records the two used buddy blocks */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	bm = buf;
	memset(bm->bits, 0xff, SCOUTFS_BLOCK_SIZE -
	       offsetof(struct scoutfs_bitmap_block, bits));
	bm->bits[0] = cpu_to_le64(~0ULL << 2); /* two low order bits clear */

	ret = write_block(fd, SCOUTFS_BUDDY_BM_BLKNO, super, &bm->hdr);
	if (ret)
		goto out;

	/* the super references the buddy bitmap block */
	super->buddy_bm_ref.blkno = bm->hdr.blkno;
	super->buddy_bm_ref.seq = bm->hdr.seq;

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
	       "  buddy blocks: %llu\n"
	       "  fsid: %llx\n"
	       "  uuid: %s\n",
		total_blocks, buddy_blocks,
		le64_to_cpu(super->hdr.fsid), uuid_str);

	ret = 0;
out:
	if (super)
		free(super);
	if (buf)
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
