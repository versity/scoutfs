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

static u64 first_blkno(struct scoutfs_super_block *super)
{
	return SCOUTFS_BUDDY_BLKNO + le64_to_cpu(super->buddy_blocks);
}

static u64 last_blkno(struct scoutfs_super_block *super)
{
	return le64_to_cpu(super->total_blocks) - 1;
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

static void set_order_nr(struct scoutfs_buddy_block *bud, int order, u16 nr)
{
	u16 first = le16_to_cpu(bud->first_set[order]);

	if (nr <= first)
		bud->first_set[order] = cpu_to_le16(nr);
}

static void clear_order_nr(struct scoutfs_buddy_block *bud, int order, u16 nr)
{
	u16 first = le16_to_cpu(bud->first_set[order]);
	int size;
	int i;

	if (nr != first)
		return;

	if (bud->level) {
		for (i = nr + 1; i < SCOUTFS_BUDDY_SLOTS; i++) {
			if (le16_to_cpu(bud->slots[i].free_orders) &
			    (1 << order))
				break;
		}
		if (i == SCOUTFS_BUDDY_SLOTS)
			i = U16_MAX;

	} else {
		size = order_off(order + 1);
		i = find_next_bit_le(bud->bits, size,
				       order_nr(order, first) + 1);
		if (i >= size)
			i = U16_MAX;
		else
			i -= order_off(order);
	}

	bud->first_set[order] = cpu_to_le16(i);
}

#define for_each_changed_bit(nr, bit, old, new, tmp)		\
	for (tmp = old ^ new;					\
	     tmp && (nr = ffs(tmp) - 1, bit = 1 << nr, 1);	\
	     tmp ^= bit)

/*
 * Set a slot's free_orders value and update first_set for each order
 * that it changes.  Returns true of the slot's free_orders was changed.
 */
static int set_slot_free_orders(struct scoutfs_buddy_block *bud, u16 sl,
				 u16 free_orders)
{
	u16 old = le16_to_cpu(bud->slots[sl].free_orders);
	int order;
	int tmp;
	int bit;

	if (old == free_orders)
		return 0;

	for_each_changed_bit(order, bit, old, free_orders, tmp) {
		if (old & bit)
			clear_order_nr(bud, order, sl);
		else
			set_order_nr(bud, order, sl);
	}

	bud->slots[sl].free_orders = cpu_to_le16(free_orders);
	return 1;
}

static int test_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	return test_bit_le(order_nr(order, nr), bud->bits);
}

static void set_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (!test_and_set_bit_le(order_nr(order, nr), bud->bits))
		set_order_nr(bud, order, nr);
}

static void clear_buddy_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	if (test_and_clear_bit_le(order_nr(order, nr), bud->bits))
		clear_order_nr(bud, order, nr);
}

/* merge lower orders buddies as we free up to the highest */
static void free_order_bit(struct scoutfs_buddy_block *bud, int order, int nr)
{
	int i;

	for (i = order; i < SCOUTFS_BUDDY_ORDERS - 2; i++) {

		if (!test_buddy_bit(bud, i, nr ^ 1))
			break;

		clear_buddy_bit(bud, i, nr ^ 1);
		nr >>= 1;
	}

	set_buddy_bit(bud, i, nr);
}

static u16 calc_free_orders(struct scoutfs_buddy_block *bud)
{
	u16 free = 0;
	int i;

	for (i = 0; i < SCOUTFS_BUDDY_ORDERS; i++)
		if (le16_to_cpu(bud->first_set[i]) != U16_MAX)
			free |= 1 << i;

	return free;
}

static void init_buddy_block(struct scoutfs_buddy_block *bud, int level)
{
	int i;

	memset(bud, 0, SCOUTFS_BLOCK_SIZE);
	for (i = 0; i < array_size(bud->first_set); i++)
		bud->first_set[i] = cpu_to_le16(U16_MAX);
	bud->level = level;
}

/*
 * Write either the left-most or right-most buddy bitmap leaf in the
 * allocator and then ascend writing parent blocks to the root.
 *
 * If we're writing the left leaf then blk is the first free blk.  If
 * we're writing the right leaf then blk is the last usable blk.
 *
 * If we're writing the left leaf then we don't actually write the root
 * block.  We record the free_orders for the first child block from the
 * root block.  When we write the right leaf we'll ascend into the root
 * block and initialize the free_order of the first slot for the path to
 * the left leaf.
 *
 * We initialize free_orders in all the unused slots so that the kernel
 * can try to descend in to them when searching by size and will
 * initialize new full blocks blocks.
 */
static int write_buddy_blocks(int fd, struct scoutfs_super_block *super,
			      struct buddy_info *binf,
			      struct scoutfs_buddy_block *bud, u64 blk,
			      int left, u16 *free_orders)
{
	u64 blkno;
	int level;
	int first;
	int last;
	int ret;
	u16 free;
	u16 full;
	int sl;
	int i;

	if (left) {
		first = blk;
		last = SCOUTFS_BUDDY_ORDER0_BITS - 1;
	} else {
		first = 0;
		last = min(blk % SCOUTFS_BUDDY_ORDER0_BITS,
			   SCOUTFS_BUDDY_ORDER0_BITS);
	}

	/* write the leaf block */
	level = 0;
	init_buddy_block(bud, level);
	for (i = first; i <= last; i++)
		free_order_bit(bud, 0, i);

	blk = blk / SCOUTFS_BUDDY_ORDER0_BITS;
	blkno = binf->blknos[level] + (blk * 2);

	ret = write_block(fd, blkno, super, &bud->hdr);
	if (ret)
		return ret;

	free = calc_free_orders(bud);
	full = SCOUTFS_BUDDY_ORDER0_BITS;

	/* write parents, stopping before root if left */
	while (++level < (left ? binf->height - 1 : binf->height)) {

		sl = blk % SCOUTFS_BUDDY_SLOTS;
		blk = blk / SCOUTFS_BUDDY_SLOTS;
		blkno = binf->blknos[level] + (blk * 2);

		init_buddy_block(bud, level);

		/* set full until right spine, 0th in root from left */
		for (i = 0; i < sl; i++)
			set_slot_free_orders(bud, i, full);

		if (!left && level == (binf->height - 1)) {
			set_slot_free_orders(bud, 0, *free_orders);
			bud->slots[0].seq = super->hdr.seq;
		}

		set_slot_free_orders(bud, sl, free);
		bud->slots[sl].seq = super->hdr.seq;

		/* init full slots in full parents down the left spine */
		for (i = sl; left && i < SCOUTFS_BUDDY_SLOTS; i++)
			set_slot_free_orders(bud, i, full);

		ret = write_block(fd, blkno, super, &bud->hdr);
		if (ret)
			return ret;

		free = calc_free_orders(bud);
	}

	*free_orders = free;

	return 0;
}

static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_inode *inode;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *item;
	struct scoutfs_key root_key;
	struct buddy_info binf;
	struct timeval tv;
	char uuid_str[37];
	unsigned int i;
	u64 limit;
	u64 size;
	u64 blkno;
	u64 count;
	u64 total_blocks;
	u16 free_orders;
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

	buddy_init(&binf, total_blocks);

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
	super->buddy_blocks = cpu_to_le64(binf.buddy_blocks);

	/* require space for two leaf blocks for writing left/right paths */
	count = last_blkno(super) - first_blkno(super) + 1;
	limit = (SCOUTFS_BUDDY_ORDER0_BITS * 2);
	if (count < limit) {
		fprintf(stderr, "%llu byte device only has room for %llu %u byte fs blocks, needs at least %llu fs blocks\n",
			size, count, SCOUTFS_BLOCK_SIZE, limit);
		goto out;
	}

	blkno = first_blkno(super);

	/* write a btree leaf root inode item */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	bt = buf;
	bt->nr_items = cpu_to_le16(1);
	bt->free_end = cpu_to_le16(SCOUTFS_BLOCK_SIZE - sizeof(*item) -
				   sizeof(*inode));
	bt->free_reclaim = 0;
	bt->item_offs[0] = bt->free_end;

	item = (void *)bt + le16_to_cpu(bt->free_end);
	item->seq = cpu_to_le64(1);
	item->key = root_key;
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

	ret = write_block(fd, blkno, super, &bt->hdr);
	if (ret)
		goto out;
	/* blkno is now first free */
	blkno++;

	/* the super references the btree block */
	super->btree_root.height = 1;
	super->btree_root.ref.blkno = bt->hdr.blkno;
	super->btree_root.ref.seq = bt->hdr.seq;

	/* free_blocks reflects the fs blocks, not buddy blocks */
	super->free_blocks = cpu_to_le64(total_blocks - blkno);

	/* write left-most buddy block and all full parents, not root */
	ret = write_buddy_blocks(fd, super, &binf, buf, 0, 1, &free_orders);
	if (ret)
		goto out;

	/* write right-most buddy and parents and the root */
	ret = write_buddy_blocks(fd, super, &binf, buf,
				 last_blkno(super) - first_blkno(super),
				 0, &free_orders);
	if (ret)
		goto out;

	/* the super references the buddy leaf block */
	super->buddy_root.height = binf.height;
	super->buddy_root.slot.seq = super->hdr.seq;
	super->buddy_root.slot.free_orders = cpu_to_le16(free_orders);

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
		total_blocks, le64_to_cpu(super->buddy_blocks),
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
