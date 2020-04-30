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
#include "bitops.h"
#include "radix.h"

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
 * Update a reference to a block of references that has been modified.  We
 * walk all the references and rebuild the ref tracking.
 */
static void update_parent_ref(struct scoutfs_radix_ref *ref,
			      struct scoutfs_radix_block *rdx)
{
	int i;

	ref->sm_total = cpu_to_le64(0);
	ref->lg_total = cpu_to_le64(0);

	rdx->sm_first = cpu_to_le32(SCOUTFS_RADIX_REFS);
	rdx->lg_first = cpu_to_le32(SCOUTFS_RADIX_REFS);

	for (i = 0; i < SCOUTFS_RADIX_REFS; i++) {
		if (le32_to_cpu(rdx->sm_first) == SCOUTFS_RADIX_REFS &&
		    rdx->refs[i].sm_total != 0)
			rdx->sm_first = cpu_to_le32(i);
		if (le32_to_cpu(rdx->lg_first) == SCOUTFS_RADIX_REFS &&
		    rdx->refs[i].lg_total != 0)
			rdx->lg_first = cpu_to_le32(i);

		le64_add_cpu(&ref->sm_total,
			     le64_to_cpu(rdx->refs[i].sm_total));
		le64_add_cpu(&ref->lg_total,
			     le64_to_cpu(rdx->refs[i].lg_total));
	}
}

/*
 * Initialize all the blocks in a path to a leaf with the given blocks
 * set.  We know that we're being called to set all the bits in a region
 * by setting the left and right partial leafs of the region.  We first
 * set the left and set full references down the left path, then we're
 * called on the right and set full to the left and clear full refs past
 * the right.
 *
 * The caller provides an array of block buffers and a starting block
 * number to allocate blocks from and reference blocks within.  It's the
 * world's dumbest block cache.
 */
static void set_radix_path(struct scoutfs_super_block *super, int *inds,
			   struct scoutfs_radix_ref *ref, int level, bool left,
			   void **blocks, u64 blkno_base, u64 *next_blkno,
			   u64 first, u64 last)
{
	struct scoutfs_radix_block *rdx;
	int lg_ind;
	int lg_after;
	u64 bno;
	int ind;
	int end;
	int i;

	if (ref->blkno == 0) {
		bno = (*next_blkno)++;
		ref->blkno = cpu_to_le64(bno);
		ref->seq = cpu_to_le64(1);
	}

	rdx = blocks[le64_to_cpu(ref->blkno) - blkno_base];

	if (level) {
		ind = inds[level];

		/* initialize empty parent blocks with empty refs */
		if (ref->sm_total == 0) {
			for (i = 0; i < SCOUTFS_RADIX_REFS; i++)
				radix_init_ref(&rdx->refs[i], level - 1, false);
		}

		if (left) {
			/* initialize full refs from left to end */
			for (i = ind + 1; i < SCOUTFS_RADIX_REFS; i++)
				radix_init_ref(&rdx->refs[i], level - 1, true);
		} else {
			/* initialize full refs from start or left to right */
			for (i = le32_to_cpu(rdx->sm_first) !=
							SCOUTFS_RADIX_REFS ?
				 le32_to_cpu(rdx->sm_first) + 1 : 0;
			     i < ind; i++)
				radix_init_ref(&rdx->refs[i], level - 1, true);

			/* wipe full refs from right (maybe including) to end */
			for (i = le64_to_cpu(rdx->refs[ind].blkno) == U64_MAX ?
				 ind : ind + 1; i < SCOUTFS_RADIX_REFS; i++)
				radix_init_ref(&rdx->refs[i], level - 1, false);
		}

		set_radix_path(super, inds, &rdx->refs[ind], level - 1, left,
			       blocks, blkno_base, next_blkno, first, last);
		update_parent_ref(ref, rdx);

	} else {
		ind = first - radix_calc_leaf_bit(first);
		end = last - radix_calc_leaf_bit(last);
		for (i = ind; i <= end; i++)
			set_bit_le(i, rdx->bits);

		rdx->sm_first = cpu_to_le32(ind);
		ref->sm_total = cpu_to_le64(end - ind + 1);

		lg_ind = round_up(ind, SCOUTFS_RADIX_LG_BITS);
		lg_after = round_down(end + 1, SCOUTFS_RADIX_LG_BITS);

		if (lg_ind < SCOUTFS_RADIX_BITS)
			rdx->lg_first = cpu_to_le32(lg_ind);
		else
			rdx->lg_first = cpu_to_le32(SCOUTFS_RADIX_BITS);
		ref->lg_total = cpu_to_le64(lg_after - lg_ind);
	}
}

/*
 * Initialize a new radix allocator with the region of bits set.  We
 * initialize and write populated blocks down the paths to the two ends
 * of the interval and write full refs in between.
 */
static int write_radix_blocks(struct scoutfs_super_block *super, int fd,
			      struct scoutfs_radix_root *root,
			      u64 blkno, u64 first, u64 last)
{
	struct scoutfs_radix_block *rdx;
	void **blocks;
	u64 next_blkno;
	u64 edge;
	u8 height;
	int alloced;
	int used;
	int *inds;
	int ret;
	int i;

	height = radix_height_from_last(last);
	inds = alloca(sizeof(inds[0]) * height);
	alloced = height * 2;
	next_blkno = blkno;

	/* allocate all the blocks we might need */
	blocks = calloc(alloced, sizeof(*blocks));
	if (!blocks)
		return -ENOMEM;

	for (i = 0; i < alloced; i++) {
		blocks[i] = calloc(1, SCOUTFS_BLOCK_SIZE);
		if (blocks[i] == NULL) {
			ret = -ENOMEM;
			goto out;
		}
	}

	/* initialize empty root ref */
	memset(root, 0, sizeof(struct scoutfs_radix_root));
	root->height = height;
	radix_init_ref(&root->ref, height - 1, false);

	edge = radix_calc_leaf_bit(first) + SCOUTFS_RADIX_BITS - 1;
	radix_calc_level_inds(inds, height, first);
	set_radix_path(super, inds, &root->ref, root->height - 1, true, blocks,
		       blkno, &next_blkno, first, min(edge, last));

	edge = radix_calc_leaf_bit(last);
	radix_calc_level_inds(inds, height, last);
	set_radix_path(super, inds, &root->ref, root->height - 1, false, blocks,
		       blkno, &next_blkno, max(first, edge), last);

	used = next_blkno - blkno;

	/* write out all the dirtied blocks */
	for (i = 0; i < used; i++) {
		rdx = blocks[i];
		rdx->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_RADIX);
		rdx->hdr.fsid = super->hdr.fsid;
		rdx->hdr.seq = cpu_to_le64(1);
		rdx->hdr.blkno = cpu_to_le64(blkno + i);
		rdx->hdr.crc = cpu_to_le32(crc_block(&rdx->hdr));
		ret = write_raw_block(fd, blkno + i, rdx);
		if (ret < 0)
			goto out;
	}

	ret = used;
out:
	if (blocks) {
		for (i = 0; i < alloced && blocks[i]; i++)
			free(blocks[i]);
		free(blocks);
	}

	return ret;
}

/*
 * Make a new file system by writing:
 *  - super blocks
 *  - btree ring blocks with manifest and allocator btree blocks
 *  - segment with root inode items
 */
static int write_new_fs(char *path, int fd, u8 quorum_count)
{
	struct scoutfs_super_block *super;
	struct scoutfs_inode *inode;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *btitem;
	struct scoutfs_key *key;
	struct timeval tv;
	char uuid_str[37];
	void *zeros;
	u64 blkno;
	u64 limit;
	u64 size;
	u64 total_blocks;
	u64 meta_alloc_blocks;
	u64 next_meta;
	u64 last_meta;
	u64 next_data;
	u64 last_data;
	int ret;
	int i;

	gettimeofday(&tv, NULL);

	super = calloc(1, SCOUTFS_BLOCK_SIZE);
	bt = calloc(1, SCOUTFS_BLOCK_SIZE);
	zeros = calloc(1, SCOUTFS_BLOCK_SIZE);
	if (!super || !bt || !zeros) {
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

	/* arbitrarily require a reasonably large device */
	limit = 8ULL * (1024 * 1024 * 1024);
	if (size < limit) {
		fprintf(stderr, "%llu byte device too small for min %llu byte fs\n",
			size, limit);
		goto out;
	}

	total_blocks = size / SCOUTFS_BLOCK_SIZE;
	/* metadata blocks start after the quorum blocks */
	next_meta = SCOUTFS_QUORUM_BLKNO + SCOUTFS_QUORUM_BLOCKS;
	/* data blocks are after metadata, we'll say 1:4 for now */
	next_data = round_up(next_meta + ((total_blocks - next_meta) / 5),
			     SCOUTFS_RADIX_BITS);
	last_meta = next_data - 1;
	last_data = total_blocks - 1;

	/* partially initialize the super so we can use it to init others */
	memset(super, 0, SCOUTFS_BLOCK_SIZE);
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_SUPER);
	super->hdr.seq = cpu_to_le64(1);
	super->format_hash = cpu_to_le64(SCOUTFS_FORMAT_HASH);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(SCOUTFS_ROOT_INO + 1);
	super->next_trans_seq = cpu_to_le64(1);
	super->total_meta_blocks = cpu_to_le64(last_meta + 1);
	super->first_meta_blkno = cpu_to_le64(next_meta);
	super->last_meta_blkno = cpu_to_le64(last_meta);
	super->total_data_blocks = cpu_to_le64(last_data - next_data + 1);
	super->first_data_blkno = cpu_to_le64(next_data);
	super->last_data_blkno = cpu_to_le64(last_data);
	super->quorum_count = quorum_count;

	/* fs root starts with root inode and its index items */
	blkno = next_meta++;

	super->fs_root.ref.blkno = cpu_to_le64(blkno);
	super->fs_root.ref.seq = cpu_to_le64(1);
	super->fs_root.height = 1;

	memset(bt, 0, SCOUTFS_BLOCK_SIZE);
	bt->hdr.fsid = super->hdr.fsid;
	bt->hdr.blkno = cpu_to_le64(blkno);
	bt->hdr.seq = cpu_to_le64(1);
	bt->nr_items = cpu_to_le32(2);

	/* btree item allocated from the back of the block */
	key = (void *)bt + SCOUTFS_BLOCK_SIZE - sizeof(*key);
	btitem = (void *)key - sizeof(*btitem);

	bt->item_hdrs[0].off = cpu_to_le32((long)btitem - (long)bt);
	btitem->val_len = cpu_to_le16(0);

	memset(key, 0, sizeof(*key));
	key->sk_zone = SCOUTFS_INODE_INDEX_ZONE;
	key->sk_type = SCOUTFS_INODE_INDEX_META_SEQ_TYPE;
	key->skii_ino = cpu_to_le64(SCOUTFS_ROOT_INO);

	inode = (void *)btitem - sizeof(*inode);
	key = (void *)inode - sizeof(*key);
	btitem = (void *)key - sizeof(*btitem);

	bt->item_hdrs[1].off = cpu_to_le32((long)btitem - (long)bt);
	btitem->val_len = cpu_to_le16(sizeof(*inode));

	memset(key, 0, sizeof(*key));
	key->sk_zone = SCOUTFS_FS_ZONE;
	key->ski_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	key->sk_type = SCOUTFS_INODE_TYPE;

	inode->next_readdir_pos = cpu_to_le64(2);
	inode->nlink = cpu_to_le32(SCOUTFS_DIRENT_FIRST_POS);
	inode->mode = cpu_to_le32(0755 | 0040000);
	inode->atime.sec = cpu_to_le64(tv.tv_sec);
	inode->atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode->ctime.sec = inode->atime.sec;
	inode->ctime.nsec = inode->atime.nsec;
	inode->mtime.sec = inode->atime.sec;
	inode->mtime.nsec = inode->atime.nsec;

	bt->free_end = bt->item_hdrs[le32_to_cpu(bt->nr_items) - 1].off;

	bt->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BTREE);
	bt->hdr.crc = cpu_to_le32(crc_block(&bt->hdr));

	ret = write_raw_block(fd, blkno, bt);
	if (ret)
		goto out;

	/* write out radix allocator blocks for data */
	ret = write_radix_blocks(super, fd, &super->core_data_avail, next_meta,
				 next_data, last_data);
	if (ret < 0)
		goto out;
	next_meta += ret;

	super->core_data_freed.height = super->core_data_avail.height;
	radix_init_ref(&super->core_data_freed.ref, 0, false);

	meta_alloc_blocks = radix_blocks_needed(next_meta, last_meta);

	/*
	 * Write out radix alloc blocks, knowing that the region we mark
	 * has to start after the blocks we store the allocator itself in.
	 */
	ret = write_radix_blocks(super, fd, &super->core_meta_avail,
				 next_meta, next_meta + meta_alloc_blocks,
				 last_meta);
	if (ret < 0)
		goto out;
	next_meta += ret;

	super->core_meta_freed.height = super->core_meta_avail.height;
	radix_init_ref(&super->core_meta_freed.ref, 0, false);

	/* zero out quorum blocks */
	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		ret = write_raw_block(fd, SCOUTFS_QUORUM_BLKNO + i, zeros);
		if (ret < 0) {
			fprintf(stderr, "error zeroing quorum block: %s (%d)\n",
				strerror(-errno), -errno);
			goto out;
		}
	}

	/* fill out allocator fields now that we've written our blocks */
	super->free_meta_blocks = cpu_to_le64(last_meta - next_meta + 1);
	super->free_data_blocks = cpu_to_le64(last_data - next_data + 1);

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
	       "  device path:          %s\n"
	       "  fsid:                 %llx\n"
	       "  format hash:          %llx\n"
	       "  uuid:                 %s\n"
	       "  device blocks:        "SIZE_FMT"\n"
	       "  metadata blocks:      "SIZE_FMT"\n"
	       "  data blocks:          "SIZE_FMT"\n"
	       "  quorum count:         %u\n",
		path,
		le64_to_cpu(super->hdr.fsid),
		le64_to_cpu(super->format_hash),
		uuid_str,
		SIZE_ARGS(total_blocks, SCOUTFS_BLOCK_SIZE),
		SIZE_ARGS(le64_to_cpu(super->total_meta_blocks),
			  SCOUTFS_BLOCK_SIZE),
		SIZE_ARGS(le64_to_cpu(super->total_data_blocks),
			  SCOUTFS_BLOCK_SIZE),
		super->quorum_count);

	ret = 0;
out:
	if (super)
		free(super);
	if (bt)
		free(bt);
	if (zeros)
		free(zeros);
	return ret;
}

static struct option long_ops[] = {
	{ "quorum_count", 1, NULL, 'Q' },
	{ NULL, 0, NULL, 0}
};

static int mkfs_func(int argc, char *argv[])
{
	unsigned long long ull;
	char *path = argv[1];
	u8 quorum_count = 0;
	char *end = NULL;
	int ret;
	int fd;
	int c;

	while ((c = getopt_long(argc, argv, "Q:", long_ops, NULL)) != -1) {
		switch (c) {
		case 'Q':
			ull = strtoull(optarg, &end, 0);
			if (*end != '\0' || ull == 0 ||
			    ull > SCOUTFS_QUORUM_MAX_COUNT) {
				printf("scoutfs: invalid quorum count '%s'\n",
					optarg);
				return -EINVAL;
			}
			quorum_count = ull;
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

	if (!quorum_count) {
		printf("provide quorum count with --quorum_count|-Q option\n");
		return -EINVAL;
	}

	fd = open(path, O_RDWR | O_EXCL);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	ret = write_new_fs(path, fd, quorum_count);
	close(fd);

	return ret;
}

static void __attribute__((constructor)) mkfs_ctor(void)
{
	cmd_register("mkfs", "<path>", "write a new file system", mkfs_func);

	/* for lack of some other place to put these.. */
	build_assert(sizeof(uuid_t) == SCOUTFS_UUID_BYTES);
}
