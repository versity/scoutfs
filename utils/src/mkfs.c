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
 * Make a new file system by writing:
 *  - super blocks
 *  - btree ring blocks with manifest and allocator btree blocks
 *  - segment with root inode items
 */
static int write_new_fs(char *path, int fd, u8 quorum_count)
{
	struct scoutfs_super_block *super;
	struct scoutfs_key_be *kbe;
	struct scoutfs_inode *inode;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *btitem;
	struct scoutfs_balloc_item_key *bik;
	struct scoutfs_balloc_item_val *biv;
	struct scoutfs_key key;
	struct timeval tv;
	char uuid_str[37];
	void *zeros;
	u64 blkno;
	u64 limit;
	u64 size;
	u64 total_blocks;
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
	super->quorum_count = quorum_count;

	/* metadata blocks start after the quorum blocks */
	next_meta = SCOUTFS_QUORUM_BLKNO + SCOUTFS_QUORUM_BLOCKS;

	/* data blocks are after metadata, we'll say 1:4 for now */
	next_data = round_up(next_meta + ((total_blocks - next_meta) / 5),
			     SCOUTFS_BLOCK_BITMAP_BITS);
	last_meta = next_data - 1;
	last_data = total_blocks - 1;

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
	kbe = (void *)bt + SCOUTFS_BLOCK_SIZE - sizeof(*kbe);
	btitem = (void *)kbe - sizeof(*btitem);

	bt->item_hdrs[0].off = cpu_to_le32((long)btitem - (long)bt);
	btitem->key_len = cpu_to_le16(sizeof(*kbe));
	btitem->val_len = cpu_to_le16(0);

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_INODE_INDEX_ZONE;
	key.sk_type = SCOUTFS_INODE_INDEX_META_SEQ_TYPE;
	key.skii_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	scoutfs_key_to_be(kbe, &key);

	inode = (void *)btitem - sizeof(*inode);
	kbe = (void *)inode - sizeof(*kbe);
	btitem = (void *)kbe - sizeof(*btitem);

	bt->item_hdrs[1].off = cpu_to_le32((long)btitem - (long)bt);
	btitem->key_len = cpu_to_le16(sizeof(*kbe));
	btitem->val_len = cpu_to_le16(sizeof(*inode));

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_FS_ZONE;
	key.ski_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	key.sk_type = SCOUTFS_INODE_TYPE;
	scoutfs_key_to_be(kbe, &key);

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

	/* metadata block allocator has single item, server continues init */
	blkno = next_meta++;

	super->core_balloc_alloc.root.ref.blkno = cpu_to_le64(blkno);
	super->core_balloc_alloc.root.ref.seq = cpu_to_le64(1);
	super->core_balloc_alloc.root.height = 1;

	/* XXX magic */

	memset(bt, 0, SCOUTFS_BLOCK_SIZE);
	bt->hdr.fsid = super->hdr.fsid;
	bt->hdr.blkno = cpu_to_le64(blkno);
	bt->hdr.seq = cpu_to_le64(1);
	bt->nr_items = cpu_to_le32(1);

	/* btree item allocated from the back of the block */
	biv = (void *)bt + SCOUTFS_BLOCK_SIZE - sizeof(*biv);
	bik = (void *)biv - sizeof(*bik);
	btitem = (void *)bik - sizeof(*btitem);

	bt->item_hdrs[0].off = cpu_to_le32((long)btitem - (long)bt);
	btitem->key_len = cpu_to_le16(sizeof(*bik));
	btitem->val_len = cpu_to_le16(sizeof(*biv));

	bik->base = cpu_to_be64(0); /* XXX true? */

	/* set all the bits past our final used blkno */
	super->core_balloc_free.total_free =
			cpu_to_le64(SCOUTFS_BALLOC_ITEM_BITS - next_meta);
	for (i = next_meta; i < SCOUTFS_BALLOC_ITEM_BITS; i++)
		set_bit_le(i, &biv->bits);
	next_meta = i;

	bt->free_end = bt->item_hdrs[le32_to_cpu(bt->nr_items) - 1].off;

	bt->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_BTREE);
	bt->hdr.crc = cpu_to_le32(crc_block(&bt->hdr));

	ret = write_raw_block(fd, blkno, bt);
	if (ret)
		goto out;

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
	super->next_uninit_meta_blkno = cpu_to_le64(next_meta);
	super->last_uninit_meta_blkno = cpu_to_le64(last_meta);
	super->next_uninit_data_blkno = cpu_to_le64(next_data);
	super->last_uninit_data_blkno = cpu_to_le64(last_data);
	super->free_blocks = cpu_to_le64(total_blocks - next_meta);

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
		SIZE_ARGS(last_meta - next_meta + 1,
			  SCOUTFS_BLOCK_SIZE),
		SIZE_ARGS(last_data - next_data + 1,
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
