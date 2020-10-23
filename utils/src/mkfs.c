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
#include "parse.h"
#include "crc.h"
#include "rand.h"
#include "dev.h"
#include "key.h"
#include "bitops.h"
#include "btree.h"
#include "leaf_item_hash.h"

static int write_raw_block(int fd, u64 blkno, int shift, void *blk)
{
	size_t size = 1ULL << shift;
	ssize_t ret;

	ret = pwrite(fd, blk, size, blkno << shift);
	if (ret != size) {
		fprintf(stderr, "write to blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		return -errno;
	}

	return 0;
}

/*
 * Update the block's header and write it out.
 */
static int write_block(int fd, u64 blkno, int shift,
		       struct scoutfs_super_block *super,
		       struct scoutfs_block_header *hdr)
{
	size_t size = 1ULL << shift;

	if (super)
		*hdr = super->hdr;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->crc = cpu_to_le32(crc_block(hdr, size));

	return write_raw_block(fd, blkno, shift, hdr);
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
 * Write the single btree block that contains the blkno and len indexed
 * items to store the given extent, and update the root to point to it.
 */
static int write_alloc_root(struct scoutfs_super_block *super, int fd,
			    struct scoutfs_alloc_root *root,
			    struct scoutfs_btree_block *bt,
			    u64 blkno, u64 start, u64 len)
{
	struct scoutfs_key key;

	btree_init_root_single(&root->root, bt, blkno, 1, super->hdr.fsid);
	root->total_len = cpu_to_le64(len);

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_FREE_EXTENT_ZONE;
	key.sk_type = SCOUTFS_FREE_EXTENT_BLKNO_TYPE;
	key.skii_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	key.skfb_end = cpu_to_le64(start + len - 1);
	key.skfb_len = cpu_to_le64(len);
	btree_append_item(bt, &key, NULL, 0);

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_FREE_EXTENT_ZONE;
	key.sk_type = SCOUTFS_FREE_EXTENT_LEN_TYPE;
	key.skii_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	key.skfl_neglen = cpu_to_le64(-len);
	key.skfl_blkno = cpu_to_le64(start);
	btree_append_item(bt, &key, NULL, 0);

	bt->hdr.crc = cpu_to_le32(crc_block(&bt->hdr,
					    SCOUTFS_BLOCK_LG_SIZE));

	return write_raw_block(fd, blkno, SCOUTFS_BLOCK_LG_SHIFT, bt);
}

/*
 * Make a new file system by writing:
 *  - super blocks
 *  - btree ring blocks with manifest and allocator btree blocks
 *  - segment with root inode items
 */
static int write_new_fs(char *path, int fd, u8 quorum_count, u64 dev_blocks)
{
	struct scoutfs_super_block *super;
	struct scoutfs_inode inode;
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_btree_block *bt;
	struct scoutfs_key key;
	struct timeval tv;
	char uuid_str[37];
	void *zeros;
	u64 blkno;
	u64 limit;
	u64 size;
	u64 next_meta;
	u64 last_meta;
	u64 first_data;
	u64 last_data;
	u64 meta_start;
	u64 meta_len;
	int ret;
	int i;

	gettimeofday(&tv, NULL);

	super = calloc(1, SCOUTFS_BLOCK_SM_SIZE);
	bt = calloc(1, SCOUTFS_BLOCK_LG_SIZE);
	zeros = calloc(1, SCOUTFS_BLOCK_SM_SIZE);
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

	if (dev_blocks > 0 && size < (dev_blocks << SCOUTFS_BLOCK_SM_SHIFT)) {
		fprintf(stderr, "device size limit %llu in 4KB blocks given with -S is greater than device byte size %llu\n",
			dev_blocks, size);
		ret = -EINVAL;
		goto out;
	}

	if (dev_blocks > 0 && size > (dev_blocks << SCOUTFS_BLOCK_SM_SHIFT))
		size = dev_blocks << SCOUTFS_BLOCK_SM_SHIFT;

	/* arbitrarily require a reasonably large device */
	limit = 8ULL * (1024 * 1024 * 1024);
	if (size < limit) {
		fprintf(stderr, "%llu byte device too small for min %llu byte fs\n",
			size, limit);
		ret = -EINVAL;
		goto out;
	}

	/* metadata blocks start after the quorum blocks */
	next_meta = (SCOUTFS_QUORUM_BLKNO + SCOUTFS_QUORUM_BLOCKS) >>
		    SCOUTFS_BLOCK_SM_LG_SHIFT;
	/* use about 1/5 of the device for metadata blocks */
	last_meta = next_meta + ((size / 5) >> SCOUTFS_BLOCK_LG_SHIFT);
	/* The rest of the device is data blocks */
	first_data = (last_meta + 1) << SCOUTFS_BLOCK_SM_LG_SHIFT;
	last_data = (size >> SCOUTFS_BLOCK_SM_SHIFT) - 1;

	/* partially initialize the super so we can use it to init others */
	memset(super, 0, SCOUTFS_BLOCK_SM_SIZE);
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
	super->total_data_blocks = cpu_to_le64(last_data - first_data + 1);
	super->first_data_blkno = cpu_to_le64(first_data);
	super->last_data_blkno = cpu_to_le64(last_data);
	super->quorum_count = quorum_count;

	/* fs root starts with root inode and its index items */
	blkno = next_meta++;
	btree_init_root_single(&super->fs_root, bt, blkno, 1, super->hdr.fsid);

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_INODE_INDEX_ZONE;
	key.sk_type = SCOUTFS_INODE_INDEX_META_SEQ_TYPE;
	key.skii_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	btree_append_item(bt, &key, NULL, 0);

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_FS_ZONE;
	key.ski_ino = cpu_to_le64(SCOUTFS_ROOT_INO);
	key.sk_type = SCOUTFS_INODE_TYPE;

	memset(&inode, 0, sizeof(inode));
	inode.next_readdir_pos = cpu_to_le64(2);
	inode.nlink = cpu_to_le32(SCOUTFS_DIRENT_FIRST_POS);
	inode.mode = cpu_to_le32(0755 | 0040000);
	inode.atime.sec = cpu_to_le64(tv.tv_sec);
	inode.atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode.ctime.sec = inode.atime.sec;
	inode.ctime.nsec = inode.atime.nsec;
	inode.mtime.sec = inode.atime.sec;
	inode.mtime.nsec = inode.atime.nsec;
	btree_append_item(bt, &key, &inode, sizeof(inode));

	bt->hdr.crc = cpu_to_le32(crc_block(&bt->hdr,
					    SCOUTFS_BLOCK_LG_SIZE));

	ret = write_raw_block(fd, blkno, SCOUTFS_BLOCK_LG_SHIFT, bt);
	if (ret)
		goto out;

	/* fill an avail list block for the first server transaction */
	blkno = next_meta++;
	lblk = (void *)bt;
	memset(lblk, 0, SCOUTFS_BLOCK_LG_SIZE);

	lblk->hdr.magic = cpu_to_le32(SCOUTFS_BLOCK_MAGIC_ALLOC_LIST);
	lblk->hdr.fsid = super->hdr.fsid;
	lblk->hdr.blkno = cpu_to_le64(blkno);
	lblk->hdr.seq = cpu_to_le64(1);

	meta_len = (64 * 1024 * 1024) >> SCOUTFS_BLOCK_LG_SHIFT;
	for (i = 0; i < meta_len; i++) {
		lblk->blknos[i] = cpu_to_le64(next_meta);
		next_meta++;
	}
	lblk->nr = cpu_to_le32(i);

	super->server_meta_avail[0].ref.blkno = lblk->hdr.blkno;
	super->server_meta_avail[0].ref.seq = lblk->hdr.seq;
	super->server_meta_avail[0].total_nr = le32_to_le64(lblk->nr);
	super->server_meta_avail[0].first_nr = lblk->nr;

	lblk->hdr.crc = cpu_to_le32(crc_block(&bt->hdr, SCOUTFS_BLOCK_LG_SIZE));
	ret = write_raw_block(fd, blkno, SCOUTFS_BLOCK_LG_SHIFT, lblk);
	if (ret)
		goto out;

	/* the data allocator has a single extent */
	blkno = next_meta++;
	ret = write_alloc_root(super, fd, &super->data_alloc, bt,
			       blkno, first_data,
			       le64_to_cpu(super->total_data_blocks));
	if (ret < 0)
		goto out;

	/*
	 * Initialize all the meta_alloc roots with an equal portion of
	 * the free metadata extents, excluding the blocks we're going
	 * to use for the allocators.
	 */
	meta_start = next_meta + array_size(super->meta_alloc);
	meta_len = DIV_ROUND_UP(last_meta - meta_start + 1,
			        array_size(super->meta_alloc));

	/* each meta alloc root contains a portion of free metadata extents */
	for (i = 0; i < array_size(super->meta_alloc); i++) {
		blkno = next_meta++;
		ret = write_alloc_root(super, fd, &super->meta_alloc[i], bt,
				       blkno, meta_start,
				       min(meta_len,
					   last_meta - meta_start + 1));
		if (ret < 0)
			goto out;

		meta_start += meta_len;
	}

	/* zero out quorum blocks */
	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		ret = write_raw_block(fd, SCOUTFS_QUORUM_BLKNO + i,
				      SCOUTFS_BLOCK_SM_SHIFT, zeros);
		if (ret < 0) {
			fprintf(stderr, "error zeroing quorum block: %s (%d)\n",
				strerror(-errno), -errno);
			goto out;
		}
	}

	/* fill out allocator fields now that we've written our blocks */
	super->free_meta_blocks = cpu_to_le64(last_meta - next_meta + 1);
	super->free_data_blocks = cpu_to_le64(last_data - first_data + 1);

	/* write the super block */
	super->hdr.seq = cpu_to_le64(1);
	ret = write_block(fd, SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT,
			  NULL, &super->hdr);
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
	       "  64KB metadata blocks: "SIZE_FMT"\n"
	       "  4KB data blocks:      "SIZE_FMT"\n"
	       "  quorum count:         %u\n",
		path,
		le64_to_cpu(super->hdr.fsid),
		le64_to_cpu(super->format_hash),
		uuid_str,
		SIZE_ARGS(le64_to_cpu(super->total_meta_blocks),
			  SCOUTFS_BLOCK_LG_SIZE),
		SIZE_ARGS(le64_to_cpu(super->total_data_blocks),
			  SCOUTFS_BLOCK_SM_SIZE),
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
	u64 dev_blocks = 0;
	char *end = NULL;
	int ret;
	int fd;
	int c;

	while ((c = getopt_long(argc, argv, "Q:S:", long_ops, NULL)) != -1) {
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
		case 'S':
			ret = parse_u64(optarg, &dev_blocks);
			if (ret < 0) {
				printf("scoutfs: invalid device blocks count '%s'\n",
					optarg);
				return ret;
			}
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

	ret = write_new_fs(path, fd, quorum_count, dev_blocks);
	close(fd);

	return ret;
}

static void __attribute__((constructor)) mkfs_ctor(void)
{
	cmd_register("mkfs", "<path>", "write a new file system", mkfs_func);

	/* for lack of some other place to put these.. */
	build_assert(sizeof(uuid_t) == SCOUTFS_UUID_BYTES);
}
