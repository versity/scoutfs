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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <argp.h>

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
#include "blkid.h"
#include "quorum.h"


/*
 * Return the order of the length of a free extent, which we define as
 * floor(log_8_(len)): 0..7 = 0, 8..63 = 1, etc.
 */
static u64 free_extent_order(u64 len)
{
	return (flsll(len | 1) - 1) / 3;
}

/*
 * Write the single btree block that contains the blkno and len indexed
 * items to store the given extent, and update the root to point to it.
 */
static int write_alloc_root(int fd, __le64 fsid,
			    struct scoutfs_alloc_root *root,
			    struct scoutfs_btree_block *bt,
			    u64 seq, u64 blkno, u64 start, u64 len)
{
	struct scoutfs_key key;

	btree_init_root_single(&root->root, bt, seq, blkno);
	root->total_len = cpu_to_le64(len);

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_FREE_EXTENT_BLKNO_ZONE;
	key.skfb_end = cpu_to_le64(start + len - 1);
	key.skfb_len = cpu_to_le64(len);
	btree_append_item(bt, &key, NULL, 0);

	memset(&key, 0, sizeof(key));
	key.sk_zone = SCOUTFS_FREE_EXTENT_ORDER_ZONE;
	key.skfo_revord = cpu_to_le64(U64_MAX - free_extent_order(len));
	key.skfo_end = cpu_to_le64(start + len - 1);
	key.skfo_len = cpu_to_le64(len);
	btree_append_item(bt, &key, NULL, 0);

	return write_block(fd, SCOUTFS_BLOCK_MAGIC_BTREE, fsid, seq, blkno,
			   SCOUTFS_BLOCK_LG_SHIFT, &bt->hdr);
}

#define SCOUTFS_SERVER_DATA_FILL_TARGET \
	((4ULL * 1024 * 1024 * 1024) >> SCOUTFS_BLOCK_SM_SHIFT)
static bool invalid_data_alloc_zone_blocks(u64 total_data_blocks, u64 zone_blocks)
{
	u64 nr;

	if (zone_blocks == 0)
		return false;

	if (zone_blocks < SCOUTFS_SERVER_DATA_FILL_TARGET) {
		fprintf(stderr, "setting data_alloc_zone_blocks to '%llu' failed, must be at least %llu mount data allocation target blocks",
		        zone_blocks, SCOUTFS_SERVER_DATA_FILL_TARGET);
		return true;
	}

	nr = total_data_blocks / SCOUTFS_DATA_ALLOC_MAX_ZONES;
	if (zone_blocks < nr) {
		fprintf(stderr, "setting data_alloc_zone_blocks to '%llu' failed, must be greater than %llu blocks which results in max %u zones",
			    zone_blocks, nr, SCOUTFS_DATA_ALLOC_MAX_ZONES);
		return true;
	}

	if (zone_blocks > total_data_blocks) {
		fprintf(stderr, "setting data_alloc_zone_blocks to '%llu' failed, must be at most %llu total data device blocks",
			    zone_blocks, total_data_blocks);
		return true;
	}

	return false;
}

struct mkfs_args {
	char *meta_device;
	char *data_device;
	unsigned long long max_meta_size;
	unsigned long long max_data_size;
	u64 data_alloc_zone_blocks;
	u64 fmt_vers;
	bool force;
	bool allow_small_size;
	int nr_slots;
	struct scoutfs_quorum_slot slots[SCOUTFS_QUORUM_MAX_SLOTS];
};

/*
 * Make a new file system by writing:
 *  - super blocks
 *  - btree ring blocks with manifest and allocator btree blocks
 *  - segment with root inode items
 *
 * Superblock is written to both metadata and data devices, everything else is
 * written only to the metadata device.
 */
static int do_mkfs(struct mkfs_args *args)
{
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_inode inode;
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_btree_block *bt = NULL;
	struct scoutfs_block_header *hdr;
	struct scoutfs_key key;
	struct timeval tv;
	int meta_fd = -1;
	int data_fd = -1;
	char uuid_str[37];
	void *zeros = NULL;
	u64 blkno;
	u64 meta_size;
	u64 data_size;
	u64 next_meta;
	u64 last_meta;
	u64 first_data;
	u64 last_data;
	u64 meta_start;
	u64 meta_len;
	__le64 fsid;
	int ret;
	int i;

	gettimeofday(&tv, NULL);
	pseudo_random_bytes(&fsid, sizeof(fsid));

	meta_fd = open(args->meta_device, O_RDWR | O_EXCL);
	if (meta_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->meta_device, strerror(errno), errno);
		goto out;
	}
	if (!args->force) {
		ret = check_bdev(meta_fd, args->meta_device, "meta");
		if (ret)
			return ret;
	}

	data_fd = open(args->data_device, O_RDWR | O_EXCL);
	if (data_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->data_device, strerror(errno), errno);
		goto out;
	}
	if (!args->force) {
		ret = check_bdev(data_fd, args->data_device, "data");
		if (ret)
			return ret;
	}


	super = calloc(1, SCOUTFS_BLOCK_SM_SIZE);
	bt = calloc(1, SCOUTFS_BLOCK_LG_SIZE);
	zeros = calloc(1, SCOUTFS_BLOCK_SM_SIZE);
	if (!super || !bt || !zeros) {
		ret = -errno;
		fprintf(stderr, "failed to allocate block mem: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	/* minumum meta device size to make reserved blocks reasonably large */
	ret = device_size(args->meta_device, meta_fd, 64ULL * (1024 * 1024 * 1024),
			  args->max_meta_size, args->allow_small_size, "meta", &meta_size);
	if (ret)
		goto out;

	/* .. then arbitrarily the same minimum data device size */
	ret = device_size(args->data_device, data_fd, 64ULL * (1024 * 1024 * 1024),
			  args->max_data_size, args->allow_small_size, "data", &data_size);
	if (ret)
		goto out;

	next_meta = SCOUTFS_META_DEV_START_BLKNO;
	last_meta = (meta_size >> SCOUTFS_BLOCK_LG_SHIFT) - 1;
	/* Data blocks go on the data dev */
	first_data = SCOUTFS_DATA_DEV_START_BLKNO;
	last_data = (data_size >> SCOUTFS_BLOCK_SM_SHIFT) - 1;

	/* partially initialize the super so we can use it to init others */
	memset(super, 0, SCOUTFS_BLOCK_SM_SIZE);
	super->fmt_vers = cpu_to_le64(args->fmt_vers);
	uuid_generate(super->uuid);
	super->next_ino = cpu_to_le64(round_up(SCOUTFS_ROOT_INO + 1, SCOUTFS_LOCK_INODE_GROUP_NR));
	super->inode_count = cpu_to_le64(1);
	super->seq = cpu_to_le64(1);
	super->total_meta_blocks = cpu_to_le64(last_meta + 1);
	super->total_data_blocks = cpu_to_le64(last_data + 1);

	assert(sizeof(args->slots) ==
		     member_sizeof(struct scoutfs_super_block, qconf.slots));
	memcpy(super->qconf.slots, args->slots, sizeof(args->slots));

	if (invalid_data_alloc_zone_blocks(le64_to_cpu(super->total_data_blocks),
					   args->data_alloc_zone_blocks)) {
		ret = -EINVAL;
		goto out;
	}

	if (args->data_alloc_zone_blocks) {
		super->volopt.set_bits |= cpu_to_le64(SCOUTFS_VOLOPT_DATA_ALLOC_ZONE_BLOCKS_BIT);
		super->volopt.data_alloc_zone_blocks = cpu_to_le64(args->data_alloc_zone_blocks);
	}

	/* fs root starts with root inode and its index items */
	blkno = next_meta++;
	btree_init_root_single(&super->fs_root, bt, 1, blkno);

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

	ret = write_block(meta_fd, SCOUTFS_BLOCK_MAGIC_BTREE, fsid, 1, blkno,
			  SCOUTFS_BLOCK_LG_SHIFT, &bt->hdr);
	if (ret)
		goto out;

	/* fill an avail list block for the first server transaction */
	blkno = next_meta++;
	lblk = (void *)bt;
	memset(lblk, 0, SCOUTFS_BLOCK_LG_SIZE);

	meta_len = (64 * 1024 * 1024) >> SCOUTFS_BLOCK_LG_SHIFT;
	for (i = 0; i < meta_len; i++) {
		lblk->blknos[i] = cpu_to_le64(next_meta);
		next_meta++;
	}
	lblk->nr = cpu_to_le32(i);

	super->server_meta_avail[0].ref.blkno = cpu_to_le64(blkno);
	super->server_meta_avail[0].ref.seq = cpu_to_le64(1);
	super->server_meta_avail[0].total_nr = le32_to_le64(lblk->nr);
	super->server_meta_avail[0].first_nr = lblk->nr;

	ret = write_block(meta_fd, SCOUTFS_BLOCK_MAGIC_ALLOC_LIST, fsid, 1,
			  blkno, SCOUTFS_BLOCK_LG_SHIFT, &lblk->hdr);
	if (ret)
		goto out;

	/* the data allocator has a single extent */
	blkno = next_meta++;
	ret = write_alloc_root(meta_fd, fsid, &super->data_alloc, bt,
			       1, blkno, first_data,
			       last_data - first_data + 1);
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
		ret = write_alloc_root(meta_fd, fsid, &super->meta_alloc[i], bt,
				       1, blkno, meta_start,
				       min(meta_len,
					   last_meta - meta_start + 1));
		if (ret < 0)
			goto out;

		meta_start += meta_len;
	}

	/* zero out quorum blocks */
	hdr = zeros;
	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		ret = write_block(meta_fd, SCOUTFS_BLOCK_MAGIC_QUORUM, fsid,
				  1, SCOUTFS_QUORUM_BLKNO + i,
				  SCOUTFS_BLOCK_SM_SHIFT, hdr);
		if (ret < 0) {
			fprintf(stderr, "error zeroing quorum block: %s (%d)\n",
				strerror(-errno), -errno);
			goto out;
		}
	}

	/* write the super block to data dev and meta dev*/
	ret = write_block_sync(data_fd, SCOUTFS_BLOCK_MAGIC_SUPER, fsid, 1,
			       SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT,
			       &super->hdr);
	if (ret)
		goto out;

	super->flags |= cpu_to_le64(SCOUTFS_FLAG_IS_META_BDEV);
	ret = write_block_sync(meta_fd, SCOUTFS_BLOCK_MAGIC_SUPER, fsid,
			       1, SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT,
			       &super->hdr);
	if (ret)
		goto out;

	uuid_unparse(super->uuid, uuid_str);

	printf("Created scoutfs filesystem:\n"
	       "  meta device path:     %s\n"
	       "  data device path:     %s\n"
	       "  fsid:                 %llx\n"
	       "  uuid:                 %s\n"
	       "  format version:       %llu\n"
	       "  64KB metadata blocks: "SIZE_FMT"\n"
	       "  4KB data blocks:      "SIZE_FMT"\n"
	       "  quorum slots:         ",
		args->meta_device,
	        args->data_device,
		le64_to_cpu(super->hdr.fsid),
		uuid_str,
		le64_to_cpu(super->fmt_vers),
		SIZE_ARGS(le64_to_cpu(super->total_meta_blocks),
			  SCOUTFS_BLOCK_LG_SIZE),
		SIZE_ARGS(le64_to_cpu(super->total_data_blocks),
			  SCOUTFS_BLOCK_SM_SIZE));

	print_quorum_slots(super->qconf.slots, array_size(super->qconf.slots),
			   "                        ");

	ret = 0;
out:
	if (super)
		free(super);
	if (bt)
		free(bt);
	if (zeros)
		free(zeros);
	if (meta_fd != -1)
		close(meta_fd);
	if (data_fd != -1)
		close(data_fd);
	return ret;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct mkfs_args *args = state->input;
	struct scoutfs_quorum_slot slot;
	int ret;

	switch (key) {
	case 'Q':
		ret = parse_quorum_slot(&slot, arg);
		if (ret < 0)
			return ret;
		if (args->slots[ret].addr.v4.family != cpu_to_le16(SCOUTFS_AF_NONE))
			argp_error(state, "Quorum slot %u already specified before slot '%s'\n",
				   ret, arg);
		args->slots[ret] = slot;
		args->nr_slots++;
		break;
	case 'f':
		args->force = true;
		break;
	case 'm': /* max-meta-size */
	{
		u64 prev_val;
		ret = parse_human(arg, &args->max_meta_size);
		if (ret)
			return ret;
		prev_val = args->max_meta_size;
		args->max_meta_size = round_down(args->max_meta_size, SCOUTFS_BLOCK_LG_SIZE);
		if (args->max_meta_size != prev_val)
			fprintf(stderr, "Meta dev size %llu rounded down to %llu bytes\n",
				prev_val, args->max_meta_size);
		break;
	}
	case 'd': /* max-data-size */
	{
		u64 prev_val;
		ret = parse_human(arg, &args->max_data_size);
		if (ret)
			return ret;
		prev_val = args->max_data_size;
		args->max_data_size = round_down(args->max_data_size, SCOUTFS_BLOCK_SM_SIZE);
		if (args->max_data_size != prev_val)
			fprintf(stderr, "Data dev size %llu rounded down to %llu bytes\n",
				prev_val, args->max_data_size);
		break;
	}
	case 'A':
		args->allow_small_size = true;
		break;
	case 'V':
		ret = parse_u64(arg, &args->fmt_vers);
		if (ret)
			return ret;
		if (args->fmt_vers < SCOUTFS_FORMAT_VERSION_MIN ||
		    args->fmt_vers > SCOUTFS_FORMAT_VERSION_MAX)
			argp_error(state, "format-version %llu is outside supported range of %u-%u",
				   args->fmt_vers, SCOUTFS_FORMAT_VERSION_MIN,
				   SCOUTFS_FORMAT_VERSION_MAX);
		break;
	case 'z': /* data-alloc-zone-blocks */
	{
		ret = parse_u64(arg, &args->data_alloc_zone_blocks);
		if (ret)
			return ret;

		if (args->data_alloc_zone_blocks == 0)
			argp_error(state, "must provide non-zero data-alloc-zone-blocks");

		break;
	}
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else if (!args->data_device)
			args->data_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two arguments given");
		break;
	case ARGP_KEY_FINI:
		if (!args->nr_slots)
			argp_error(state, "must specify at least one quorum slot with --quorum-slot|-Q");
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		if (!args->data_device)
			argp_error(state, "no data device argument given");
		if (!valid_quorum_slots(args->slots))
			argp_error(state, "invalid quorum slot configuration");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "quorum-slot", 'Q', "NR,ADDR,PORT", 0, "Specify quorum slot addresses [Required]"},
	{ "force", 'f', NULL, 0, "Overwrite existing data on block devices"},
	{ "allow-small-size", 'A', NULL, 0, "Allow specified meta/data devices less than minimum, still warns"},
	{ "max-meta-size", 'm', "SIZE", 0, "Use a size less than the base metadata device size (bytes or KMGTP units)"},
	{ "max-data-size", 'd', "SIZE", 0, "Use a size less than the base data device size (bytes or KMGTP units)"},
	{ "data-alloc-zone-blocks", 'z', "BLOCKS", 0, "Divide data device into block zones so each mounts writes to a zone (4KB blocks)"},
	{ "format-version", 'V', "version", 0, "Specify a format version within supported range, ("SCOUTFS_FORMAT_VERSION_MIN_STR"-"SCOUTFS_FORMAT_VERSION_MAX_STR", default "SCOUTFS_FORMAT_VERSION_MAX_STR")"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"META-DEVICE DATA-DEVICE",
	"Initialize a new ScoutFS filesystem"
};

static int mkfs_cmd(int argc, char *argv[])
{
	struct mkfs_args mkfs_args = {
		.fmt_vers = SCOUTFS_FORMAT_VERSION_MAX,
	};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &mkfs_args);
	if (ret)
		return ret;

	return do_mkfs(&mkfs_args);
}

static void __attribute__((constructor)) mkfs_ctor(void)
{
	cmd_register_argp("mkfs", &argp, GROUP_CORE, mkfs_cmd);

	/* for lack of some other place to put these.. */
	build_assert(sizeof(uuid_t) == SCOUTFS_UUID_BYTES);
}
