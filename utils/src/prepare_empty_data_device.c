#define _GNU_SOURCE /* O_DIRECT */
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

struct prepare_empty_data_dev_args {
	char *meta_device;
	char *data_device;
	bool check;
	bool force;
};

static int do_prepare_empty_data_dev(struct prepare_empty_data_dev_args *args)
{
	struct scoutfs_super_block *meta_super = NULL;
	struct scoutfs_super_block *data_super = NULL;
	char uuid_str[37];
	int meta_fd = -1;
	int data_fd = -1;
	u64 data_blocks;
	u64 data_size;
	u64 in_use;
	int ret;

	ret = posix_memalign((void **)&data_super, SCOUTFS_BLOCK_SM_SIZE, SCOUTFS_BLOCK_SM_SIZE);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "failed to allocate data super block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	meta_fd = open(args->meta_device, O_DIRECT | O_SYNC | O_RDONLY | O_EXCL);
	if (meta_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open meta device '%s': %s (%d)\n",
			args->meta_device, strerror(errno), errno);
		goto out;
	}

	ret = read_block_verify(meta_fd, SCOUTFS_BLOCK_MAGIC_SUPER, 0, SCOUTFS_SUPER_BLKNO,
				SCOUTFS_BLOCK_SM_SHIFT, (void **)&meta_super);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "failed to read meta super block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	if (!args->force) {
		ret = meta_super_in_use(meta_fd, meta_super);
		if (ret < 0) {
			if (ret == -EBUSY)
				fprintf(stderr, "The filesystem must be fully recovered and cleanly unmounted to determine if the data device is empty.\n");
			goto out;
		}

		in_use = (le64_to_cpu(meta_super->total_data_blocks) - SCOUTFS_DATA_DEV_START_BLKNO) -
			 le64_to_cpu(meta_super->data_alloc.total_len);
		if (in_use) {
			fprintf(stderr, "Data block allocator metadata shows "SIZE_FMT" data blocks used by files.  They must be removed, truncated, or released before a new empty data device can be used.\n",
			       SIZE_ARGS(in_use, SCOUTFS_BLOCK_SM_SIZE));
			ret = -EINVAL;
			goto out;
		}
	}

	if (args->data_device) {
		data_fd = open(args->data_device, O_DIRECT | O_EXCL |
						  (args->check ? O_RDONLY : O_RDWR | O_SYNC));
		if (data_fd < 0) {
			ret = -errno;
			fprintf(stderr, "failed to open data device '%s': %s (%d)\n",
				args->data_device, strerror(errno), errno);
			goto out;
		}

		ret = get_device_size(args->data_device, data_fd, &data_size);
		if (ret < 0)
			goto out;

		data_blocks = data_size >> SCOUTFS_BLOCK_SM_SHIFT;

		if (data_blocks < le64_to_cpu(meta_super->total_data_blocks)) {
			fprintf(stderr, "new data device %s of size "BASE_SIZE_FMT" has %llu 4KiB blocks, it needs at least "SIZE_FMT" blocks.\n",
			       args->data_device,
			       BASE_SIZE_ARGS(data_size),
			       data_blocks,
			       SIZE_ARGS(le64_to_cpu(meta_super->total_data_blocks),
					  SCOUTFS_BLOCK_SM_SIZE));
			ret = -EINVAL;
			goto out;
		}
	}

	if (args->check) {
		ret = 0;
		goto out;
	}

	/* the data device superblock only needs fs identifying fields */
	memset(data_super, 0, sizeof(struct scoutfs_super_block));
	data_super->id = meta_super->id;
	data_super->fmt_vers = meta_super->fmt_vers;
	data_super->flags = meta_super->flags &~ cpu_to_le64(SCOUTFS_FLAG_IS_META_BDEV);
	memcpy(data_super->uuid, meta_super->uuid,sizeof(data_super->uuid));
	data_super->seq = meta_super->seq;
	data_super->total_meta_blocks = meta_super->total_meta_blocks;
	data_super->total_data_blocks = meta_super->total_data_blocks;

	ret = write_block(data_fd, SCOUTFS_BLOCK_MAGIC_SUPER, meta_super->hdr.fsid, 1,
			  SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT, &data_super->hdr);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "Error writing super block to new data device '%s': %s (%d)\n",
			args->data_device, strerror(errno), errno);
		goto out;
	}

	uuid_unparse(meta_super->uuid, uuid_str);

	printf("Successfully initialized empty data device for scoutfs filesystem:\n"
	       "  meta device path:       %s\n"
	       "  data device path:       %s\n"
	       "  fsid:                   %llx\n"
	       "  uuid:                   %s\n"
	       "  format version:         %llu\n"
	       "  64KB metadata blocks:   "SIZE_FMT"\n"
	       "  4KB data blocks:        "SIZE_FMT"\n",
		args->meta_device,
	        args->data_device,
		le64_to_cpu(meta_super->hdr.fsid),
		uuid_str,
		le64_to_cpu(meta_super->fmt_vers),
		SIZE_ARGS(le64_to_cpu(meta_super->total_meta_blocks),
			  SCOUTFS_BLOCK_LG_SIZE),
		SIZE_ARGS(le64_to_cpu(meta_super->total_data_blocks),
			  SCOUTFS_BLOCK_SM_SIZE));

	ret = 0;
out:
	if (args->check) {
		if (ret == 0)
			printf("All checks passed.\n");
		else
			printf("Errors were found that must be addressed before a new empty data device could be prepared and used.\n");
	}

	if (meta_super)
		free(meta_super);
	if (data_super)
		free(data_super);
	if (meta_fd != -1)
		close(meta_fd);
	if (data_fd != -1)
		close(data_fd);
	return ret;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct prepare_empty_data_dev_args *args = state->input;

	switch (key) {
	case 'c':
		args->check = true;
		break;
	case 'f':
		args->force = true;
		break;
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else if (!args->data_device)
			args->data_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two device arguments given");
		break;
	case ARGP_KEY_FINI:
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		if (!args->data_device && !args->check)
			argp_error(state, "no data device argument given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "check", 'c', NULL, 0, "Only check for errors and do not write", },
	{ "force", 'f', NULL, 0, "Do not check that super is in use, nor if blocks are in use",},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"META-DEVICE DATA-DEVICE",
	"Prepare empty data device for use with an existing ScoutFS filesystem"
};

static int prepare_empty_data_dev_cmd(int argc, char *argv[])
{
	struct prepare_empty_data_dev_args prepare_empty_data_dev_args = { 
		.check = false,
		.force = false,
	};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &prepare_empty_data_dev_args);
	if (ret)
		return ret;

	return do_prepare_empty_data_dev(&prepare_empty_data_dev_args);
}

static void __attribute__((constructor)) prepare_empty_data_dev_ctor(void)
{
	cmd_register_argp("prepare-empty-data-device", &argp, GROUP_CORE,
			  prepare_empty_data_dev_cmd);
}
