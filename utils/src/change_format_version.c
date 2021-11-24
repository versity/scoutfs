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

struct change_fmt_vers_args {
	char *meta_device;
	char *data_device;
	u64 fmt_vers;
	bool offline;
};

static int do_change_fmt_vers(struct change_fmt_vers_args *args)
{
	struct scoutfs_super_block *meta_super = NULL;
	struct scoutfs_super_block *data_super = NULL;
	bool wrote_meta = false;
	char uuid_str[37];
	int meta_fd = -1;
	int data_fd = -1;
	int ret;

	meta_fd = open(args->meta_device, O_DIRECT | O_SYNC | O_RDWR | O_EXCL);
	if (meta_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open meta device '%s': %s (%d)\n",
			args->meta_device, strerror(errno), errno);
		goto out;
	}

	data_fd = open(args->data_device, O_DIRECT | O_SYNC | O_RDWR | O_EXCL);
	if (data_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open data device '%s': %s (%d)\n",
			args->data_device, strerror(errno), errno);
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

	ret = read_block_verify(data_fd, SCOUTFS_BLOCK_MAGIC_SUPER,
				le64_to_cpu(meta_super->hdr.fsid), SCOUTFS_SUPER_BLKNO,
				SCOUTFS_BLOCK_SM_SHIFT, (void **)&data_super);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "failed to read data super block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	if (le64_to_cpu(meta_super->fmt_vers) == args->fmt_vers &&
	    meta_super->fmt_vers == data_super->fmt_vers) {
		printf("both metadata and data device format version are already %llu, nothing to do.\n",
			args->fmt_vers);
		ret = 0;
		goto out;
	}

	if (le64_to_cpu(meta_super->fmt_vers) < SCOUTFS_FORMAT_VERSION_MIN ||
	    le64_to_cpu(meta_super->fmt_vers) > SCOUTFS_FORMAT_VERSION_MAX) {
		fprintf(stderr, "meta super block has format version %llu outside of supported version range %u-%u",
			    le64_to_cpu(meta_super->fmt_vers), SCOUTFS_FORMAT_VERSION_MIN,
			    SCOUTFS_FORMAT_VERSION_MAX);
		ret = -EINVAL;
		goto out;
	}

	if (le64_to_cpu(data_super->fmt_vers) < SCOUTFS_FORMAT_VERSION_MIN ||
	    le64_to_cpu(data_super->fmt_vers) > SCOUTFS_FORMAT_VERSION_MAX) {
		fprintf(stderr, "data super block has format version %llu outside of supported version range %u-%u",
			    le64_to_cpu(data_super->fmt_vers), SCOUTFS_FORMAT_VERSION_MIN,
			    SCOUTFS_FORMAT_VERSION_MAX);
		ret = -EINVAL;
		goto out;
	}

	ret = meta_super_in_use(meta_fd, meta_super);
	if (ret < 0) {
		if (ret == -EBUSY)
			fprintf(stderr, "The filesystem must be fully recovered and cleanly unmounted to change the format version\n");
		goto out;
	}

	if (le64_to_cpu(meta_super->fmt_vers) != args->fmt_vers) {
		meta_super->fmt_vers = cpu_to_le64(args->fmt_vers);

		ret = write_block(meta_fd, SCOUTFS_BLOCK_MAGIC_SUPER, meta_super->hdr.fsid, 1,
				  SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT, &meta_super->hdr);
		if (ret)
			goto out;

		wrote_meta = true;
	}

	if (le64_to_cpu(data_super->fmt_vers) != args->fmt_vers) {
		data_super->fmt_vers = cpu_to_le64(args->fmt_vers);

		ret = write_block(data_fd, SCOUTFS_BLOCK_MAGIC_SUPER, data_super->hdr.fsid, 1,
				  SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT, &data_super->hdr);
		if (ret < 0 && wrote_meta) {
			fprintf(stderr, "Error writing data super block after writing the meta\n"
					"super block.  The two super blocks may now be out of sync which\n"
					"would prevent mounting.   Correct the source of the write error\n"
					"and retry changing the version to write both super blocks.\n");
			goto out;
		}
	}

	uuid_unparse(meta_super->uuid, uuid_str);

	printf("Successfully updated format version for scoutfs filesystem:\n"
	       "  meta device path:     %s\n"
	       "  data device path:     %s\n"
	       "  fsid:                 %llx\n"
	       "  uuid:                 %s\n"
	       "  format version:       %llu\n",
		args->meta_device,
	        args->data_device,
		le64_to_cpu(meta_super->hdr.fsid),
		uuid_str,
		le64_to_cpu(meta_super->fmt_vers));

out:

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
	struct change_fmt_vers_args *args = state->input;
	int ret;

	switch (key) {
	case 'F':
		args->offline = true;
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
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else if (!args->data_device)
			args->data_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two device arguments given");
		break;
	case ARGP_KEY_FINI:
		if (!args->offline)
			argp_error(state, "must specify --offline");
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		if (!args->data_device)
			argp_error(state, "no data device argument given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "offline", 'F', NULL, 0, "Write format version in offline device super blocks"},
	{ "format-version", 'V', "VERS", 0, "Specify a format version within supported range ("SCOUTFS_FORMAT_VERSION_MIN_STR"-"SCOUTFS_FORMAT_VERSION_MAX_STR", default "SCOUTFS_FORMAT_VERSION_MAX_STR")"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"",
	"Change format version of an existing ScoutFS filesystem"
};

static int change_fmt_vers_cmd(int argc, char *argv[])
{
	struct change_fmt_vers_args change_fmt_vers_args = {
		.offline = false,
		.fmt_vers = SCOUTFS_FORMAT_VERSION_MAX,
	};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &change_fmt_vers_args);
	if (ret)
		return ret;

	return do_change_fmt_vers(&change_fmt_vers_args);
}

static void __attribute__((constructor)) change_fmt_vers_ctor(void)
{
	cmd_register_argp("change-format-version", &argp, GROUP_CORE, change_fmt_vers_cmd);
}
