#define _GNU_SOURCE /* O_DIRECT */
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <argp.h>

#include "sparse.h"
#include "cmd.h"
#include "util.h"
#include "format.h"
#include "parse.h"
#include "dev.h"
#include "quorum.h"

struct change_quorum_args {
	char *meta_device;
	bool offline;
	int nr_slots;
	struct scoutfs_quorum_slot slots[SCOUTFS_QUORUM_MAX_SLOTS];
};

static int do_change_quorum(struct change_quorum_args *args)
{
	struct scoutfs_super_block *meta_super = NULL;
	char uuid_str[37];
	int meta_fd = -1;
	int ret;

	meta_fd = open(args->meta_device, O_DIRECT | O_SYNC | O_RDWR | O_EXCL);
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

	ret = meta_super_in_use(meta_fd, meta_super);
	if (ret < 0) {
		if (ret == -EBUSY)
			fprintf(stderr, "The filesystem must be fully recovered and cleanly unmounted to change the quorum config\n");
		goto out;
	}

	assert(sizeof(meta_super->qconf.slots) == sizeof(args->slots));
	memcpy(meta_super->qconf.slots, args->slots, sizeof(meta_super->qconf.slots));
	le64_add_cpu(&meta_super->qconf.version, 1);

	ret = write_block(meta_fd, SCOUTFS_BLOCK_MAGIC_SUPER, meta_super->hdr.fsid, 1,
			  SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT, &meta_super->hdr);
	if (ret)
		goto out;

	uuid_unparse(meta_super->uuid, uuid_str);

	printf("Successfully changed quorum config for scoutfs filesystem:\n"
	       "  meta device path:       %s\n"
	       "  fsid:                   %llx\n"
	       "  uuid:                   %s\n"
	       "  quorum config version:  %llu\n"
	       "  quorum slots:           ",
		args->meta_device,
		le64_to_cpu(meta_super->hdr.fsid),
		uuid_str,
		le64_to_cpu(meta_super->qconf.version));

	print_quorum_slots(meta_super->qconf.slots, array_size(meta_super->qconf.slots),
			   "                          ");

out:

	if (meta_super)
		free(meta_super);
	if (meta_fd != -1)
		close(meta_fd);
	return ret;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct change_quorum_args *args = state->input;
	struct scoutfs_quorum_slot slot;
	int ret;

	switch (key) {
	case 'F':
		args->offline = true;
		break;
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
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than one metadata device argument given");
		break;
	case ARGP_KEY_FINI:
		if (!args->offline)
			argp_error(state, "must specify --offline");
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		if (!args->nr_slots)
			argp_error(state, "must specify at least one quorum slot with --quorum-slot|-Q");
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
	{ "offline", 'F', NULL, 0, "Write format version in offline device super blocks [Currently Required]"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"",
	"Change quorum slots and addresses of an existing ScoutFS filesystem"
};

static int change_quorum_cmd(int argc, char *argv[])
{
	struct change_quorum_args change_quorum_args = {
		.offline = false,
	};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &change_quorum_args);
	if (ret)
		return ret;

	return do_change_quorum(&change_quorum_args);
}

static void __attribute__((constructor)) change_quorum_ctor(void)
{
	cmd_register_argp("change-quorum-config", &argp, GROUP_CORE, change_quorum_cmd);
}
