#define _GNU_SOURCE /* O_DIRECT */
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <argp.h>

#include "sparse.h"
#include "cmd.h"
#include "util.h"
#include "format.h"
#include "parse.h"
#include "dev.h"
#include "btree.h"
#include "avl.h"

struct wipe_ltdf_args {
	char *meta_device;
	u64 fsid;
	u64 rid;
};

static int do_wipe_ltdf(struct wipe_ltdf_args *args)
{
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_btree_block *bt = NULL;
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *node;
	struct scoutfs_log_trees *lt;
	bool found = false;
	int meta_fd = -1;
	unsigned val_len;
	u64 blkno;
	int ret;

	meta_fd = open(args->meta_device, O_DIRECT | O_RDWR | O_EXCL);
	if (meta_fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->meta_device, strerror(errno), errno);
		goto out;
	}

	ret = read_block_verify(meta_fd, SCOUTFS_BLOCK_MAGIC_SUPER, args->fsid, SCOUTFS_SUPER_BLKNO,
				SCOUTFS_BLOCK_SM_SHIFT, (void **)&super);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "failed to read meta super block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	if (!(le64_to_cpu(super->flags) & SCOUTFS_FLAG_IS_META_BDEV)) {
		fprintf(stderr, "The super block in device %s doesn't have the META_BDEV flag set, is it a data device?\n",
			args->meta_device);
		ret = -EIO;
		goto out;
	}

	blkno = le64_to_cpu(super->logs_root.ref.blkno);
	if (blkno == 0) {
		fprintf(stderr, "The logs_root btree ref is empty, no pending log_trees items\n");
		ret = 0;
		goto out;
	}

	if (super->logs_root.height != 1) {
		fprintf(stderr, "The logs_root btree is not a single leaf, can't find items\n");
		ret = -EINVAL;
		goto out;
	}

	ret = read_block_verify(meta_fd, SCOUTFS_BLOCK_MAGIC_BTREE, args->fsid, blkno,
				SCOUTFS_BLOCK_LG_SHIFT, (void **)&bt);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "failed to read meta super block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	if (bt->level != 0) {
		fprintf(stderr, "read non-leaf logs_root btree block at blkno %llu with level %u\n",
			blkno, bt->level);
		ret = -EIO;
		goto out;
	}

	node = avl_first(&bt->item_root);
	while (node) {
		item = container_of(node, struct scoutfs_btree_item, node);
		val_len = le16_to_cpu(item->val_len);

		if (val_len != sizeof(struct scoutfs_log_trees)) {
			fprintf(stderr, "invalid item length: %u, expected %zu\n",
				val_len, sizeof(struct scoutfs_log_trees));
			ret = -EIO;
			goto out;
		}

		lt = (void *)bt + le16_to_cpu(item->val_off);

		if (le64_to_cpu(lt->rid) == args->rid) {
			printf("found rid %016llx\n", args->rid);
			found = true;
			break;
		} else {
			printf("skipping mount rid %016llx\n", le64_to_cpu(lt->rid));
		}

		node = avl_next(&bt->item_root, node);
	}

	if (!found) {
		fprintf(stderr, "couldn't find log_trees item with rid %016llx\n", args->rid);
		ret = -ENOENT;
		goto out;
	}

	printf("wiping meta_avail: blkno %llu total_nr %llu\n",
		le64_to_cpu(lt->meta_avail.ref.blkno), le64_to_cpu(lt->meta_avail.total_nr));
	printf("wiping meta_freed: blkno %llu total_nr %llu\n",
		le64_to_cpu(lt->meta_freed.ref.blkno), le64_to_cpu(lt->meta_freed.total_nr));
	printf("wiping data_avail: blkno %llu total_len %llu\n",
		le64_to_cpu(lt->data_avail.root.ref.blkno), le64_to_cpu(lt->data_avail.total_len));
	printf("wiping data_freed: blkno %llu total_len %llu\n",
		le64_to_cpu(lt->data_freed.root.ref.blkno), le64_to_cpu(lt->data_freed.total_len));

	memset(&lt->meta_avail, 0, sizeof(lt->meta_avail));
	memset(&lt->meta_freed, 0, sizeof(lt->meta_freed));
	memset(&lt->data_avail, 0, sizeof(lt->data_avail));
	memset(&lt->data_freed, 0, sizeof(lt->data_freed));

	ret = write_block(meta_fd, SCOUTFS_BLOCK_MAGIC_BTREE, super->hdr.fsid,
			  le64_to_cpu(bt->hdr.seq), blkno, SCOUTFS_BLOCK_LG_SHIFT,
			  &bt->hdr);
	if (ret)
		fprintf(stderr, "Failed to write updated log_trees block.\n");
	else
		printf("Writing updated log_trees block succeeded.\n");

out:
	if (meta_fd >= 0)
		close(meta_fd);
	if (super)
		free(super);
	if (bt)
		free(bt);
	return ret;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct wipe_ltdf_args *args = state->input;
	int ret;

	switch (key) {
	case 'f': /* fsid */
	{
		ret = parse_u64(arg, &args->fsid);
		if (ret)
			return ret;

		if (args->fsid == 0)
			argp_error(state, "must provide non-zero fsid");

		break;
	}
	case 'r': /* rid */
	{
		ret = parse_u64(arg, &args->rid);
		if (ret)
			return ret;

		if (args->rid == 0)
			argp_error(state, "must provide non-zero rid");

		break;
	}
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two metadata device given");
		break;
	case ARGP_KEY_FINI:
		if (!args->fsid)
			argp_error(state, "must specify fsid with --fsid|-f");
		if (!args->rid)
			argp_error(state, "must specify rid with --rid|-r");
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "fsid", 'f', "FSID", 0, "fsid of volume in which to wipe root item, for validation"},
	{ "rid", 'r', "RID", 0, "rid of log_trees item in which to wipe data_freed btree ref"},
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"META-DEVICE",
	"(debug) wipe a data_freed btree root ref for a given mount rid, do not do this"
};

static int wipe_ltdf_cmd(int argc, char *argv[])
{
	struct wipe_ltdf_args wipe_ltdf_args = {NULL,};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &wipe_ltdf_args);
	if (ret)
		return ret;

	return do_wipe_ltdf(&wipe_ltdf_args);
}

static void __attribute__((constructor)) wipe_ltdf_ctor(void)
{
	cmd_register_argp("wipe-log-trees-data-freed", &argp, GROUP_DEBUG, wipe_ltdf_cmd);
}
