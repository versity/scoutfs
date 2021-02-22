/*
 * Copyright (C) 2017 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/namei.h>

#include <linux/parser.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/in.h>

#include "msg.h"
#include "options.h"
#include "super.h"

static const match_table_t tokens = {
	{Opt_quorum_slot_nr, "quorum_slot_nr=%s"},
	{Opt_metadev_path, "metadev_path=%s"},
	{Opt_err, NULL}
};

struct options_sb_info {
	struct dentry *debugfs_dir;
};

u32 scoutfs_option_u32(struct super_block *sb, int token)
{
	WARN_ON_ONCE(1);
	return 0;
}

static int parse_bdev_path(struct super_block *sb, substring_t *substr,
			      char **bdev_path_ret)
{
	char *bdev_path;
	struct inode *bdev_inode;
	struct path path;
	bool got_path = false;
	int ret;

	bdev_path = match_strdup(substr);
	if (!bdev_path) {
		scoutfs_err(sb, "bdev string dup failed");
		ret = -ENOMEM;
		goto out;
	}

	ret = kern_path(bdev_path, LOOKUP_FOLLOW, &path);
	if (ret) {
		scoutfs_err(sb, "path %s not found for bdev: error %d",
			    bdev_path, ret);
		goto out;
	}
	got_path = true;

	bdev_inode = d_inode(path.dentry);
	if (!S_ISBLK(bdev_inode->i_mode)) {
		scoutfs_err(sb, "path %s for bdev is not a block device",
			    bdev_path);
		ret = -ENOTBLK;
		goto out;
	}

out:
	if (got_path) {
		path_put(&path);
	}

	if (ret < 0) {
		kfree(bdev_path);
	} else {
		*bdev_path_ret = bdev_path;
	}

	return ret;
}

int scoutfs_parse_options(struct super_block *sb, char *options,
			  struct mount_options *parsed)
{
	substring_t args[MAX_OPT_ARGS];
	int nr;
	int token;
	char *p;
	int ret;

	/* Set defaults */
	memset(parsed, 0, sizeof(*parsed));
	parsed->quorum_slot_nr = -1;

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_quorum_slot_nr:

			if (parsed->quorum_slot_nr != -1) {
				scoutfs_err(sb, "multiple quorum_slot_nr options provided, only provide one.");
				return -EINVAL;
			}

			ret = match_int(args, &nr);
			if (ret < 0 || nr < 0 ||
			    nr >= SCOUTFS_QUORUM_MAX_SLOTS) {
				scoutfs_err(sb, "invalid quorum_slot_nr option, must be between 0 and %u",
					    SCOUTFS_QUORUM_MAX_SLOTS - 1);
				if (ret == 0)
					ret = -EINVAL;
				return ret;
			}
			parsed->quorum_slot_nr = nr;
			break;
		case Opt_metadev_path:

			ret = parse_bdev_path(sb, &args[0],
						 &parsed->metadev_path);
			if (ret < 0)
				return ret;
			break;
		default:
			scoutfs_err(sb, "Unknown or malformed option, \"%s\"",
				    p);
			break;
		}
	}

	if (!parsed->metadev_path) {
		scoutfs_err(sb, "Required mount option \"metadev_path\" not found");
		return -EINVAL;
	}

	return 0;
}

int scoutfs_options_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct options_sb_info *osi;
	int ret;

	osi = kzalloc(sizeof(struct options_sb_info), GFP_KERNEL);
	if (!osi)
		return -ENOMEM;

	sbi->options = osi;

	osi->debugfs_dir = debugfs_create_dir("options", sbi->debug_root);
	if (!osi->debugfs_dir) {
		ret = -ENOMEM;
		goto out;
	}

	ret = 0;
out:
	if (ret)
		scoutfs_options_destroy(sb);
	return ret;
}

void scoutfs_options_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct options_sb_info *osi = sbi->options;

	if (osi) {
		if (osi->debugfs_dir)
			debugfs_remove_recursive(osi->debugfs_dir);
		kfree(osi);
		sbi->options = NULL;
	}
}
