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
#include "inode.h"

enum {
	Opt_acl,
	Opt_metadev_path,
	Opt_noacl,
	Opt_orphan_scan_delay_ms,
	Opt_quorum_slot_nr,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_acl, "acl"},
	{Opt_metadev_path, "metadev_path=%s"},
	{Opt_noacl, "noacl"},
	{Opt_orphan_scan_delay_ms, "orphan_scan_delay_ms=%s"},
	{Opt_quorum_slot_nr, "quorum_slot_nr=%s"},
	{Opt_err, NULL}
};

struct options_info {
	seqlock_t seqlock;
	struct scoutfs_mount_options opts;
	struct scoutfs_sysfs_attrs sysfs_attrs;
};

#define DECLARE_OPTIONS_INFO(sb, name) \
	struct options_info *name = SCOUTFS_SB(sb)->options_info

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

static void free_options(struct scoutfs_mount_options *opts)
{
	kfree(opts->metadev_path);
}

#define MIN_ORPHAN_SCAN_DELAY_MS	100UL
#define DEFAULT_ORPHAN_SCAN_DELAY_MS	(10 * MSEC_PER_SEC)
#define MAX_ORPHAN_SCAN_DELAY_MS	(60 * MSEC_PER_SEC)

static void init_default_options(struct scoutfs_mount_options *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->quorum_slot_nr = -1;
	opts->orphan_scan_delay_ms = DEFAULT_ORPHAN_SCAN_DELAY_MS;
}

/*
 * Parse the option string into our options struct.   This can allocate
 * memory in the struct.  The caller is responsible for always calling
 * free_options() when the struct is destroyed, including when we return
 * an error.
 */
static int parse_options(struct super_block *sb, char *options, struct scoutfs_mount_options *opts)
{
	substring_t args[MAX_OPT_ARGS];
	int nr;
	int token;
	char *p;
	int ret;

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {

		case Opt_acl:
			sb->s_flags |= MS_POSIXACL;
			break;

		case Opt_metadev_path:
			ret = parse_bdev_path(sb, &args[0], &opts->metadev_path);
			if (ret < 0)
				return ret;
			break;

		case Opt_noacl:
			sb->s_flags &= ~MS_POSIXACL;
			break;

		case Opt_orphan_scan_delay_ms:
			if (opts->orphan_scan_delay_ms != -1) {
				scoutfs_err(sb, "multiple orphan_scan_delay_ms options provided, only provide one.");
				return -EINVAL;
			}

			ret = match_int(args, &nr);
			if (ret < 0 ||
			    nr < MIN_ORPHAN_SCAN_DELAY_MS || nr > MAX_ORPHAN_SCAN_DELAY_MS) {
				scoutfs_err(sb, "invalid orphan_scan_delay_ms option, must be between %lu and %lu",
					    MIN_ORPHAN_SCAN_DELAY_MS, MAX_ORPHAN_SCAN_DELAY_MS);
				if (ret == 0)
					ret = -EINVAL;
				return ret;
			}
			opts->orphan_scan_delay_ms = nr;
			break;

		case Opt_quorum_slot_nr:
			if (opts->quorum_slot_nr != -1) {
				scoutfs_err(sb, "multiple quorum_slot_nr options provided, only provide one.");
				return -EINVAL;
			}

			ret = match_int(args, &nr);
			if (ret < 0 || nr < 0 || nr >= SCOUTFS_QUORUM_MAX_SLOTS) {
				scoutfs_err(sb, "invalid quorum_slot_nr option, must be between 0 and %u",
					    SCOUTFS_QUORUM_MAX_SLOTS - 1);
				if (ret == 0)
					ret = -EINVAL;
				return ret;
			}
			opts->quorum_slot_nr = nr;
			break;

		default:
			scoutfs_err(sb, "Unknown or malformed option, \"%s\"", p);
			return -EINVAL;
		}
	}

	if (!opts->metadev_path) {
		scoutfs_err(sb, "Required mount option \"metadev_path\" not found");
		return -EINVAL;
	}

	return 0;
}

void scoutfs_options_read(struct super_block *sb, struct scoutfs_mount_options *opts)
{
	DECLARE_OPTIONS_INFO(sb, optinf);
	unsigned int seq;

	if (WARN_ON_ONCE(optinf == NULL)) {
		/* trying to use options before early setup or after destroy */
		init_default_options(opts);
		return;
	}

	do {
		seq = read_seqbegin(&optinf->seqlock);
		memcpy(opts, &optinf->opts, sizeof(struct scoutfs_mount_options));
	} while (read_seqretry(&optinf->seqlock, seq));
}

/*
 * Early setup that parses and stores the options so that the rest of
 * setup can use them.   Full options setup that relies on other
 * components will be done later.
 */
int scoutfs_options_early_setup(struct super_block *sb, char *options)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_mount_options opts;
	struct options_info *optinf;
	int ret;

	init_default_options(&opts);

	ret = parse_options(sb, options, &opts);
	if (ret < 0)
		goto out;

	optinf = kzalloc(sizeof(struct options_info), GFP_KERNEL);
	if (!optinf) {
		ret = -ENOMEM;
		goto out;
	}

	seqlock_init(&optinf->seqlock);
	scoutfs_sysfs_init_attrs(sb, &optinf->sysfs_attrs);

	write_seqlock(&optinf->seqlock);
	optinf->opts = opts;
	write_sequnlock(&optinf->seqlock);

	sbi->options_info = optinf;
	ret = 0;
out:
	if (ret < 0)
		free_options(&opts);

	return ret;
}

int scoutfs_options_show(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct scoutfs_mount_options opts;
	const bool is_acl = !!(sb->s_flags & MS_POSIXACL);

	scoutfs_options_read(sb, &opts);

	if (is_acl)
		seq_puts(seq, ",acl");
	seq_printf(seq, ",metadev_path=%s", opts.metadev_path);
	if (!is_acl)
		seq_puts(seq, ",noacl");
	seq_printf(seq, ",orphan_scan_delay_ms=%u", opts.orphan_scan_delay_ms);
	if (opts.quorum_slot_nr >= 0)
		seq_printf(seq, ",quorum_slot_nr=%d", opts.quorum_slot_nr);

	return 0;
}

static ssize_t metadev_path_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = SCOUTFS_SYSFS_ATTRS_SB(kobj);
	struct scoutfs_mount_options opts;

	scoutfs_options_read(sb, &opts);

	return snprintf(buf, PAGE_SIZE, "%s", opts.metadev_path);
}
SCOUTFS_ATTR_RO(metadev_path);

static ssize_t orphan_scan_delay_ms_show(struct kobject *kobj, struct kobj_attribute *attr,
					 char *buf)
{
	struct super_block *sb = SCOUTFS_SYSFS_ATTRS_SB(kobj);
	struct scoutfs_mount_options opts;

	scoutfs_options_read(sb, &opts);

	return snprintf(buf, PAGE_SIZE, "%u", opts.orphan_scan_delay_ms);
}
static ssize_t orphan_scan_delay_ms_store(struct kobject *kobj, struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct super_block *sb = SCOUTFS_SYSFS_ATTRS_SB(kobj);
	DECLARE_OPTIONS_INFO(sb, optinf);
	char nullterm[20]; /* more than enough for octal -U32_MAX */
	long val;
	int len;
	int ret;

	len = min(count, sizeof(nullterm) - 1);
	memcpy(nullterm, buf, len);
	nullterm[len] = '\0';

	ret = kstrtol(nullterm, 0, &val);
	if (ret < 0 || val < MIN_ORPHAN_SCAN_DELAY_MS || val > MAX_ORPHAN_SCAN_DELAY_MS) {
		scoutfs_err(sb, "invalid orphan_scan_delay_ms value written to options sysfs file, must be between %lu and %lu",
			    MIN_ORPHAN_SCAN_DELAY_MS, MAX_ORPHAN_SCAN_DELAY_MS);
		return -EINVAL;
	}

	write_seqlock(&optinf->seqlock);
	optinf->opts.orphan_scan_delay_ms = val;
	write_sequnlock(&optinf->seqlock);

	scoutfs_inode_schedule_orphan_dwork(sb);

	return count;
}
SCOUTFS_ATTR_RW(orphan_scan_delay_ms);

static ssize_t quorum_slot_nr_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct super_block *sb = SCOUTFS_SYSFS_ATTRS_SB(kobj);
	struct scoutfs_mount_options opts;

	scoutfs_options_read(sb, &opts);

	return snprintf(buf, PAGE_SIZE, "%d\n", opts.quorum_slot_nr);
}
SCOUTFS_ATTR_RO(quorum_slot_nr);

static struct attribute *options_attrs[] = {
	SCOUTFS_ATTR_PTR(metadev_path),
	SCOUTFS_ATTR_PTR(orphan_scan_delay_ms),
	SCOUTFS_ATTR_PTR(quorum_slot_nr),
	NULL,
};

int scoutfs_options_setup(struct super_block *sb)
{
	DECLARE_OPTIONS_INFO(sb, optinf);
	int ret;

	ret = scoutfs_sysfs_create_attrs(sb, &optinf->sysfs_attrs, options_attrs, "mount_options");
	if (ret < 0)
		scoutfs_options_destroy(sb);
	return ret;
}

/*
 * We remove the sysfs files early in unmount so that they can't try to call other subsystems
 * as they're being destroyed.
 */
void scoutfs_options_stop(struct super_block *sb)
{
	DECLARE_OPTIONS_INFO(sb, optinf);

	if (optinf)
		scoutfs_sysfs_destroy_attrs(sb, &optinf->sysfs_attrs);
}

void scoutfs_options_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_OPTIONS_INFO(sb, optinf);

	scoutfs_options_stop(sb);

	if (optinf) {
		free_options(&optinf->opts);
		kfree(optinf);
		sbi->options_info = NULL;
	}
}
