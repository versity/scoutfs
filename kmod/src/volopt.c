/*
 * Copyright (C) 2021 Versity Software, Inc.  All rights reserved.
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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "super.h"
#include "client.h"
#include "volopt.h"

/*
 * Volume options are exposed through a sysfs directory.  Getting and
 * setting the values sends rpcs to the server who owns the options in
 * the super block.
 */

struct volopt_info {
	struct super_block *sb;
	struct scoutfs_sysfs_attrs ssa;
};

#define DECLARE_VOLOPT_INFO(sb, name) \
	struct volopt_info *name = SCOUTFS_SB(sb)->volopt_info
#define DECLARE_VOLOPT_INFO_KOBJ(kobj, name) \
	DECLARE_VOLOPT_INFO(SCOUTFS_SYSFS_ATTRS_SB(kobj), name)

/*
 * attribute arrays need to be dense but the options we export could
 * well become sparse over time.  .store and .load are generic and we
 * have a lookup table to map the attributes array indexes to the number
 * and name of the option.
 */
static struct volopt_nr_name {
	int nr;
	char *name;
} volopt_table[] = {
};

/* initialized by setup, pointer array is null terminated */
static struct kobj_attribute volopt_attrs[ARRAY_SIZE(volopt_table)];
static struct attribute *volopt_attr_ptrs[ARRAY_SIZE(volopt_table) + 1];

static void get_opt_data(struct kobj_attribute *attr, struct scoutfs_volume_options *volopt,
			 u64 *bit, __le64 **opt)
{
	size_t index = attr - &volopt_attrs[0];
	int nr = volopt_table[index].nr;

	*bit = 1ULL << nr;
	*opt = &volopt->set_bits + 1 + nr;
}

static ssize_t volopt_attr_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	DECLARE_VOLOPT_INFO_KOBJ(kobj, vinf);
	struct super_block *sb = vinf->sb;
	struct scoutfs_volume_options volopt;
	__le64 *opt;
	u64 bit;
	int ret;

	ret = scoutfs_client_get_volopt(sb, &volopt);
	if (ret < 0)
		return ret;

	get_opt_data(attr, &volopt, &bit, &opt);

	if (le64_to_cpu(volopt.set_bits) & bit) {
		return snprintf(buf, PAGE_SIZE, "%llu", le64_to_cpup(opt));
	} else {
		buf[0] = '\0';
		return 0;
	}
}

static ssize_t volopt_attr_store(struct kobject *kobj, struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	DECLARE_VOLOPT_INFO_KOBJ(kobj, vinf);
	struct super_block *sb = vinf->sb;
	struct scoutfs_volume_options volopt = {0,};
	u8 chars[32];
	__le64 *opt;
	u64 bit;
	u64 val;
	int ret;

	if (count == 0)
		return 0;
	if (count > sizeof(chars) - 1)
		return -ERANGE;

	get_opt_data(attr, &volopt, &bit, &opt);

	if (buf[0] == '\n' || buf[0] == '\r') {
		volopt.set_bits = cpu_to_le64(bit);

		ret = scoutfs_client_clear_volopt(sb, &volopt);
	} else {
		memcpy(chars, buf, count);
		chars[count] = '\0';
		ret = kstrtoull(chars, 0, &val);
		if (ret < 0)
			return ret;

		volopt.set_bits = cpu_to_le64(bit);
		*opt = cpu_to_le64(val);

		ret = scoutfs_client_set_volopt(sb, &volopt);
	}

	if (ret == 0)
		ret = count;
	return ret;
}

/*
 * The volume option sysfs files are slim shims around RPCs so this
 * should be called after the client is setup and before it is torn
 * down.
 */
int scoutfs_volopt_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct volopt_info *vinf;
	int ret;
	int i;

	/* persistent volume options are always a bitmap u64 then the 64 options */
	BUILD_BUG_ON(sizeof(struct scoutfs_volume_options) != (1 + 64) * 8);

	vinf = kzalloc(sizeof(struct volopt_info), GFP_KERNEL);
	if (!vinf) {
		ret = -ENOMEM;
		goto out;
	}

	scoutfs_sysfs_init_attrs(sb, &vinf->ssa);
	vinf->sb = sb;
	sbi->volopt_info = vinf;

	for (i = 0; i < ARRAY_SIZE(volopt_table); i++) {
		volopt_attrs[i] = (struct kobj_attribute) {
			.attr = { .name = volopt_table[i].name, .mode = S_IWUSR | S_IRUGO },
			.show = volopt_attr_show,
			.store  = volopt_attr_store,
		};
		volopt_attr_ptrs[i] = &volopt_attrs[i].attr;
	}

	BUILD_BUG_ON(ARRAY_SIZE(volopt_table) != ARRAY_SIZE(volopt_attr_ptrs) - 1);
	volopt_attr_ptrs[i] = NULL;

	ret = scoutfs_sysfs_create_attrs(sb, &vinf->ssa, volopt_attr_ptrs, "volume_options");
	if (ret < 0)
		goto out;

out:
	if (ret)
		scoutfs_volopt_destroy(sb);

	return ret;
}

void scoutfs_volopt_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct volopt_info *vinf = SCOUTFS_SB(sb)->volopt_info;

	if (vinf) {
		scoutfs_sysfs_destroy_attrs(sb, &vinf->ssa);
		kfree(vinf);
		sbi->volopt_info = NULL;
	}
}
