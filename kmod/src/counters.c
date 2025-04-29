/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
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
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/percpu_counter.h>

#include "super.h"
#include "sysfs.h"
#include "counters.h"

/*
 * Maintain simple percpu counters which are always ticking.  sysfs
 * makes this a whole lot more noisy than it needs to be.
 */

static ssize_t scoutfs_counter_attr_show(struct kobject *, struct kobj_attribute *, char *);

#undef EXPAND_COUNTER
#define EXPAND_COUNTER(which) static struct kobj_attribute which##_attr = \
	__ATTR(which, 0444, scoutfs_counter_attr_show, NULL);
EXPAND_EACH_COUNTER

#undef EXPAND_COUNTER
#define EXPAND_COUNTER(which) &which##_attr.attr,
static struct attribute *scoutfs_counter_attrs[] = {
	EXPAND_EACH_COUNTER
	NULL,
};
#ifdef KC_KOBJECT_DEFAULT_GROUPS
ATTRIBUTE_GROUPS(scoutfs_counter);
#endif

/* zero BSS and + 1 makes this null terminated */
#define NR_ATTRS ARRAY_SIZE(scoutfs_counter_attrs)

#ifndef KC_KOBJECT_DEFAULT_GROUPS
static struct attribute *scoutfs_counter_attr_ptrs[NR_ATTRS + 1];
#endif

static ssize_t scoutfs_counter_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct scoutfs_counters *counters;
	struct percpu_counter *pcpu;
	size_t index;

	counters = container_of(kobj, struct scoutfs_counters, kobj);
	index = scoutfs_counter_attrs[0] - attr;	//WAT
	index = index / 2;				// sizeof(attr) / sizeof(pcpu)
	pcpu = &counters->FIRST_COUNTER + index;

	return snprintf(buf, PAGE_SIZE, "%lld\n", percpu_counter_sum(pcpu));
}

static ssize_t scoutfs_counter_attr_show(struct kobject *kobj,
				         struct kobj_attribute *attr, char *buf)
{
	return scoutfs_counter_show(kobj, &attr->attr, buf);
}

static void scoutfs_counters_kobj_release(struct kobject *kobj)
{
	struct scoutfs_counters *counters;

	counters = container_of(kobj, struct scoutfs_counters, kobj);

	complete(&counters->comp);
}

static const struct sysfs_ops scoutfs_counter_attr_ops = {
	.show   = scoutfs_counter_show,
};

static struct kobj_type scoutfs_counters_ktype = {
#ifdef KC_KOBJECT_DEFAULT_GROUPS
	.default_groups = scoutfs_counter_groups,
#else
	.default_attrs  = scoutfs_counter_attr_ptrs,
#endif
	.sysfs_ops      = &scoutfs_counter_attr_ops,
	.release        = scoutfs_counters_kobj_release,
};

int scoutfs_setup_counters(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_counters *counters;
	struct percpu_counter *pcpu;
	int ret;

	counters = kzalloc(sizeof(struct scoutfs_counters), GFP_KERNEL);
	if (!counters)
		return -ENOMEM;
	sbi->counters = counters;

	scoutfs_foreach_counter(sb, pcpu) {
		ret = percpu_counter_init(pcpu, 0, GFP_KERNEL);
		if (ret)
			goto out;
	}

	init_completion(&counters->comp);
	ret = kobject_init_and_add(&counters->kobj, &scoutfs_counters_ktype,
				    scoutfs_sysfs_sb_dir(sb), "counters");
out:
	if (ret) {
		/* tear down partial to avoid destroying null kobjs */
		scoutfs_foreach_counter(sb, pcpu)
			percpu_counter_destroy(pcpu);
		kfree(counters);
		sbi->counters = NULL;
	}

	return ret;
}

void scoutfs_destroy_counters(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_counters *counters = sbi->counters;
	struct percpu_counter *pcpu;

	/* this only destroys fully initialized counters */
	if (!counters)
		return;

	kobject_del(&counters->kobj);
	kobject_put(&counters->kobj);
	wait_for_completion(&counters->comp);

	scoutfs_foreach_counter(sb, pcpu)
		percpu_counter_destroy(pcpu);

	kfree(counters);
	sbi->counters = NULL;
}

void __init scoutfs_init_counters(void)
{
#ifndef KC_KOBJECT_DEFAULT_GROUPS
	int i;

	/* not ARRAY_SIZE because that would clobber null term */
	for (i = 0; i < NR_ATTRS; i++)
		scoutfs_counter_attr_ptrs[i] = scoutfs_counter_attrs[i];
#endif
}
