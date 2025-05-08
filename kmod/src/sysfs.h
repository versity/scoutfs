#ifndef _SCOUTFS_SYSFS_H_
#define _SCOUTFS_SYSFS_H_

#include <linux/kobject.h>

/*
 * We have some light wrappers around sysfs attributes to make it safe
 * to tear down the attributes before freeing the data they describe.
 */

#define SCOUTFS_ATTR_RO(_name)						\
        static struct kobj_attribute scoutfs_attr_##_name = __ATTR_RO(_name)
#define SCOUTFS_ATTR_RW(_name)						\
        static struct kobj_attribute scoutfs_attr_##_name = __ATTR_RW(_name)

#define SCOUTFS_ATTR_PTR(_name)						\
        &scoutfs_attr_##_name.attr

struct scoutfs_sysfs_attrs {
	struct super_block *sb;
	char *name;
	struct completion comp;

	struct kobject kobj;
	struct kobj_type ktype;
};

#define SCOUTFS_SYSFS_ATTRS(kobj)					\
	container_of(kobj, struct scoutfs_sysfs_attrs, kobj)

#define SCOUTFS_SYSFS_ATTRS_SB(kobj)					\
	(SCOUTFS_SYSFS_ATTRS(kobj)->sb)

#define DECLARE_SCOUTFS_SYSFS_ATTRS(name, kobj)				\
	struct scoutfs_sysfs_attrs *ssa = SCOUTFS_SYSFS_ATTRS(kobj)

void scoutfs_sysfs_init_attrs(struct super_block *sb,
			      struct scoutfs_sysfs_attrs *ssa);
int scoutfs_sysfs_create_attrs_parent(struct super_block *sb,
				      struct kobject *parent,
				      struct scoutfs_sysfs_attrs *ssa,
#ifdef KC_KOBJECT_DEFAULT_GROUPS
				      const struct attribute_group **groups,
#else
				      struct attribute **attrs,
#endif
				      char *fmt, ...);
#define scoutfs_sysfs_create_attrs(sb, ssa, attrs_or_group, fmt, args...)	\
	scoutfs_sysfs_create_attrs_parent(sb, scoutfs_sysfs_sb_dir(sb),	\
					  ssa, attrs_or_group, fmt, ##args)

void scoutfs_sysfs_destroy_attrs(struct super_block *sb,
				 struct scoutfs_sysfs_attrs *ssa);

struct kobject *scoutfs_sysfs_sb_dir(struct super_block *sb);

int scoutfs_setup_sysfs(struct super_block *sb);
void scoutfs_destroy_sysfs(struct super_block *sb);

int __init scoutfs_sysfs_init(void);
void scoutfs_sysfs_exit(void);

#endif
