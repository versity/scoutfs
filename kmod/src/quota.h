#ifndef _SCOUTFS_QUOTA_H_
#define _SCOUTFS_QUOTA_H_

#include "ioctl.h"

/*
 * Each rule's name can be in the ruleset's rbtree associated with the
 * source attr that it selects.  This lets checks only test rules that
 * the inputs could match.  The 'i' field indicates which name is in the
 * tree so we can find the containing rule.
 *
 * This is mostly private to quota.c but we expose it for tracing.
 */
struct squota_rule {
	u64 limit;
	u8 prio;
	u8 op;
	u8 rule_flags;
	struct squota_rule_name {
		struct rb_node node;
		u64 val;
		u8 source;
		u8 flags;
		u8 i;
	} names[3];
};

/* private to quota.c, only here for tracing */
struct squota_input {
	u64 attrs[SQ_NS__NR_SELECT];
	u8 op;
};

int scoutfs_quota_check_inode(struct super_block *sb, struct inode *dir);
int scoutfs_quota_check_data(struct super_block *sb, struct inode *inode);

int scoutfs_quota_get_rules(struct super_block *sb, u64 *iterator,
			    struct scoutfs_ioctl_quota_rule *irules, int nr);
int scoutfs_quota_mod_rule(struct super_block *sb, bool is_add,
			   struct scoutfs_ioctl_quota_rule *irule);

void scoutfs_quota_get_lock_range(struct scoutfs_key *start, struct scoutfs_key *end);
void scoutfs_quota_invalidate(struct super_block *sb);

int scoutfs_quota_setup(struct super_block *sb);
void scoutfs_quota_destroy(struct super_block *sb);

#endif
