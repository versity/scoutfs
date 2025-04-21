/*
 * Copyright (C) 2023 Versity Software, Inc.  All rights reserved.
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
#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/time.h>
#include <linux/rhashtable.h>
#include <linux/random.h>
#include <linux/bsearch.h>
#include <linux/sort.h>

#include "format.h"
#include "super.h"
#include "lock.h"
#include "hash.h"
#include "inode.h"
#include "item.h"
#include "ioctl.h"
#include "cmp.h"
#include "wkic.h"
#include "xattr.h"
#include "totl.h"
#include "util.h"
#include "quota.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * scoutfs quotas let userspace manage accounting and rules which
 * specify when operations should fail because a quota is exceeded.
 *
 * Userspace is responsible for managing the .totl. xattrs that
 * accumulate counts and totals that can be checked to enforce quotas.
 * Userspace then builds quota rules that map operations to totl names
 * and limits.  This puts userspace entirely in control of the quota
 * policy.
 *
 * The quota checks are specifically allowed to use slightly stale data
 * to avoid global locking bottlenecks.
 *
 * Rules are stored as items in the main fs btree and are subject strict
 * consistency cluster locking.  After any change to rules all the rules
 * will be read in again and processed for checking.
 *
 * The .totl. xattrs are not read under cluster locking to avoid lock
 * contention.  They're read using the weak item cache which expires
 * only on a timeout.  This leads to a regular background load of weak
 * reads of the item totls as they're updated at the frequency of the
 * cache expiration.
 */

#define CACHE_AGE_MS		(5 * MSEC_PER_SEC)

/*
 * Rules are stored in trees whose nodes are keyed by their input
 * matching criteria.  The trees are not modified once they're visible
 * to readers.  RCU is used to free the trees once all the readers have
 * finished.
 */
struct squota_ruleset {
	struct rcu_head rcu;
	struct rb_root roots[SQ_NS__NR_SELECT];
	struct squota_rule *defaults[SQ_OP__NR];
};

struct squota_info {
	struct super_block *sb;
	struct squota_ruleset __rcu *ruleset; /* ENOENT, EINVAL, EBUSY, or valid ptr */
	struct rhashtable check_ht;
	atomic64_t nr_checks;

	struct rw_semaphore rwsem;
	spinlock_t lock;
	wait_queue_head_t waitq;
	KC_DEFINE_SHRINKER(shrinker);
	struct dentry *drop_dentry;
};

#define DECLARE_QUOTA_INFO(sb, name) \
	struct squota_info *name = SCOUTFS_SB(sb)->squota_info

static inline int quota_unsupported(struct super_block *sb)
{
	return scoutfs_fmt_vers_unsupported(sb, SCOUTFS_FORMAT_VERSION_FEAT_QUOTA);
}

struct squota_check {
	struct rcu_head rcu;
	struct rhash_head head;
	struct squota_input inp;
	ktime_t expiration;
	int result;
};

static const struct rhashtable_params check_ht_params = {
	.key_len = member_sizeof(struct squota_check, inp),
	.key_offset = offsetof(struct squota_check, inp),
	.head_offset = offsetof(struct squota_check, head),
};

static bool get_cached_check(struct squota_info *qtinf, struct squota_input *inp, int *result)
{
	struct squota_check *chk;
	bool got;

	if (WARN_ON_ONCE(!rcu_read_lock_held()))
		return false;

	chk = rhashtable_lookup(&qtinf->check_ht, inp, check_ht_params);
	if (chk && ktime_after(chk->expiration, ktime_get_raw())) {
		*result = chk->result;
		got = true;
	} else {
		*result = 0;
		got = false;
	}

	return got;
}

/*
 * Insert a new cached check.  If a cached check already exists its
 * either timed out or was inserted very recently so either can be used.
 * We abandon the insertion attempt on other errors, including
 * allocation failures and insertion failure from a pending hash table
 * resize.
 */
static void insert_cached_check(struct squota_info *qtinf, struct squota_input *inp, int result)
{
	struct squota_check *found;
	struct squota_check *chk;
	int ret;

	/* zero full size for hash table memcmp */
	chk = kzalloc(sizeof(struct squota_check), GFP_NOFS);
	if (!chk)
		return;

	chk->inp = *inp;
	chk->expiration = ktime_add_ms(ktime_get_raw(), CACHE_AGE_MS);
	chk->result = result;

	while (chk) {
		ret = rhashtable_lookup_insert_fast(&qtinf->check_ht, &chk->head,
						    check_ht_params);
		if (ret == 0) {
			atomic64_inc(&qtinf->nr_checks);
			chk = NULL;

		} else if (ret == -EEXIST) {
			/* try to free older insertion or existing */
			rcu_read_lock();
			found = rhashtable_lookup(&qtinf->check_ht, inp, check_ht_params);
			if (found) {
				if (ktime_before(found->expiration, chk->expiration)) {
					if (rhashtable_remove_fast(&qtinf->check_ht,
								   &found->head,
								   check_ht_params) == 0) {
						kfree_rcu(found, rcu);
						atomic64_dec(&qtinf->nr_checks);
					}
				} else {
					kfree(chk);
					chk = NULL;
				}
			}
			rcu_read_unlock();

		} else {
			kfree(chk);
			chk = NULL;
		}
	}
}

/*
 * Return a random cached check from the hash table.  We sweep the
 * buckets from a random starting point and return the first we find,
 * continuing from the next table if it's resizing.  This is sort of
 * like the _walk_ api but we can set the starting point and it doesn't
 * return -EAGAIN while resizing.
 */
static struct squota_check *lookup_random_check(struct rhashtable *rht)
{
	struct bucket_table *tbl;
	struct squota_check *chk;
	struct rhash_head *pos;
	unsigned long s;
	unsigned long i;

	WARN_ON_ONCE(!rcu_read_lock_held());

	tbl = rht_dereference_rcu(rht->tbl, rht);
	do {
		for (s = 0, i = get_random_u32_below(tbl->size);
		     s < tbl->size;
		     s++, i = (i + 1) % tbl->size) {
			rht_for_each_entry_rcu(chk, pos, tbl, i, head) {
				return chk;
			}
		}
	} while (!IS_ERR_OR_NULL((tbl = rht_dereference_rcu(tbl->future_tbl, rht))));

	return NULL;
}

static unsigned long count_cached_checks(struct shrinker *shrink, struct shrink_control *sc)
{
	struct squota_info *qtinf = KC_SHRINKER_CONTAINER_OF(shrink, struct squota_info);

	scoutfs_inc_counter(qtinf->sb, quota_info_count_objects);

	return shrinker_min_long(atomic64_read(&qtinf->nr_checks));
}

/*
 * We don't bother with any precise replacement mechanism.  We choose
 * cached check results to drop at random.  If the cache is large then
 * random choices are unlikely to have been used again.  If the cache is
 * small then any choices end up blowing away most of the cache.
 */
static unsigned long scan_cached_checks(struct shrinker *shrink, struct shrink_control *sc)
{
	struct squota_info *qtinf = KC_SHRINKER_CONTAINER_OF(shrink, struct squota_info);
	unsigned long nr = sc->nr_to_scan;
	unsigned int retries = 10;
	unsigned long freed = 0;
	struct squota_check *chk;
	int err;

	scoutfs_inc_counter(qtinf->sb, quota_info_scan_objects);

	rcu_read_lock();

	while (nr > 0 && retries > 0 && (chk = lookup_random_check(&qtinf->check_ht))) {
		err = rhashtable_remove_fast(&qtinf->check_ht, &chk->head, check_ht_params);
		if (err) {
			retries--;
			continue;
		}

		kfree_rcu(chk, rcu);
		atomic64_dec(&qtinf->nr_checks);
		freed++;
		nr--;
	}

	rcu_read_unlock();

	if (retries == 0 && freed == 0)
		freed = SHRINK_STOP;

	return freed;
}

static void shrink_all_cached_checks(struct squota_info *qtinf)
{
	struct shrink_control sc = { .nr_to_scan = LONG_MAX, };

	scan_cached_checks(KC_SHRINKER_FN(&qtinf->shrinker), &sc);
}

static u8 ns_is_attr(u8 ns)
{
	switch (ns) {
	case SQ_NS_PROJ:
	case SQ_NS_UID:
	case SQ_NS_GID:
		return true;
	default:
		return false;
	}
}

/* rule validation has made sure these derefs are safe */
static u8 ns_to_attr(u8 ns)
{
	static u8 ind[] = {
		[SQ_NS_PROJ] = 0,
		[SQ_NS_UID] = 1,
		[SQ_NS_GID] = 2,
	};

	return ind[ns];
}

static void rule_to_rule_val(struct scoutfs_quota_rule_val *rv, struct squota_rule *rule)
{
	rv->limit = cpu_to_le64(rule->limit);
	rv->prio = rule->prio;
	rv->op = rule->op;
	rv->rule_flags = rule->rule_flags;
	rv->name_val[0] = cpu_to_le64(rule->names[0].val);
	rv->name_source[0] = rule->names[0].source;
	rv->name_flags[0] = rule->names[0].flags;
	rv->name_val[1] = cpu_to_le64(rule->names[1].val);
	rv->name_source[1] = rule->names[1].source;
	rv->name_flags[1] = rule->names[1].flags;
	rv->name_val[2] = cpu_to_le64(rule->names[2].val);
	rv->name_source[2] = rule->names[2].source;
	rv->name_flags[2] = rule->names[2].flags;
	memset(&rv->_pad, 0, sizeof(rv->_pad));
}

static void rule_to_irule(struct scoutfs_ioctl_quota_rule *irule, struct squota_rule *rule)
{
	irule->limit = rule->limit;
	irule->prio = rule->prio;
	irule->op = rule->op;
	irule->rule_flags = rule->rule_flags;
	irule->name_val[0] = rule->names[0].val;
	irule->name_source[0] = rule->names[0].source;
	irule->name_flags[0] = rule->names[0].flags;
	irule->name_val[1] = rule->names[1].val;
	irule->name_source[1] = rule->names[1].source;
	irule->name_flags[1] = rule->names[1].flags;
	irule->name_val[2] = rule->names[2].val;
	irule->name_source[2] = rule->names[2].source;
	irule->name_flags[2] = rule->names[2].flags;
	memset(&irule->_pad, 0, sizeof(irule->_pad));
}

/*
 * We verify rules coming from untrusted ioctls/storage.
 */
static bool valid_rule(struct squota_rule *rule)
{
	struct squota_rule_name *other;
	struct squota_rule_name *name;
	int i;
	int j;

	/* invalid op */
	if (rule->op > SQ_OP__NR)
		return false;

	if (rule->rule_flags & SQ_RF__UNKNOWN)
		return false;

	for (i = 0; i < ARRAY_SIZE(rule->names); i++) {
		name = &rule->names[i];

		/* unknown name flags */
		if (name->flags & SQ_NF__UNKNOWN)
			return false;

		if ((name->flags & SQ_NF_SELECT)) {
			/* can only select sources that are inode attributes */
			if (!ns_is_attr(name->source))
				return false;

			for (j = 0; j < ARRAY_SIZE(rule->names); j++) {
				if (i == j)
					continue;
				other = &rule->names[j];

				/* can't select different values of same attr */
				if ((other->flags & SQ_NF_SELECT) &&
				    name->source == other->source &&
				    name->val != other->val) {
					return false;
				}
			}
		}
	}

	return true;
}

static int rule_val_to_rule(struct squota_rule *rule, struct scoutfs_quota_rule_val *rv,
			    int bytes)
{
	if (bytes != sizeof(struct scoutfs_quota_rule_val))
		return -EIO;

	rule->limit = le64_to_cpu(rv->limit);
	rule->prio = rv->prio;
	rule->op = rv->op;
	rule->rule_flags = rv->rule_flags;
	rule->names[0].val = le64_to_cpu(rv->name_val[0]);
	rule->names[0].source = rv->name_source[0];
	rule->names[0].flags = rv->name_flags[0];
	rule->names[1].val = le64_to_cpu(rv->name_val[1]);
	rule->names[1].source = rv->name_source[1];
	rule->names[1].flags = rv->name_flags[1];
	rule->names[2].val = le64_to_cpu(rv->name_val[2]);
	rule->names[2].source = rv->name_source[2];
	rule->names[2].flags = rv->name_flags[2];

	if (!valid_rule(rule))
		return -EIO;

	return 0;
}

static int irule_to_rule(struct squota_rule *rule, struct scoutfs_ioctl_quota_rule *irule)
{
	rule->limit = irule->limit;
	rule->prio = irule->prio;
	rule->op = irule->op;
	rule->rule_flags = irule->rule_flags;
	rule->names[0].val = irule->name_val[0];
	rule->names[0].source = irule->name_source[0];
	rule->names[0].flags = irule->name_flags[0];
	rule->names[1].val = irule->name_val[1];
	rule->names[1].source = irule->name_source[1];
	rule->names[1].flags = irule->name_flags[1];
	rule->names[2].val = irule->name_val[2];
	rule->names[2].source = irule->name_source[2];
	rule->names[2].flags = irule->name_flags[2];

	if (!valid_rule(rule))
		return -EINVAL;

	return 0;
}

static void init_rule_key(struct scoutfs_key *key, u64 hash, u64 coll_nr)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_QUOTA_ZONE,
		.sk_type = SCOUTFS_QUOTA_RULE_TYPE,
		.skqr_hash = cpu_to_le64(hash),
		.skqr_coll_nr = cpu_to_le64(coll_nr),
	};
}

static void rule_to_key(struct scoutfs_key *key, struct squota_rule *rule)
{
	struct scoutfs_quota_rule_val rv;

	rule_to_rule_val(&rv, rule);
	init_rule_key(key, scoutfs_hash64(&rv, sizeof(rv)), 0);
}

/*
 * Callers specifically want to increase keys by increasing the
 * collision nr, not just incing the key.
 */
static void inc_coll_nr(struct scoutfs_key *key)
{
	le64_add_cpu(&key->skqr_coll_nr, 1);
	if (key->skqr_coll_nr == 0)
		le64_add_cpu(&key->skqr_hash, 1);
}

/*
 * Rules have a defined sort order that determines matching priority
 * when multiple rules match an input.
 */
static int cmp_rules(struct squota_rule *a, struct squota_rule *b)
{
	return scoutfs_cmp(a->prio, b->prio) ?:
	       scoutfs_cmp(a->names[0].val, b->names[0].val) ?:
	       scoutfs_cmp(a->names[0].source, b->names[0].source) ?:
	       scoutfs_cmp(a->names[0].flags, b->names[0].flags) ?:
	       scoutfs_cmp(a->names[1].val, b->names[1].val) ?:
	       scoutfs_cmp(a->names[1].source, b->names[1].source) ?:
	       scoutfs_cmp(a->names[1].flags, b->names[1].flags) ?:
	       scoutfs_cmp(a->names[2].val, b->names[2].val) ?:
	       scoutfs_cmp(a->names[2].source, b->names[2].source) ?:
	       scoutfs_cmp(a->names[2].flags, b->names[2].flags) ?:
	       scoutfs_cmp(a->op, b->op) ?:
	       scoutfs_cmp(a->limit, b->limit) ?:
	       scoutfs_cmp(a->rule_flags, b->rule_flags);
}

static struct squota_rule *name_to_rule(struct squota_rule_name *name)
{
	return container_of(name, struct squota_rule, names[name->i]);
}

static bool unlinked_rule(struct squota_rule *rule)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rule->names); i++) {
		if (!RB_EMPTY_NODE(&rule->names[i].node))
			return false;
	}

	return true;
}

static void free_ruleset(struct squota_ruleset *rs)
{
	struct squota_rule_name *name;
	struct squota_rule_name *name_;
	struct squota_rule *rule;
	int i;

	if (!IS_ERR_OR_NULL(rs)) {
		for (i = 0; i < ARRAY_SIZE(rs->roots); i++) {
			rbtree_postorder_for_each_entry_safe(name, name_, &rs->roots[i], node) {
				RB_CLEAR_NODE(&name->node);

				rule = name_to_rule(name);
				if (unlinked_rule(rule))
					kfree(rule);
			}
		}

		for (i = 0; i < ARRAY_SIZE(rs->defaults); i++)
			kfree(rs->defaults[i]);

		kfree(rs);
	}
}

static void free_ruleset_rcu(struct rcu_head *rcu)
{
	struct squota_ruleset *rs = container_of(rcu, struct squota_ruleset, rcu);

	free_ruleset(rs);
}

static bool empty_ruleset(struct squota_ruleset *rs)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rs->roots); i++) {
		if (!RB_EMPTY_ROOT(&rs->roots[i]))
			return false;
	}
	for (i = 0; i < ARRAY_SIZE(rs->defaults); i++) {
		if (rs->defaults[i])
			return false;
	}

	return true;
}

/*
 * Walk a rule tree for a given matching attr.  Each tree only contains
 * names which select on the tree's attr so we only have to compare each
 * name's value, not its flags or source.
 *
 * The tree allows multiple names with a given val.  The first match is
 * found and callers can iterate through all matches with _next.
 */
static struct squota_rule_name *walk_rule_tree(struct rb_root *root, u64 val,
					       struct squota_rule_name *ins)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;
	struct squota_rule_name *found = NULL;
	struct squota_rule_name *name;
	int cmp;

	while (*node) {
		parent = *node;
		name = container_of(*node, struct squota_rule_name, node);

		cmp = scoutfs_cmp(name->val, val);
		if (cmp < 0) {
			node = &(*node)->rb_left;
		} else if (cmp > 0) {
			node = &(*node)->rb_right;
		} else {
			found = name;
			node = &(*node)->rb_left;
		}
	}

	if (ins) {
		rb_link_node(&ins->node, parent, node);
		rb_insert_color(&ins->node, root);
	}

	return found;
}

/*
 * Return the next name in the ruleset attr tree that matches the val.
 * All the nodes match this attribute, so we only have to compare the
 * val.
 */
static struct squota_rule_name *next_val_name(struct squota_rule_name *name)
{
	struct squota_rule_name *next;
	struct rb_node *node;

	if (!name || RB_EMPTY_NODE(&name->node))
		return NULL;

	node = rb_next(&name->node);
	if (node) {
		next = container_of(node, struct squota_rule_name, node);
		if (next->val == name->val)
			return next;
	}

	return NULL;
}

static bool ruleset_is_busy(struct squota_info *qtinf)
{
	bool busy;

	rcu_read_lock();
	busy = rcu_dereference(qtinf->ruleset) == ERR_PTR(-EBUSY);
	rcu_read_unlock();

	return busy;
}

/*
 * The caller found that we didn't have a valid ruleset and wants us to
 * read in a new ruleset.
 *
 * We get exclusive access to the rules by marking the ruleset pointer
 * busy, possibly waiting for someone else to finish if they beat us to
 * it.  If we get exclusive access then we walk all the rule items and
 * build up a rule set and publish it for use.
 */
static int read_ruleset(struct super_block *sb, struct squota_info *qtinf)
{
	struct scoutfs_lock *lock = NULL;
	struct squota_ruleset *rs = NULL;
	struct scoutfs_quota_rule_val rv;
	struct squota_rule *rule = NULL;
	struct squota_rule_name *name;
	struct scoutfs_key key;
	struct scoutfs_key end;
	bool reading = false;
	int ret;
	int i;

	ret = scoutfs_lock_quota(sb, SCOUTFS_LOCK_READ, 0, &lock);
	if (ret < 0)
		goto out;

	spin_lock(&qtinf->lock);
	rs = rcu_dereference_protected(qtinf->ruleset, lockdep_is_held(&qtinf->lock));
	if (rs == ERR_PTR(-EINVAL)) {
		rs = ERR_PTR(-EBUSY);
		rcu_assign_pointer(qtinf->ruleset, rs);
		reading = true;
	}
	spin_unlock(&qtinf->lock);

	if (!reading) {
		wait_event(qtinf->waitq, !ruleset_is_busy(qtinf));
		ret = 0;
		goto out;
	}

	rs = kzalloc(sizeof(struct squota_ruleset), GFP_NOFS);
	if (!rs) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(rs->roots); i++)
		rs->roots[i] = RB_ROOT;

	init_rule_key(&key, 0, 0);
	init_rule_key(&end, U64_MAX, U64_MAX);

	for (;;) {
		if (!rule) {
			rule = kmalloc(sizeof(struct squota_rule), GFP_NOFS);
			if (!rule) {
				ret = -ENOMEM;
				goto out;
			}
		}

		ret = scoutfs_item_next(sb, &key, &end, &rv, sizeof(rv), lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			goto out;
		}

		ret = rule_val_to_rule(rule, &rv, ret);
		if (ret < 0)
			goto out;

		/* insert rule into attr tree if any of its names select */
		for (i = 0; i < ARRAY_SIZE(rule->names); i++) {
			name = &rule->names[i];
			name->i = i;

			if (name->flags & SQ_NF_SELECT) {
				walk_rule_tree(&rs->roots[ns_to_attr(name->source)],
					       name->val, name);
			} else {
				RB_CLEAR_NODE(&name->node);
			}
		}


		if (!unlinked_rule(rule))
			rule = NULL;

		/* remember highest priority unlinked (default) rule */
		if (rule &&
		    (!rs->defaults[rule->op] || cmp_rules(rule, rs->defaults[rule->op]) > 0)) {
			rs->defaults[rule->op] = rule;
			rule = NULL;
		}

		inc_coll_nr(&key);
	}

out:
	if (reading) {
		if (ret == 0 && empty_ruleset(rs)) {
			free_ruleset(rs);
			rs = ERR_PTR(-ENOENT);
		}

		if (ret < 0) {
			free_ruleset(rs);
			rs = ERR_PTR(-EINVAL);
		}

		spin_lock(&qtinf->lock);
		rcu_assign_pointer(qtinf->ruleset, rs);
		spin_unlock(&qtinf->lock);
		wake_up(&qtinf->waitq);
	}

	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);

	kfree(rule);

	return ret;
}

/*
 * A rule matches input when the ops match and all of the rule's key
 * name selectors match the input -- non-selecting key names always
 * match.
 */
static bool rule_matches(struct squota_input *inp, struct squota_rule *rule)
{
	struct squota_rule_name *name;
	int i;

	if (inp->op != rule->op)
		return false;

	for (i = 0; i < ARRAY_SIZE(rule->names); i++) {
		name = &rule->names[i];

		if ((name->flags & SQ_NF_SELECT) &&
		    (inp->attrs[ns_to_attr(name->source)] != name->val))
			return false;
	}

	return true;
}

struct squota_totl_check {
	u64 totl[3];
	u64 limit;
	u8 rule_flags;
};

/*
 * Check the rules against the caller's inputs.  We start with the
 * highest priority default rule for the operation then search all the
 * rules that select for any of the input's attrs and use the highest
 * priority match.
 *
 * If we find a matching rule then we give the caller the totl xattr
 * name and limit to check.
 */
static bool check_rules(struct squota_ruleset *rs, struct squota_input *inp,
			struct squota_totl_check *tc)
{
	struct squota_rule_name *name;
	struct squota_rule *match;
	struct squota_rule *rule;
	int i;

	if (WARN_ON_ONCE(!rcu_read_lock_held()))
		return false;

	match = rs->defaults[inp->op];

	for (i = 0; i < SQ_NS__NR_SELECT; i++) {
		name = walk_rule_tree(&rs->roots[i], inp->attrs[i], NULL);
		while (name) {
			rule = name_to_rule(name);
			if (rule_matches(inp, rule) && (!match || cmp_rules(rule, match) > 0))
				match = rule;
			name = next_val_name(name);
		}
	}

	if (match) {
		for (i = 0; i < ARRAY_SIZE(match->names); i++) {
			name = &match->names[i];

			if (ns_is_attr(name->source))
				tc->totl[i] = inp->attrs[ns_to_attr(name->source)];
			else
				tc->totl[i] = name->val; /* LITERAL is only non-attr source */
		}

		tc->limit = match->limit;
		tc->rule_flags = match->rule_flags;
		return true;
	}

	return false;
}

static int check_totl_cb(struct scoutfs_key *key, void *val, unsigned int val_len, void *cb_arg)
{
	struct scoutfs_xattr_totl_val *tval = val;
	struct squota_totl_check *tc = cb_arg;
	u64 use;

	if (val_len != sizeof(struct scoutfs_xattr_totl_val))
		return -EIO;

	if (tc->rule_flags & SQ_RF_TOTL_COUNT)
		use = le64_to_cpu(tval->count);
	else
		use = le64_to_cpu(tval->total);

	return use >= tc->limit ? -EDQUOT : 0;
}

/*
 * Check that operations can be performed on the given inode.  The rules
 * are protected by cluster locking and re-read any time the lock is
 * revoked.  The xattr totl items are read from the weak item cache and
 * can be a little out of date.  Check results are also cached so we can
 * rely on those while the current persistent items would produce a
 * different result.
 */
static int check_inputs(struct super_block *sb, struct squota_input *inp)
{
	DECLARE_QUOTA_INFO(sb, qtinf);
	struct squota_ruleset *rs = NULL;
	struct scoutfs_key range_start;
	struct scoutfs_key range_end;
	struct scoutfs_key key;
	struct squota_totl_check tc;
	bool found;
	int ret;

	rcu_read_lock();

	/* quick fast path check when there are no quota rules */
	rs = rcu_dereference(qtinf->ruleset);
	if (rs == ERR_PTR(-ENOENT)) {
		rcu_read_unlock();
		ret = 0;
		goto out;
	}

	/* see if we have a cached check result */
	if (get_cached_check(qtinf, inp, &ret)) {
		rcu_read_unlock();
		goto out;
	}

	/* get the current ruleset, blocking to lock+read if we need to read items */
	while ((rs = rcu_dereference(qtinf->ruleset)),
	       (rs == ERR_PTR(-EINVAL) || rs == ERR_PTR(-EBUSY))) {
		rcu_read_unlock();

		ret = read_ruleset(sb, qtinf);
		if (ret < 0)
			goto out;

		rcu_read_lock();
	}

	/* see if we have a matching rule for our inputs */
	if (!IS_ERR(rs))
		found = check_rules(rs, inp, &tc);
	else
		found = NULL;

	rcu_read_unlock();

	/* check if the totl limit was exceeded if we found a rule */
	if (found) {
		scoutfs_totl_set_range(&range_start, &range_end);
		scoutfs_xattr_init_totl_key(&key, tc.totl);

		ret = scoutfs_wkic_iterate(sb, &key, &key, &range_start, &range_end,
					   check_totl_cb, &tc);

		trace_scoutfs_quota_totl_check(sb, inp, &key, tc.limit, ret);
	} else {
		ret = 0;
	}

	if (ret == 0 || ret == -EDQUOT)
		insert_cached_check(qtinf, inp, ret);
out:
	trace_scoutfs_quota_check(sb, (long)rs, inp, ret);
	return ret;
}

static void init_inp(struct squota_input *inp, u64 proj, u32 uid, u32 gid, u8 op)
{
	/* zero full size for hash table memcmp */
	memset(inp, 0, sizeof(struct squota_input));

	inp->attrs[ns_to_attr(SQ_NS_PROJ)] = proj;
	inp->attrs[ns_to_attr(SQ_NS_UID)] = uid;
	inp->attrs[ns_to_attr(SQ_NS_GID)] = gid;
	inp->op = op;
}

/*
 * The [ug]id initialization here mirrors init_inode_owner() but that
 * takes a live inode struct and our cluster lock and transaction
 * layering makes that awkward.
 */
int scoutfs_quota_check_inode(struct super_block *sb, struct inode *dir)
{
	struct squota_input inp;

	if (quota_unsupported(sb))
		return 0;

	BUILD_BUG_ON(max(sizeof(uid_t), sizeof(gid_t)) > sizeof(u32));

	init_inp(&inp, scoutfs_inode_get_proj(dir), from_kuid(&init_user_ns, current_fsuid()),
		 (dir->i_mode & S_ISGID) ? i_gid_read(dir) :
					   from_kgid(&init_user_ns, current_fsgid()),
		 SQ_OP_INODE);

	return check_inputs(sb, &inp);
}

int scoutfs_quota_check_data(struct super_block *sb, struct inode *inode)
{
	struct squota_input inp;

	if (quota_unsupported(sb))
		return 0;

	init_inp(&inp, scoutfs_inode_get_proj(inode), i_uid_read(inode), i_gid_read(inode),
	         SQ_OP_DATA);

	return check_inputs(sb, &inp);
}

/*
 * Read rules from the iterator position into the caller's irules
 * buffer.  We set the iterator to point past the last irules we return
 * so that it can be used to continue iteration.
 */
int scoutfs_quota_get_rules(struct super_block *sb, u64 *iterator,
			    struct scoutfs_ioctl_quota_rule *irules, int nr)
{
	DECLARE_QUOTA_INFO(sb, qtinf);
	struct scoutfs_quota_rule_val rv;
	struct scoutfs_lock *lock = NULL;
	struct squota_rule rule;
	struct scoutfs_key key;
	struct scoutfs_key end;
	int copied = 0;
	int ret = 0;

	if ((ret = quota_unsupported(sb)))
		return ret;

	if (nr == 0)
		goto out;

	ret = scoutfs_lock_quota(sb, SCOUTFS_LOCK_READ, 0, &lock);
	if (ret < 0)
		goto out;

	down_read(&qtinf->rwsem);

	init_rule_key(&key, iterator[0], iterator[1]);
	init_rule_key(&end, U64_MAX, U64_MAX);

	while (copied < nr) {
		ret = scoutfs_item_next(sb, &key, &end, &rv, sizeof(rv), lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		ret = rule_val_to_rule(&rule, &rv, ret);
		if (ret < 0)
			break;

		rule_to_irule(&irules[copied], &rule);
		copied++;

		inc_coll_nr(&key);
		iterator[0] = le64_to_cpu(key.skqr_hash);
		iterator[1] = le64_to_cpu(key.skqr_coll_nr);
	}

	up_read(&qtinf->rwsem);
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
out:
	return ret ?: copied;
}

/*
 * Search through rule items with the search hash value looking for a
 * match.  The return key is set to either the rule we found or the next
 * unused collision nr.  Returns 0 if found, -ENOENT if not, and -errno
 * for errors.
 */
static int find_rule(struct super_block *sb, struct squota_rule *rule, struct scoutfs_key *key_ret,
		     struct scoutfs_lock *lock)
{
	struct scoutfs_quota_rule_val rv;
	struct squota_rule found;
	struct scoutfs_key key;
	struct scoutfs_key end;
	int ret;

	rule_to_key(&key, rule);
	end = key;
	end.skqr_coll_nr = cpu_to_le64(U64_MAX);

	for (;;) {
		ret = scoutfs_item_next(sb, &key, &end, &rv, sizeof(rv), lock);
		if (ret < 0)
			break;

		ret = rule_val_to_rule(&found, &rv, ret);
		if (ret)
			break;

		if (cmp_rules(&found, rule) == 0) {
			ret = 0;
			break;
		}

		inc_coll_nr(&key);
	}

	*key_ret = key;
	return ret;
}

/*
 * Modify a rule.  This only operates on the persistent items.  It holds
 * a write cluster lock so it invalidates all other rules used by other
 * nodes and also marks the local rules invalid.  The next enforcement
 * everywhere will re-read and process the full rule set.  All this
 * makes rule set modification expensive but it should be
 * correspondingly rare.
 */
int scoutfs_quota_mod_rule(struct super_block *sb, bool is_add,
			   struct scoutfs_ioctl_quota_rule *irule)
{
	DECLARE_QUOTA_INFO(sb, qtinf);
	struct scoutfs_quota_rule_val rv;
	struct scoutfs_lock *lock = NULL;
	struct squota_rule rule;
	struct scoutfs_key key;
	int ret;

	if ((ret = quota_unsupported(sb)))
		return ret;

	ret = irule_to_rule(&rule, irule);
	if (ret < 0)
		goto out;

	ret = scoutfs_lock_quota(sb, SCOUTFS_LOCK_WRITE, 0, &lock);
	if (ret < 0)
		goto out;

	down_write(&qtinf->rwsem);

	if (is_add) {
		ret = find_rule(sb, &rule, &key, lock);
		if (ret == -ENOENT)
			ret = 0;
		else if (ret == 0)
			ret = -EEXIST;
		if (ret < 0)
			goto unlock;

		rule_to_rule_val(&rv, &rule);
		ret = scoutfs_item_create(sb, &key, &rv, sizeof(rv), lock);
		if (ret < 0)
			goto unlock;

	} else {
		ret = find_rule(sb, &rule, &key, lock) ?:
		      scoutfs_item_delete(sb, &key, lock);
		if (ret < 0)
			goto unlock;
	}

	scoutfs_quota_invalidate(sb);
	ret = 0;

unlock:
	up_write(&qtinf->rwsem);
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_WRITE);

out:
	if (is_add)
		trace_scoutfs_quota_add_rule(sb, &rule, ret);
	else
		trace_scoutfs_quota_del_rule(sb, &rule, ret);

	return ret;
}

void scoutfs_quota_get_lock_range(struct scoutfs_key *start, struct scoutfs_key *end)
{
	scoutfs_key_set_zeros(start);
	start->sk_zone = SCOUTFS_QUOTA_ZONE;

	scoutfs_key_set_ones(end);
	end->sk_zone = SCOUTFS_QUOTA_ZONE;
}

/*
 * This is called during cluster lock invalidation to indicate that the
 * ruleset is no longer protected by cluster locking and might have been
 * modified.  We mark the ruleset invalid and free it once all readers
 * drain.  The next check will acquire the cluster lock and read the
 * rules.  Because this is called during invalidation this is serialized
 * with write holders of cluster locks so we can never see -EBUSY here.
 */
void scoutfs_quota_invalidate(struct super_block *sb)
{
	DECLARE_QUOTA_INFO(sb, qtinf);
	struct squota_ruleset *rs;

	if (quota_unsupported(sb))
		return;

	rcu_read_lock();

	spin_lock(&qtinf->lock);
	rs = rcu_dereference_protected(qtinf->ruleset, lockdep_is_held(&qtinf->lock));
	if (rs != ERR_PTR(-EINVAL))
		rcu_assign_pointer(qtinf->ruleset, ERR_PTR(-EINVAL));
	spin_unlock(&qtinf->lock);

	/* cluster locking should have prevented this */
	BUG_ON(rs == ERR_PTR(-EBUSY));

	if (!IS_ERR(rs))
		call_rcu(&rs->rcu, free_ruleset_rcu);

	rcu_read_unlock();

	shrink_all_cached_checks(qtinf);
}

static ssize_t quota_drop_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	return 0;
}

static ssize_t quota_drop_write(struct file *file, const char __user *buf, size_t size,
				loff_t *ppos)
{
	struct squota_info *qtinf = file_inode(file)->i_private;

	shrink_all_cached_checks(qtinf);

	return size;
}

static const struct file_operations quota_drop_fops = {
	.read =		quota_drop_read,
	.write =	quota_drop_write,
};

int scoutfs_quota_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct squota_info *qtinf = NULL;
	int ret;

	if (quota_unsupported(sb))
		return 0;

	qtinf = kzalloc(sizeof(struct squota_info), GFP_KERNEL);
	if (!qtinf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = rhashtable_init(&qtinf->check_ht, &check_ht_params);
	if (ret < 0) {
		kfree(qtinf);
		goto out;
	}

	qtinf->drop_dentry = debugfs_create_file("drop_quota_check_cache", S_IFREG|S_IRUSR,
						sbi->debug_root, qtinf, &quota_drop_fops);
	if (!qtinf->drop_dentry) {
		rhashtable_destroy(&qtinf->check_ht);
		kfree(qtinf);
		return -ENOMEM;
	}

	qtinf->sb = sb;
	RCU_INIT_POINTER(qtinf->ruleset, ERR_PTR(-EINVAL));
	atomic64_set(&qtinf->nr_checks, 0);
	init_rwsem(&qtinf->rwsem);
	spin_lock_init(&qtinf->lock);
	init_waitqueue_head(&qtinf->waitq);

	KC_INIT_SHRINKER_FUNCS(&qtinf->shrinker, count_cached_checks, scan_cached_checks);
	KC_REGISTER_SHRINKER(&qtinf->shrinker, "scoutfs-quota:" SCSBF, SCSB_ARGS(sb));

	sbi->squota_info = qtinf;

	ret = 0;
out:
	return ret;
}

static void free_cached_check(void *ptr, void *arg)
{
	struct squota_check *chk = ptr;

	kfree(chk);
}

void scoutfs_quota_destroy(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	DECLARE_QUOTA_INFO(sb, qtinf);
	struct squota_ruleset *rs;

	if (qtinf) {
		debugfs_remove(qtinf->drop_dentry);
		KC_UNREGISTER_SHRINKER(&qtinf->shrinker);

		spin_lock(&qtinf->lock);
		rs = rcu_dereference_protected(qtinf->ruleset, lockdep_is_held(&qtinf->lock));
		spin_unlock(&qtinf->lock);
		if (!IS_ERR(rs))
			free_ruleset(rs);

		rhashtable_free_and_destroy(&qtinf->check_ht, free_cached_check, NULL);

		kfree(qtinf);
		sbi->squota_info = NULL;
	}
}
