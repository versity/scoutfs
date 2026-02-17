/*
 * Copyright (C) 2026 Versity Software, Inc.  All rights reserved.
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
#include <linux/list_sort.h>
#include <linux/sort.h>

#include "format.h"
#include "key.h"
#include "block.h"
#include "inode.h"
#include "forest.h"
#include "client.h"
#include "ioctl.h"
#include "lock.h"
#include "xattr.h"
#include "attr_x.h"
#include "bsearch_index.h"
#include "raw.h"

struct fs_item {
	struct list_head head;
	struct scoutfs_key key;
	u64 seq;
	int val_len;
	bool deletion;
	/* val is aligned so we can deref structs in vals */
	u8 val[0] __aligned(ARCH_KMALLOC_MINALIGN);
};

static int save_fs_item(struct list_head *list, struct scoutfs_key *key, u64 seq, u8 flags,
			void *val, int val_len)
{
	struct fs_item *fsi;

	/* max btree val len is hundreds of bytes */
	fsi = kmalloc(offsetof(struct fs_item, val[val_len]), GFP_NOFS);
	if (!fsi)
		return -ENOMEM;

	fsi->key = *key;
	fsi->seq = seq;
	fsi->val_len = val_len;
	fsi->deletion = !!(flags & SCOUTFS_ITEM_FLAG_DELETION);
	if (val_len > 0)
		memcpy(fsi->val, val, val_len);
	list_add_tail(&fsi->head, list);

	return 0;
}

static void free_fs_item(struct fs_item *fsi)
{
	if (!list_empty(&fsi->head))
		list_del_init(&fsi->head);
	kfree(fsi);
}

static void free_fs_items(struct list_head *list)
{
	struct fs_item *fsi;
	struct fs_item *tmp;

	list_for_each_entry_safe(fsi, tmp, list, head)
		free_fs_item(fsi);
}

static struct fs_item *next_fs_item(struct list_head *list, struct fs_item *fsi)
{
	list_for_each_entry_continue(fsi, list, head)
		return fsi;
	return NULL;
}

static int cmp_fs_items(void *priv, KC_LIST_CMP_CONST struct list_head *A,
			KC_LIST_CMP_CONST struct list_head *B)
{
	KC_LIST_CMP_CONST struct fs_item *a =
		container_of(A, KC_LIST_CMP_CONST struct fs_item, head);
	KC_LIST_CMP_CONST struct fs_item *b =
		container_of(B, KC_LIST_CMP_CONST struct fs_item, head);

	return scoutfs_key_compare(&a->key, &b->key) ?: -scoutfs_cmp(a->seq, b->seq);
}

static void sort_and_remove(struct list_head *list, struct scoutfs_key *end)
{
	struct fs_item *prev;
	struct fs_item *fsi;
	struct fs_item *tmp;

	list_sort(NULL, list, cmp_fs_items);

	/* start by removing any items read before end was decreased by later blocks */
	list_for_each_entry_safe_reverse(fsi, tmp, list, head) {
		if (scoutfs_key_compare(&fsi->key, end) > 0)
			free_fs_item(fsi);
		else
			break;
	}

	prev = NULL;
	list_for_each_entry_safe(fsi, tmp, list, head) {
		/* remove this item if it's an older version of previous item */
		if (prev && scoutfs_key_compare(&prev->key, &fsi->key) == 0) {
			free_fs_item(fsi);
			continue;
		}

		/* remove previous deletion item once it has removed all older versions */
		if (prev && prev->deletion)
			free_fs_item(prev);

		/* next item might match this, record to compare */
		prev = fsi;
	}

	/* remove the last item if it's a deletion */
	list_for_each_entry_reverse(fsi, list, head) {
		if (fsi->deletion)
			free_fs_item(fsi);
		break;
	}
}

static int save_all_items(struct super_block *sb, struct scoutfs_key *key, u64 seq, u8 flags,
			  void *val, int val_len, int fic, void *arg)
{
	struct list_head *list = arg;

	return save_fs_item(list, key, seq, flags, val, val_len);
}

/* -------------- */

static void ms_from_key(struct scoutfs_ioctl_meta_seq *ms, struct scoutfs_key *key)
{
	ms->meta_seq = le64_to_cpu(key->skii_major);
	ms->ino = le64_to_cpu(key->skii_ino);
}

/*
 * Increment the key's ino->meta_seq so that we don't land between items.
 */
static void inc_meta_seq(struct scoutfs_key *key)
{
	le64_add_cpu(&key->skii_ino, 1);
	if (key->skii_ino == 0)
		le64_add_cpu(&key->skii_major, 1);
}

int scoutfs_raw_read_meta_seq(struct super_block *sb,
			      struct scoutfs_ioctl_raw_read_meta_seq *rms,
			      struct scoutfs_ioctl_meta_seq *last_ret)
{
	struct scoutfs_ioctl_meta_seq __user *ums;
	struct scoutfs_ioctl_meta_seq ms;
	struct scoutfs_net_roots roots;
	DECLARE_SAVED_REFS(saved);
	struct scoutfs_key start;
	struct scoutfs_key last;
	struct scoutfs_key key;
	struct scoutfs_key end;
	struct fs_item *fsi;
	struct fs_item *tmp;
	LIST_HEAD(list);
	int retries;
	int copied;
	int count;
	int ret;

	ums = (void __user *)rms->results_ptr;
	count = rms->results_size / sizeof(struct scoutfs_ioctl_meta_seq);
	retries = 10;
	copied = 0;

	scoutfs_inode_init_index_key(&last, SCOUTFS_INODE_INDEX_META_SEQ_TYPE,
				     rms->end.meta_seq, 0, rms->end.ino);

retry:
	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	scoutfs_inode_init_index_key(&key, SCOUTFS_INODE_INDEX_META_SEQ_TYPE,
				     rms->start.meta_seq, 0, rms->start.ino);

	for (;;) {
		start = key;
		end = last;
		ret = scoutfs_forest_read_items_roots(sb, &roots, &key, NULL, &start, &end,
						      save_all_items, &list);
		if (ret < 0)
			goto out;

		sort_and_remove(&list, &end);

		list_for_each_entry_safe(fsi, tmp, &list, head) {

			if (copied == count) {
				/* results are full, set end to before item can't return */
				end = fsi->key;
				le64_add_cpu(&end.skii_ino, -1ULL);
				ret = 0;
				goto out;
			}

			ms_from_key(&ms, &fsi->key);
			if (copy_to_user(&ums[copied], &ms, sizeof(ms))) {
				ret = -EFAULT;
				goto out;
			}

			free_fs_item(fsi);
			copied++;
		}

		if (scoutfs_key_compare(&end, &last) >= 0) {
			end = last;
			break;
		}

		key = end;
		inc_meta_seq(&key);
	}

	ret = 0;
out:
	free_fs_items(&list);

	ret = scoutfs_block_check_stale(sb, ret, &saved, &roots.fs_root.ref, &roots.logs_root.ref);
	if (ret == -ESTALE && copied == 0 && retries-- > 0)
		goto retry;

	ms_from_key(last_ret, &end);

	return ret ?: copied;
}

/* -------------- */

struct inode_info_context {
	size_t nr_inos;
	u64 *inos;

	size_t nr_names;
	struct xattr_name {
		u64 hash;
		char *name;
		u8 name_len; /* no null */
	} *names;

	struct list_head fs_items;
};

static int cmp_u64(const void *A, const void *B)
{
	const u64 *a = A;
	const u64 *b = B;

	return scoutfs_cmp(*a, *b);
}

static int cmp_name_hash(const void *A, const void *B)
{
	const struct xattr_name *a = A;
	const struct xattr_name *b = B;

	return scoutfs_cmp(a->hash, b->hash);
}

static int cmp_name_string(const void *A, const void *B)
{
	const struct xattr_name *a = A;
	const struct xattr_name *b = B;

	return scoutfs_cmp(a->name_len, b->name_len) ?: memcmp(a->name, b->name, a->name_len);
}

static int setup_context(struct inode_info_context *ctx,
			 struct scoutfs_ioctl_raw_read_inode_info *rii)
{
	__u64 __user *uinos = (void __user *)rii->inos_ptr;
	char __user *uname;
	long len_null;
	long len;
	int ret;
	u32 i;

	ctx->nr_inos = rii->inos_count;
	ctx->nr_names = rii->names_count;
	INIT_LIST_HEAD(&ctx->fs_items);

	ctx->inos = kvmalloc_array(ctx->nr_inos, sizeof(ctx->inos[0]), GFP_KERNEL);
	ctx->names = kvcalloc(ctx->nr_names, sizeof(ctx->names[0]), GFP_KERNEL);
	if (!ctx->inos || !ctx->names) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(ctx->inos, uinos, ctx->nr_inos * sizeof(ctx->inos[0]))) {
		ret = -EFAULT;
		goto out;
	}

	/* inos must not be 0 and must increase and contain no duplicates */
	if (ctx->inos[0] == 0) {
		ret = -EINVAL;
		goto out;
	}
	for (i = 1; i < ctx->nr_inos; i++) {
		if (ctx->inos[i] <= ctx->inos[i - 1]) {
			ret = -EINVAL;
			goto out;
		}
	}

	uname = (void __user *)rii->names_ptr;
	for (i = 0; i < ctx->nr_names; i++) {
		len_null = SCOUTFS_XATTR_MAX_NAME_LEN + 1;
		ret = strnlen_user(uname, len_null);
		if (ret <= 1 || ret > len_null) {
			if (ret >= 0)
				ret = -EINVAL;
			goto out;
		}
		len_null = ret;
		len = len_null - 1;

		ctx->names[i].name_len = len;
		ctx->names[i].name = kmalloc(len_null, GFP_KERNEL);
		if (!ctx->names[i].name) {
			ret = -ENOMEM;
			goto out;
		}

		ret = strncpy_from_user(ctx->names[i].name, uname, len_null);
		if (ret != len) {
			if (ret >= 0)
				ret = -EINVAL;
			goto out;
		}

		ctx->names[i].hash = scoutfs_xattr_name_hash(ctx->names[i].name, len);
		uname += len_null;
	}

	/* make sure all the names differ */
	sort(ctx->names, ctx->nr_names, sizeof(ctx->names[0]), cmp_name_string, NULL);
	for (i = 1; i < ctx->nr_names; i++) {
		if (cmp_name_string(&ctx->names[i - 1], &ctx->names[i]) == 0) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* then leave them sorted by hash */
	sort(ctx->names, ctx->nr_names, sizeof(ctx->names[0]), cmp_name_hash, NULL);

	ret = 0;
out:
	return ret;
}

static void free_context(struct inode_info_context *ctx)
{
	int i;

	kvfree(ctx->inos);

	if (ctx->names) {
		for (i = 0; i < ctx->nr_names; i++) {
			if (!ctx->names[i].name)
				break;
			kfree(ctx->names[i].name);
		}
		kvfree(ctx->names);
	}
}

/*
 * Iterate over fs items and save any that we're interested in.  We want
 * inode struct items and any xattr items whose hashes collide with the
 * xattr names we're searching for.
 *
 * Our forest calls can be advancing through the key space as we see
 * slices that intersect with blocks in trees.  And each forest caller
 * can be resetting the key position to the start of each forest block
 * it reads in an intersection.
 *
 * From this callback's perspective, the key can be jumping all over the
 * place.  We don't have any iterative position state.  For each key we
 * decide if we want to save it and then set the key to the next key we
 * want after the current key.  We'll combine all the saved keys later.
 */
static int save_info_items(struct super_block *sb, struct scoutfs_key *key, u64 seq,
			   u8 flags, void *val, int val_len, int fic, void *arg)
{
	u64 ino = le64_to_cpu(key->_sk_first);
	struct inode_info_context *ctx = arg;
	struct xattr_name name;
	size_t name_ind;
	size_t ino_ind;
	bool hash_match;
	bool ino_match;
	int ret;

	ino_ind = bsearch_index(&ino, ctx->inos, ctx->nr_inos, sizeof(ctx->inos[0]), cmp_u64);
	ino_match = ino_ind < ctx->nr_inos && ctx->inos[ino_ind] == ino;

	/* jump to to next ino, could be for this key if we're before the ino struct */
	if (!ino_match || key->sk_type < SCOUTFS_INODE_TYPE)
		goto next_inode;

	/* find our search position in xattrs */
	if (key->sk_type < SCOUTFS_XATTR_TYPE) {
		name_ind = 0;
		hash_match = false;

	} else if (key->sk_type == SCOUTFS_XATTR_TYPE) {
		name = (struct xattr_name) { .hash = le64_to_cpu(key->skx_name_hash) };
		name_ind = bsearch_index(&name, ctx->names, ctx->nr_names, sizeof(ctx->names[0]),
					 cmp_name_hash);
		hash_match = name_ind < ctx->nr_names && ctx->names[name_ind].hash == name.hash;
	} else {
		name_ind = ctx->nr_names;
		hash_match = false;
	}

	/* save inode items for our search and all xattr items that match search hashes */
	if (key->sk_type == SCOUTFS_INODE_TYPE || hash_match) {
		ret = save_fs_item(&ctx->fs_items, key,  seq, flags, val, val_len);
		if (ret < 0)
			goto out;
	}

	/* let the caller continue iterating through matching xattr items */
	if (hash_match) {
		ret = 0;
		goto out;
	}

	/* jump to the next xattr */
	if (name_ind < ctx->nr_names) {
		scoutfs_xattr_init_key(key, ino, ctx->names[name_ind].hash, 0);
		ret = -ESRCH;
		goto out;
	}

	/* no more xattrs, must be done with this ino */
	ino_ind++;

next_inode:
	/* now jump to next inode struct key, or we're done */
	if (ino_ind < ctx->nr_inos)
		scoutfs_inode_init_key(key, ctx->inos[ino_ind]);
	else
		scoutfs_key_set_ones(key);

	ret = -ESRCH;
out:
	return ret;
}

static int copy_to_user_off(void __user *dst, size_t *dst_off, size_t dst_size,
			    void *src, size_t copy_size)
{
	if (copy_size == 0)
		return 0;
	if (*dst_off + copy_size > dst_size)
		return -ERANGE;
	if (copy_to_user(dst + *dst_off, src, copy_size))
		return -EFAULT;

	*dst_off += copy_size;
	return 0;
}

static int copy_result_to_user(void __user *ures, size_t *off, size_t size, u8 type,
			       void *a_data, size_t a_len, void *b_data, size_t b_len,
			       size_t extra_size)
{
	struct scoutfs_ioctl_raw_read_result res;
	const size_t szof_res = sizeof(struct scoutfs_ioctl_raw_read_result);

	memzero_explicit(&res, szof_res);
	res = (struct scoutfs_ioctl_raw_read_result) {
		.size = a_len + b_len + extra_size,
		.type = type,
	};

	return copy_to_user_off(ures, off, size, &res, szof_res) ?:
	       (a_len ? copy_to_user_off(ures, off, size, a_data, a_len) : 0) ?:
	       (b_len ? copy_to_user_off(ures, off, size, b_data, b_len) : 0);
}

static int copy_item_results_to_user(struct super_block *sb, struct inode_info_context *ctx,
				     void __user *ures, size_t *off, size_t size,
				     struct fs_item *fsi)
{
	struct scoutfs_inode *cinode;
	struct scoutfs_xattr *xat;
	static char null = '\0';
	size_t len;
	u64 ino;
	int ret = 0;

	if (fsi->key.sk_type == SCOUTFS_INODE_TYPE) {
		cinode = (void *)fsi->val;
		ino = le64_to_cpu(fsi->key.ski_ino);

		ret = copy_result_to_user(ures, off, size, SCOUTFS_IOC_RAW_READ_RESULT_INODE,
					  &ino, sizeof(ino), cinode, sizeof(struct scoutfs_inode),
					  0);

	} else if (fsi->key.sk_type == SCOUTFS_XATTR_TYPE) {
		if (fsi->key.skx_part == 0) {
			xat = (void *)fsi->val;
			ret = copy_result_to_user(ures, off, size,
						  SCOUTFS_IOC_RAW_READ_RESULT_XATTR, xat->name,
						  xat->name_len, &null, sizeof(null),
						  le16_to_cpu(xat->val_len));
			if (ret == 0 && xat->val_len != 0) {
				/* then append the start of the value */
				len = fsi->val_len -
				      offsetof(struct scoutfs_xattr, name[xat->name_len]);
				ret = copy_to_user_off(ures, off, size, xat->name + xat->name_len,
						       len);
			}
		} else {
			/* continue appending partial values */
			ret = copy_to_user_off(ures, off, size, fsi->val, fsi->val_len);
		}
	}

	return ret;
}

static bool ignore_zero_nlink(struct inode_info_context *ctx, struct fs_item *fsi)
{
	struct scoutfs_inode *cinode = (void *)fsi->val;

	return cinode->nlink == 0;
}

static bool ignore_xattr_name(struct inode_info_context *ctx, struct fs_item *fsi)
{
	struct scoutfs_xattr *xat = (void *)fsi->val;
	struct xattr_name name = {
		.hash = le64_to_cpu(fsi->key.skx_name_hash),
		.name = xat->name,
		.name_len = xat->name_len,
	};
	size_t i;

	for (i = bsearch_index(&name, ctx->names, ctx->nr_names, sizeof(ctx->names[0]),
			       cmp_name_hash);
	     i < ctx->nr_names && name.hash == ctx->names[i].hash; i++) {
		if (cmp_name_string(&name, &ctx->names[i]) == 0)
			return false;
	}

	return true;
}

static int copy_results_to_user(struct super_block *sb, struct inode_info_context *ctx,
				struct scoutfs_ioctl_raw_read_inode_info *rii)
{
	void __user *ures = (void __user *)rii->results_ptr;
	struct scoutfs_xattr *xat;
	struct fs_item *next;
	struct fs_item *fsi;
	struct fs_item *tmp;
	size_t xattr_end;
	size_t off;
	__le64 in_ino;
	__le64 in_id;
	int ret;

	in_ino = 0;
	xattr_end = 0;
	in_id = 0;
	off = 0;

	list_for_each_entry_safe(fsi, tmp, &ctx->fs_items, head) {
		/*
		 * ignore:
		 *  - inodes with an nlink of 0
		 *  - all items for an ino after the inode struct that we're ignoring 
		 *  - first xattr parts with a name we don't need
		 *  - additional xattr parts when we ignored the first
		 */
		if ((fsi->key.sk_type == SCOUTFS_INODE_TYPE && ignore_zero_nlink(ctx, fsi)) ||
		    (fsi->key.sk_type > SCOUTFS_INODE_TYPE && fsi->key._sk_first != in_ino) ||
		    (fsi->key.sk_type == SCOUTFS_XATTR_TYPE &&
		     ((fsi->key.skx_part == 0 && ignore_xattr_name(ctx, fsi)) ||
		      (fsi->key.skx_part > 0 && fsi->key.skx_id != in_id)))) {
			free_fs_item(fsi);
			in_ino = 0;
			in_id = 0;
			continue;
		}

		/* advance ino/xattr stream context state machine */
		if (fsi->key.sk_type == SCOUTFS_INODE_TYPE) {
			in_ino = fsi->key.ski_ino;
			in_id = 0;
		} else if (fsi->key.sk_type == SCOUTFS_XATTR_TYPE && fsi->key.skx_part == 0) {
			in_id = fsi->key.skx_id;
			/* save the required offset after the complete xattr */
			xat = (void *)fsi->val;
			xattr_end = off + sizeof(struct scoutfs_ioctl_raw_read_result) +
				    xat->name_len + 1 + le16_to_cpu(xat->val_len);
		}

		/* copy results, usually with header, but additional xattr parts copied raw */
		ret = copy_item_results_to_user(sb, ctx, ures, &off, rii->results_size, fsi);
		if (ret < 0)
			goto out;

		/* make sure we saw all xattr parts and copied the correct size */
		if (xattr_end > 0 &&
		    !((next = next_fs_item(&ctx->fs_items, fsi)) &&
		      next->key.sk_type == SCOUTFS_XATTR_TYPE && next->key.skx_ino == in_ino &&
		      next->key.skx_id == in_id)) {
			if (off != xattr_end) {
				ret = -EUCLEAN;
				goto out;
			}
			xattr_end = 0;
		}
	}

	ret = 0;
out:
	return ret ?: off;
}

/*
 * If the key is for an inode we're not interested in, or if its past
 * the xattr items, then advance to the next inode.  This is used
 * between forest read items calls to avoid leaf blocks.  The callback
 * takes care of iterating through the items for an inode across
 * multiple leaves.
 */
static void advance_key_ino(struct scoutfs_key *key, struct inode_info_context *ctx)
{
	u64 ino = le64_to_cpu(key->_sk_first);
	size_t ino_ind;

	ino_ind = bsearch_index(&ino, ctx->inos, ctx->nr_inos, sizeof(ctx->inos[0]), cmp_u64);
	if (ino_ind < ctx->nr_inos && ctx->inos[ino_ind] == ino) {
		if (key->sk_type <= SCOUTFS_XATTR_TYPE)
			return;
		else
			ino_ind++;
	}

	if (ino_ind < ctx->nr_inos)
		scoutfs_inode_init_key(key, ctx->inos[ino_ind]);
	else
		scoutfs_key_set_ones(key);
}

int scoutfs_raw_read_inode_info(struct super_block *sb,
				struct scoutfs_ioctl_raw_read_inode_info *rii)
{
	struct inode_info_context ctx = {0, };
	struct scoutfs_net_roots roots;
	DECLARE_SAVED_REFS(saved);
	struct scoutfs_key lock_start;
	struct scoutfs_key lock_end;
	struct scoutfs_key start;
	struct scoutfs_key last;
	struct scoutfs_key key;
	struct scoutfs_key end;
	LIST_HEAD(list);
	int retries = 10;
	int ret;

	ret = setup_context(&ctx, rii);
	if (ret < 0)
		goto out;

	if (ctx.nr_names > 0)
		scoutfs_xattr_init_key(&last, ctx.inos[ctx.nr_inos -1],
				       ctx.names[ctx.nr_names - 1].hash, U64_MAX);
	else
		scoutfs_inode_init_key(&last, ctx.inos[ctx.nr_inos - 1]);

retry:
	ret = scoutfs_client_get_roots(sb, &roots);
	if (ret)
		goto out;

	scoutfs_inode_init_key(&key, ctx.inos[0]);

	while (scoutfs_key_compare(&key, &last) <= 0) {
		scoutfs_lock_get_fs_item_range(le64_to_cpu(key._sk_first), &lock_start, &lock_end);

		start = key;
		end = last;
		if (scoutfs_key_compare(&lock_end, &end) < 0)
			end = lock_end;

		ret = scoutfs_forest_read_items_roots(sb, &roots, &key, &lock_start, &start, &end,
						      save_info_items, &ctx);
		if (ret < 0)
			goto out;

		/* save each sorted batch, might have partial results for an inode */
		sort_and_remove(&ctx.fs_items, &end);
		list_splice_tail_init(&ctx.fs_items, &list);

		key = end;
		if (!scoutfs_key_is_ones(&key)) {
			scoutfs_key_inc(&key);
			advance_key_ino(&key, &ctx);
		}
	}

	list_splice_tail_init(&list, &ctx.fs_items);
	ret = copy_results_to_user(sb, &ctx, rii);
out:
	free_fs_items(&list);
	free_fs_items(&ctx.fs_items);

	ret = scoutfs_block_check_stale(sb, ret, &saved, &roots.fs_root.ref, &roots.logs_root.ref);
	if (ret == -ESTALE && retries-- > 0)
		goto retry;

	free_context(&ctx);
	return ret;
}
