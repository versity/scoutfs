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

#include "format.h"
#include "key.h"
#include "block.h"
#include "inode.h"
#include "forest.h"
#include "client.h"
#include "ioctl.h"
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
