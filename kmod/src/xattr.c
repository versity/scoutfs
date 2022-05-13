/*
 * Copyright (C) 2018 Versity Software, Inc.  All rights reserved.
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
#include <linux/dcache.h>
#include <linux/xattr.h>
#include <linux/crc32c.h>

#include "format.h"
#include "inode.h"
#include "key.h"
#include "super.h"
#include "item.h"
#include "forest.h"
#include "trans.h"
#include "xattr.h"
#include "lock.h"
#include "hash.h"
#include "scoutfs_trace.h"

/*
 * Extended attributes are packed into multiple smaller file system
 * items.  The common case only uses one item.
 *
 * The xattr keys contain the hash of the xattr name and a unique
 * identifier used to differentiate xattrs whose names hash to the same
 * value.  xattr lookup has to walk all the xattrs with the matching
 * name hash to compare the names.
 *
 * We use a rwsem in the inode to serialize modification of multiple
 * items to make sure that we don't let readers race and see an
 * inconsistent mix of the items that make up xattrs.
 *
 * XXX
 *  - add acl support and call generic xattr->handlers for SYSTEM
 */

static u32 xattr_name_hash(const char *name, unsigned int name_len)
{
	return crc32c(U32_MAX, name, name_len);
}

/* only compare names if the lens match, callers might not have both names */
static u32 xattr_names_equal(const char *a_name, unsigned int a_len,
			     const char *b_name, unsigned int b_len)
{
	return a_len == b_len && memcmp(a_name, b_name, a_len) == 0;
}

static unsigned int xattr_nr_parts(struct scoutfs_xattr *xat)
{
	return SCOUTFS_XATTR_NR_PARTS(xat->name_len,
				      le16_to_cpu(xat->val_len));
}

static void init_xattr_key(struct scoutfs_key *key, u64 ino, u32 name_hash,
			   u64 id)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skx_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_XATTR_TYPE,
		.skx_name_hash = cpu_to_le64(name_hash),
		.skx_id = cpu_to_le64(id),
		.skx_part = 0,
	};
}

#define SCOUTFS_XATTR_PREFIX		"scoutfs."
#define SCOUTFS_XATTR_PREFIX_LEN	(sizeof(SCOUTFS_XATTR_PREFIX) - 1)

static int unknown_prefix(const char *name, bool *is_user)
{
	if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) {
		if (is_user)
			*is_user = true;
		return false;
	}

	if (is_user)
		*is_user = false;

	return strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN) &&
	       strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN) &&
	       strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN)&&
	       strncmp(name, SCOUTFS_XATTR_PREFIX, SCOUTFS_XATTR_PREFIX_LEN);
}


#define HIDE_TAG	"hide."
#define SRCH_TAG	"srch."
#define TOTL_TAG	"totl."
#define WORM_TAG	"worm."
#define TAG_LEN		(sizeof(HIDE_TAG) - 1)

int scoutfs_xattr_parse_tags(struct super_block *sb, const char *name,
			     unsigned int name_len, struct scoutfs_xattr_prefix_tags *tgs)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	bool found;

	memset(tgs, 0, sizeof(struct scoutfs_xattr_prefix_tags));

	if ((name_len < (SCOUTFS_XATTR_PREFIX_LEN + TAG_LEN + 1)) ||
	    strncmp(name, SCOUTFS_XATTR_PREFIX, SCOUTFS_XATTR_PREFIX_LEN))
		return 0;
	name += SCOUTFS_XATTR_PREFIX_LEN;

	found = false;
	for (;;) {
		if (!strncmp(name, HIDE_TAG, TAG_LEN)) {
			if (++tgs->hide == 0)
				return -EINVAL;
		} else if (!strncmp(name, SRCH_TAG, TAG_LEN)) {
			if (++tgs->srch == 0)
				return -EINVAL;
		} else if (!strncmp(name, TOTL_TAG, TAG_LEN)) {
			if (++tgs->totl == 0)
				return -EINVAL;
		} else if (!strncmp(name, WORM_TAG, TAG_LEN)) {
			if (++tgs->worm == 0 || sbi->fmt_vers < 2)
				return -EINVAL;
		} else {
			/* only reason to use scoutfs. is tags */
			if (!found)
				return -EINVAL;
			break;
		}
		name += TAG_LEN;
		found = true;
	}

	return 0;
}

/*
 * xattrs are stored in multiple items.   The first item is a
 * concatenation of an initial header, the name, and then as much of the
 * value as fits in the remainder of the first item.  This return the
 * size of the first item that'd store an xattr with the given name
 * length and value payload size.
 */
static int first_item_bytes(int name_len, size_t size)
{
	if (WARN_ON_ONCE(name_len <= 0) ||
	    WARN_ON_ONCE(name_len > SCOUTFS_XATTR_MAX_NAME_LEN))
		return 0;

	return min_t(int, sizeof(struct scoutfs_xattr) + name_len + size,
			  SCOUTFS_XATTR_MAX_PART_SIZE);
}

/*
 * Find the next xattr, set the caller's key, and copy as much of the
 * first item into the callers buffer as we can.  Returns the number of
 * bytes copied which can include the header, name, and start of the
 * value from the first item.  The caller is responsible for comparing
 * their lengths, the header, and the returned length before safely
 * using the buffer.
 *
 * If a name is provided then we'll iterate over items with a matching
 * name_hash until we find a matching name.  If we don't find a matching
 * name then we return -ENOENT.
 *
 * If a name isn't provided then we'll return the next xattr from the
 * given name_hash and id position.
 *
 * Returns -ENOENT if it didn't find a next item.
 */
static int get_next_xattr(struct inode *inode, struct scoutfs_key *key,
			  struct scoutfs_xattr *xat, unsigned int xat_bytes,
			  const char *name, unsigned int name_len,
			  u64 name_hash, u64 id, struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key last;
	int ret;

	/* need to be able to see the name we're looking for */
	if (WARN_ON_ONCE(name_len > 0 &&
			 xat_bytes < offsetof(struct scoutfs_xattr, name[name_len])))
		return -EINVAL;

	if (name_len)
		name_hash = xattr_name_hash(name, name_len);

	init_xattr_key(key, scoutfs_ino(inode), name_hash, id);
	init_xattr_key(&last, scoutfs_ino(inode), U32_MAX, U64_MAX);

	for (;;) {
		ret = scoutfs_item_next(sb, key, &last, xat, xat_bytes, lock);
		if (ret < 0)
			break;

		trace_scoutfs_xattr_get_next_key(sb, key);

		/* XXX corruption */
		if (key->skx_part != 0) {
			ret = -EIO;
			break;
		}

		/*
		 * XXX corruption: We should have seen a valid header in
		 * the first part and if the next xattr name fits in our
		 * buffer then the item must have included it.
		 */
		if ((ret < sizeof(struct scoutfs_xattr) ||
		     (xat->name_len <= name_len &&
		      ret < offsetof(struct scoutfs_xattr,
				     name[xat->name_len])) ||
		     xat->name_len > SCOUTFS_XATTR_MAX_NAME_LEN ||
		     le16_to_cpu(xat->val_len) > SCOUTFS_XATTR_MAX_VAL_LEN)) {
			ret = -EIO;
			break;
		}

		if (name_len > 0) {
			/* ran out of names that could match */
			if (le64_to_cpu(key->skx_name_hash) != name_hash) {
				ret = -ENOENT;
				break;
			}

			/* keep looking for our name */
			if (!xattr_names_equal(name, name_len, xat->name, xat->name_len)) {
				le64_add_cpu(&key->skx_id, 1);
				continue;
			}
		}

		/* found next name */
		break;
	}

	return ret;
}

/*
 * The caller has already read and verified the xattr's first item.
 * Copy the value from the tail of the first item and from any future
 * items into the destination buffer.
 */
static int copy_xattr_value(struct super_block *sb, struct scoutfs_key *xat_key,
			    struct scoutfs_xattr *xat, int xat_bytes,
			    char *buffer, size_t size,
			    struct scoutfs_lock *lock)
{
	struct scoutfs_key key;
	size_t copied = 0;
	int val_tail;
	int bytes;
	int ret;
	int i;

	/* must have first item up to value */
	if (WARN_ON_ONCE(xat_bytes < sizeof(struct scoutfs_xattr)) ||
	    WARN_ON_ONCE(xat_bytes < offsetof(struct scoutfs_xattr, name[xat->name_len])))
		return -EINVAL;

	/* only ever copy up to the full value */
	size = min_t(size_t, size, le16_to_cpu(xat->val_len));

	/* must have full first item if caller needs value from second item */
	val_tail = SCOUTFS_XATTR_MAX_PART_SIZE -
		   offsetof(struct scoutfs_xattr, name[xat->name_len]);
	if (WARN_ON_ONCE(size > val_tail && xat_bytes != SCOUTFS_XATTR_MAX_PART_SIZE))
		return -EINVAL;

	/* copy from tail of first item */
	bytes = min_t(unsigned int, size, val_tail);
	if (bytes > 0) {
		memcpy(buffer, &xat->name[xat->name_len], bytes);
		copied += bytes;
	}

	key = *xat_key;
	for (i = 1; copied < size; i++) {
		key.skx_part = i;
		bytes = min_t(unsigned int, size - copied, SCOUTFS_XATTR_MAX_PART_SIZE);

		ret = scoutfs_item_lookup(sb, &key, buffer + copied, bytes, lock);
		if (ret >= 0 && ret != bytes)
			ret = -EIO;
		if (ret < 0)
			return ret;

		copied += ret;
	}

	return copied;
}

/*
 * The caller is working with items that are either in the allocated
 * first compound item or further items that are offsets into a value
 * buffer.  Give them a pointer and length of the start of the item.
 */
static void xattr_item_part_buffer(void **buf, int *len, int part,
				   struct scoutfs_xattr *xat, unsigned int xat_bytes,
				   const char *value, size_t size)
{
	int off;

	if (part == 0) {
		*buf = xat;
		*len = xat_bytes;
	} else {
		off = (part * SCOUTFS_XATTR_MAX_PART_SIZE) -
		      offsetof(struct scoutfs_xattr, name[xat->name_len]);
		BUG_ON(off >= size); /* calls limited by number of parts */
		*buf = (void *)value + off;
		*len = min_t(size_t, size - off, SCOUTFS_XATTR_MAX_PART_SIZE);
	}
}

/*
 * Create all the items associated with the given xattr.  If this
 * returns an error it will have already cleaned up any items it created
 * before seeing the error.
 */
static int create_xattr_items(struct inode *inode, u64 id, struct scoutfs_xattr *xat,
			      int xat_bytes, const char *value, size_t size, u8 new_parts,
			      struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	int ret = 0;
	void *buf;
	int len;
	int i;

	init_xattr_key(&key, scoutfs_ino(inode),
		       xattr_name_hash(xat->name, xat->name_len), id);

	for (i = 0; i < new_parts; i++) {
		key.skx_part = i;
		xattr_item_part_buffer(&buf, &len, i, xat, xat_bytes, value, size);

		ret = scoutfs_item_create(sb, &key, buf, len, lock);
		if (ret < 0) {
			while (key.skx_part-- > 0)
				scoutfs_item_delete(sb, &key, lock);
			break;
		}
	}

	return ret;
}

/*
 * Delete the items that make up the given xattr.  If this returns an
 * error then no items have been deleted.
 */
static int delete_xattr_items(struct inode *inode, u32 name_hash, u64 id,
			      u8 nr_parts, struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	int ret = 0;
	int i;

	init_xattr_key(&key, scoutfs_ino(inode), name_hash, id);

	/* dirty additional existing old items */
	for (i = 1; i < nr_parts; i++) {
		key.skx_part = i;
		ret = scoutfs_item_dirty(sb, &key, lock);
		if (ret)
			goto out;
	}

	for (i = 0; i < nr_parts; i++) {
		key.skx_part = i;
		ret = scoutfs_item_delete(sb, &key, lock);
		if (ret)
			break;
	}
out:
	return ret;
}

/*
 * The caller needs to overwrite existing old xattr items with new
 * items.  We carefully stage the changes so that we can always unwind
 * to the original items if we return an error.  Both items have at
 * least one part.  Either the old or new can have more parts.  We dirty
 * and create first because we can always unwind those.  We delete last
 * after dirtying so that it can't fail and we don't have to restore the
 * deleted items.
 */
static int change_xattr_items(struct inode *inode, u64 id,
			      struct scoutfs_xattr *xat, int xat_bytes,
			      const char *value, size_t size,
			      u8 new_parts, u8 old_parts, struct scoutfs_lock *lock)
{
	struct super_block *sb = inode->i_sb;
	struct scoutfs_key key;
	int last_created = -1;
	void *buf;
	int len;
	int i;
	int ret;

	init_xattr_key(&key, scoutfs_ino(inode),
		       xattr_name_hash(xat->name, xat->name_len), id);

	/* dirty existing old items */
	for (i = 0; i < old_parts; i++) {
		key.skx_part = i;
		ret = scoutfs_item_dirty(sb, &key, lock);
		if (ret)
			goto out;
	}

	/* create any new items past the old */
	for (i = old_parts; i < new_parts; i++) {
		key.skx_part = i;
		xattr_item_part_buffer(&buf, &len, i, xat, xat_bytes, value, size);

		ret = scoutfs_item_create(sb, &key, buf, len, lock);
		if (ret)
			goto out;

		last_created = i;
	}

	/* update dirtied overlapping existing items, last partial first */
	for (i = min(old_parts, new_parts) - 1; i >= 0; i--) {
		key.skx_part = i;
		xattr_item_part_buffer(&buf, &len, i, xat, xat_bytes, value, size);

		ret = scoutfs_item_update(sb, &key, buf, len, lock);
		/* only last partial can fail, then we unwind created */
		if (ret < 0)
			goto out;
	}

	/* delete any dirtied old items past new */
	for (i = new_parts; i < old_parts; i++) {
		key.skx_part = i;
		scoutfs_item_delete(sb, &key, lock);
	}

	ret = 0;
out:
	if (ret < 0) {
		/* delete any newly created items */
		for (i = old_parts; i <= last_created; i++) {
			key.skx_part = i;
			scoutfs_item_delete(sb, &key, lock);
		}
	}
	return ret;
}

/*
 * Copy the value for the given xattr name into the caller's buffer, if it
 * fits.  Return the bytes copied or -ERANGE if it doesn't fit.
 */
ssize_t scoutfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
			 size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_lock *lck = NULL;
	struct scoutfs_key key;
	unsigned int xat_bytes;
	size_t name_len;
	int ret;

	if (unknown_prefix(name, NULL))
		return -EOPNOTSUPP;

	name_len = strlen(name);
	if (name_len > SCOUTFS_XATTR_MAX_NAME_LEN)
		return -ENODATA;

	xat_bytes = first_item_bytes(name_len, size);
	xat = kmalloc(xat_bytes, GFP_NOFS);
	if (!xat)
		return -ENOMEM;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &lck);
	if (ret)
		goto out;

	down_read(&si->xattr_rwsem);

	ret = get_next_xattr(inode, &key, xat, xat_bytes, name, name_len, 0, 0, lck);

	if (ret < 0) {
		if (ret == -ENOENT)
			ret = -ENODATA;
		goto unlock;
	}

	/* the caller just wants to know the size */
	if (size == 0) {
		ret = le16_to_cpu(xat->val_len);
		goto unlock;
	}

	/* the caller's buffer wasn't big enough */
	if (size < le16_to_cpu(xat->val_len)) {
		ret = -ERANGE;
		goto unlock;
	}

	ret = copy_xattr_value(sb, &key, xat, xat_bytes, buffer, size, lck);
unlock:
	up_read(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck, SCOUTFS_LOCK_READ);
out:
	kfree(xat);
	return ret;
}

void scoutfs_xattr_init_totl_key(struct scoutfs_key *key, u64 *name)
{
	scoutfs_key_set_zeros(key);
	key->sk_zone = SCOUTFS_XATTR_TOTL_ZONE;
	key->skxt_a = cpu_to_le64(name[0]);
	key->skxt_b = cpu_to_le64(name[1]);
	key->skxt_c = cpu_to_le64(name[2]);
}

/*
 * Currently only support enabling level1 worm by setting a non-zero
 * expiration.
 */
static int parse_worm_name(const char *name)
{
	static const char worm_name[] = "level1_expire";
	char *last_dot;

	last_dot = strrchr(name, '.');
	if (!last_dot)
		return -EINVAL;

	return strcmp(worm_name, last_dot + 1) == 0 ? 0 : -EINVAL;
}

/*
 * Parse a u64 in any base after null terminating it while forbidding
 * the leading + and trailing \n that kstrotull allows.
 */
static int parse_totl_u64(const char *s, int len, u64 *res)
{
	char str[SCOUTFS_XATTR_MAX_TOTL_U64 + 1];

	if (len <= 0 || len >= ARRAY_SIZE(str) || s[0] == '+' || s[len - 1] == '\n')
		return -EINVAL;

	memcpy(str, s, len);
	str[len] = '\0';

	return kstrtoull(str, 0, res) != 0 ? -EINVAL : 0;
}

static int parse_worm_u32(const char *s, int len, u32 *res)
{
        u64 tmp;
        int ret;

        ret = parse_totl_u64(s, len, &tmp);
        if (ret == 0 && tmp > U32_MAX) {
                tmp = 0;
                ret = -EINVAL;
        }

        *res = tmp;
        return ret;
}

static int parse_worm_timespec(struct timespec *ts, const char *name, int name_len)
{
	char *delim;
	u64 sec;
	u32 nsec;
	int sec_len;
	int nsec_len;
	int ret;

	memset(ts, 0, sizeof(struct scoutfs_timespec));

	if (name_len < 3)
		return -EINVAL;

	delim = strnchr(name, name_len, '.');
	if (!delim)
		return -EINVAL;

	if (delim == name || delim == (name + name_len - 1))
		return -EINVAL;

	sec_len = delim - name;
	nsec_len = name_len - (sec_len + 1);

	/* Check to make sure only one '.' */
	if (strnchr(delim + 1, nsec_len, '.'))
		return -EINVAL;

	ret = parse_totl_u64(name, sec_len, &sec);
	if (ret < 0)
		return ret;

	ret = parse_worm_u32(delim + 1, nsec_len, &nsec);
	if (ret < 0)
		return ret;

	if (sec > S64_MAX || nsec >= NSEC_PER_SEC || (sec == 0 && nsec == 0))
		return -EINVAL;

	ts->tv_sec = sec;
	ts->tv_nsec = nsec;

	return 0;
}

/*
 * non-destructive relatively quick parse of the last 3 dotted u64s that
 * make up the name of the xattr total.  -EINVAL is returned if there
 * are anything but 3 valid u64 encodings between single dots at the end
 * of the name.
 */
static int parse_totl_key(struct scoutfs_key *key, const char *name, int name_len)
{
	u64 tot_name[3];
	int end = name_len;
	int nr = 0;
	int len;
	int ret;
	int i;

	/* parse name elements in reserve order from end of xattr name string */
	for (i = name_len - 1; i >= 0 && nr < ARRAY_SIZE(tot_name); i--) {
		if (name[i] != '.')
			continue;

		len = end - (i + 1);
		ret = parse_totl_u64(&name[i + 1], len, &tot_name[nr]);
		if (ret < 0)
			goto out;

		end = i;
		nr++;
	}

	if (nr == ARRAY_SIZE(tot_name)) {
		/* swap to account for parsing in reverse */
		swap(tot_name[0], tot_name[2]);
		scoutfs_xattr_init_totl_key(key, tot_name);
		ret = 0;
	} else {
		ret = -EINVAL;
	}

out:
	return ret;
}

static int apply_totl_delta(struct super_block *sb, struct scoutfs_key *key,
			    struct scoutfs_xattr_totl_val *tval, struct scoutfs_lock *lock)
{
	if (tval->total == 0 && tval->count == 0)
		return 0;

	return scoutfs_item_delta(sb, key, tval, sizeof(*tval), lock);
}

int scoutfs_xattr_combine_totl(void *dst, int dst_len, void *src, int src_len)
{
	struct scoutfs_xattr_totl_val *s_tval = src;
	struct scoutfs_xattr_totl_val *d_tval = dst;

	if (src_len != sizeof(*s_tval) || dst_len != src_len)
		return -EIO;

	le64_add_cpu(&d_tval->total, le64_to_cpu(s_tval->total));
	le64_add_cpu(&d_tval->count, le64_to_cpu(s_tval->count));

	if (d_tval->total == 0 && d_tval->count == 0)
		return SCOUTFS_DELTA_COMBINED_NULL;

	return SCOUTFS_DELTA_COMBINED;
}

/*
 * The confusing swiss army knife of creating, modifying, and deleting
 * xattrs.
 *
 * This always removes the old existing xattr items.
 *
 * If the value pointer is set then we're adding a new xattr.  The flags
 * cause creation to fail if the xattr already exists (_CREATE) or
 * doesn't already exist (_REPLACE).  xattrs can have a zero length
 * value.
 */
static int scoutfs_xattr_set(struct dentry *dentry, const char *name,
			     const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct scoutfs_xattr_totl_val tval = {0,};
	struct scoutfs_lock *totl_lock = NULL;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_xattr_prefix_tags tgs;
	const u64 ino = scoutfs_ino(inode);
	struct timespec worm_ts = {0,};
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_lock *lck = NULL;
	size_t name_len = strlen(name);
	struct scoutfs_key totl_key;
	struct scoutfs_key key;
	bool undo_srch = false;
	bool undo_totl = false;
	bool is_user = false;
	LIST_HEAD(ind_locks);
	unsigned int xat_bytes_totl;
	unsigned int xat_bytes;
	unsigned int val_len;
	u8 found_parts;
	u64 ind_seq;
	u64 total;
	u64 hash = 0;
	u64 id = 0;
	int ret;
	int err;

	trace_scoutfs_xattr_set(sb, name_len, value, size, flags);

	/* mirror the syscall's errors for large names and values */
	if (name_len > SCOUTFS_XATTR_MAX_NAME_LEN)
		return -ERANGE;
	if (value && size > SCOUTFS_XATTR_MAX_VAL_LEN)
		return -E2BIG;

	if (((flags & XATTR_CREATE) && (flags & XATTR_REPLACE)) ||
	    (flags & ~(XATTR_CREATE | XATTR_REPLACE)))
		return -EINVAL;

	if (unknown_prefix(name, &is_user))
		return -EOPNOTSUPP;

	if (scoutfs_xattr_parse_tags(sb, name, name_len, &tgs) != 0)
		return -EINVAL;

	if ((tgs.hide | tgs.srch | tgs.totl | tgs.worm) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (tgs.worm && !tgs.hide)
		return -EINVAL;

	if ((tgs.totl && ((ret = parse_totl_key(&totl_key, name, name_len)) != 0)) ||
	    (tgs.worm && ((ret = parse_worm_name(name)) != 0)))
		return ret;

	/* allocate enough to always read an existing xattr's totl */
	xat_bytes_totl = first_item_bytes(name_len,
					  max_t(size_t, size, SCOUTFS_XATTR_MAX_TOTL_U64));
	/* but store partial first item that only includes the new xattr's value */
	xat_bytes = first_item_bytes(name_len, size);
	xat = kmalloc(xat_bytes_totl, GFP_NOFS);
	if (!xat) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &lck);
	if (ret)
		goto out;

	down_write(&si->xattr_rwsem);

	if (!S_ISREG(inode->i_mode) && tgs.worm) {
		ret = -EINVAL;
		goto unlock;
	}

	/* find an existing xattr to delete, including possible totl value */
	ret = get_next_xattr(inode, &key, xat, xat_bytes_totl, name, name_len, 0, 0, lck);
	if (ret < 0 && ret != -ENOENT)
		goto unlock;

	/* check existence constraint flags */
	if (ret == -ENOENT && (flags & XATTR_REPLACE)) {
		ret = -ENODATA;
		goto unlock;
	} else if (ret >= 0 && (flags & XATTR_CREATE)) {
		ret = -EEXIST;
		goto unlock;
	}

	/* not an error to delete something that doesn't exist */
	if (ret == -ENOENT && !value) {
		ret = 0;
		goto unlock;
	}

	/* current worm only protects user. xattrs and expiration xattr itself */
	if (scoutfs_inode_worm_denied(inode) && (is_user || tgs.worm)) {
		ret = -EACCES;
		goto unlock;
	}

	/* s64 count delta if we create or delete */
	if (tgs.totl)
		tval.count = cpu_to_le64((u64)!!(value) - (u64)!!(ret != -ENOENT));

	/* found fields in key will also be used */
	found_parts = ret >= 0 ? xattr_nr_parts(xat) : 0;

	if (found_parts && tgs.totl) {
		/* parse old totl value before we clobber xat buf */
		val_len = ret - offsetof(struct scoutfs_xattr, name[xat->name_len]);
		ret = parse_totl_u64(&xat->name[xat->name_len], val_len, &total);
		if (ret < 0)
			goto unlock;

		le64_add_cpu(&tval.total, -total);
	}

	/* prepare the xattr header, name, and start of value in first item */
	if (value) {
		if (found_parts)
			id = le64_to_cpu(key.skx_id);
		else
			id = si->next_xattr_id++;
		xat->name_len = name_len;
		xat->val_len = cpu_to_le16(size);
		memset(xat->__pad, 0, sizeof(xat->__pad));
		memcpy(xat->name, name, name_len);
		memcpy(&xat->name[name_len], value,
		       min(size, SCOUTFS_XATTR_MAX_PART_SIZE -
			         offsetof(struct scoutfs_xattr, name[name_len])));

		if (tgs.totl) {
			ret = parse_totl_u64(value, size, &total);
			if (ret < 0)
				goto unlock;

			le64_add_cpu(&tval.total, total);
		}

		if (tgs.worm) {
			/* can't set multiple times with different names */
			scoutfs_inode_get_worm(inode, &worm_ts);
			if (worm_ts.tv_sec || worm_ts.tv_nsec) {
				ret = -EINVAL;
				goto unlock;
			}

			ret = parse_worm_timespec(&worm_ts, value, size);
			if (ret < 0)
				goto unlock;
		}
	}

	if (tgs.totl) {
		ret = scoutfs_lock_xattr_totl(sb, SCOUTFS_LOCK_WRITE_ONLY, 0, &totl_lock);
		if (ret)
			goto unlock;
	}

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, inode, false) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq, true);
	if (ret > 0)
		goto retry;
	if (ret)
		goto unlock;

	ret = scoutfs_dirty_inode_item(inode, lck);
	if (ret < 0)
		goto release;

	if (tgs.srch && !(found_parts && value)) {
		if (found_parts)
			id = le64_to_cpu(key.skx_id);
		hash = scoutfs_hash64(name, name_len);
		ret = scoutfs_forest_srch_add(sb, hash, ino, id);
		if (ret < 0)
			goto release;
		undo_srch = true;
	}

	if (tgs.totl) {
		ret = apply_totl_delta(sb, &totl_key, &tval, totl_lock);
		if (ret < 0)
			goto release;
		undo_totl = true;
	}

	if (found_parts && value)
		ret = change_xattr_items(inode, id, xat, xat_bytes, value, size,
					 xattr_nr_parts(xat), found_parts, lck);
	else if (found_parts)
		ret = delete_xattr_items(inode, le64_to_cpu(key.skx_name_hash),
					 le64_to_cpu(key.skx_id), found_parts,
					 lck);
	else
		ret = create_xattr_items(inode, id, xat, xat_bytes, value, size,
					 xattr_nr_parts(xat), lck);
	if (ret < 0)
		goto release;

	if (tgs.worm)
		scoutfs_inode_set_worm(inode, worm_ts.tv_sec, worm_ts.tv_nsec);

	/* XXX do these want i_mutex or anything? */
	inode_inc_iversion(inode);
	inode->i_ctime = CURRENT_TIME;
	scoutfs_update_inode_item(inode, lck, &ind_locks);
	ret = 0;

release:
	if (ret < 0 && undo_srch) {
		err = scoutfs_forest_srch_add(sb, hash, ino, id);
		BUG_ON(err);
	}
	if (ret < 0 && undo_totl) {
		/* _delta() on dirty items shouldn't fail */
		tval.total = cpu_to_le64(-le64_to_cpu(tval.total));
		tval.count = cpu_to_le64(-le64_to_cpu(tval.count));
		err = apply_totl_delta(sb, &totl_key, &tval, totl_lock);
		BUG_ON(err);
	}

	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
unlock:
	up_write(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, totl_lock, SCOUTFS_LOCK_WRITE_ONLY);
out:
	kfree(xat);

	return ret;
}

int scoutfs_setxattr(struct dentry *dentry, const char *name,
		     const void *value, size_t size, int flags)
{
	if (size == 0)
		value = ""; /* set empty value */

	return scoutfs_xattr_set(dentry, name, value, size, flags);
}

int scoutfs_removexattr(struct dentry *dentry, const char *name)
{
	return scoutfs_xattr_set(dentry, name, NULL, 0, XATTR_REPLACE);
}

ssize_t scoutfs_list_xattrs(struct inode *inode, char *buffer,
			    size_t size, __u32 *hash_pos, __u64 *id_pos,
			    bool e_range, bool show_hidden)
{
	struct scoutfs_inode_info *si = SCOUTFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_xattr_prefix_tags tgs;
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_lock *lck = NULL;
	struct scoutfs_key key;
	unsigned int xat_bytes;
	ssize_t total = 0;
	u32 name_hash = 0;
	bool is_hidden;
	u64 id = 0;
	int ret;

	if (hash_pos)
		name_hash = *hash_pos;
	if (id_pos)
		id = *id_pos;

	/* need a buffer large enough for all possible names */
	xat_bytes = first_item_bytes(SCOUTFS_XATTR_MAX_NAME_LEN, 0);
	xat = kmalloc(xat_bytes, GFP_NOFS);
	if (!xat) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &lck);
	if (ret)
		goto out;

	down_read(&si->xattr_rwsem);

	for (;;) {
		ret = get_next_xattr(inode, &key, xat, xat_bytes, NULL, 0, name_hash, id, lck);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = total;
			break;
		}

		is_hidden = scoutfs_xattr_parse_tags(sb, xat->name, xat->name_len,
						     &tgs) == 0 && tgs.hide;

		if (show_hidden == is_hidden) {
			if (size) {
				if ((total + xat->name_len + 1) > size) {
					if (e_range)
						ret = -ERANGE;
					else
						ret = total;
					break;
				}

				memcpy(buffer, xat->name, xat->name_len);
				buffer += xat->name_len;
				*(buffer++) = '\0';
			}

			total += xat->name_len + 1;
		}

		name_hash = le64_to_cpu(key.skx_name_hash);
		id = le64_to_cpu(key.skx_id) + 1;
	}

	up_read(&si->xattr_rwsem);
	scoutfs_unlock(sb, lck, SCOUTFS_LOCK_READ);
out:
	kfree(xat);

	if (hash_pos)
		*hash_pos = name_hash;
	if (id_pos)
		*id_pos = id;

	return ret;
}

ssize_t scoutfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;

	return scoutfs_list_xattrs(inode, buffer, size,
				   NULL, NULL, true, false);
}

/*
 * Delete all the xattr items associated with this inode.  The inode is
 * dead so we don't need the xattr rwsem.
 */
int scoutfs_xattr_drop(struct super_block *sb, u64 ino,
		       struct scoutfs_lock *lock)
{
	struct scoutfs_xattr_prefix_tags tgs;
	struct scoutfs_xattr *xat = NULL;
	struct scoutfs_lock *totl_lock = NULL;
	struct scoutfs_xattr_totl_val tval;
	struct scoutfs_key totl_key;
	struct scoutfs_key last;
	struct scoutfs_key key;
	bool release = false;
	unsigned int bytes;
	unsigned int val_len;
	void *value;
	u64 total;
	u64 hash;
	int ret;

	/* need a buffer large enough for all possible names and totl value */
	bytes = sizeof(struct scoutfs_xattr) + SCOUTFS_XATTR_MAX_NAME_LEN +
		SCOUTFS_XATTR_MAX_TOTL_U64;
	xat = kmalloc(bytes, GFP_NOFS);
	if (!xat) {
		ret = -ENOMEM;
		goto out;
	}

	init_xattr_key(&key, ino, 0, 0);
	init_xattr_key(&last, ino, U32_MAX, U64_MAX);

	for (;;) {
		ret = scoutfs_item_next(sb, &key, &last, (void *)xat, bytes,
					lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		if (key.skx_part == 0 && (ret < sizeof(struct scoutfs_xattr) ||
		    ret < offsetof(struct scoutfs_xattr, name[xat->name_len]))) {
			ret = -EIO;
			break;
		}

		if (key.skx_part != 0 ||
		    scoutfs_xattr_parse_tags(sb, xat->name, xat->name_len, &tgs) != 0)
			memset(&tgs, 0, sizeof(tgs));

		if (tgs.totl) {
			value = &xat->name[xat->name_len];
			val_len = ret - offsetof(struct scoutfs_xattr, name[xat->name_len]);
			if (val_len != le16_to_cpu(xat->val_len)) {
				ret = -EIO;
				goto out;
			}

			ret = parse_totl_key(&totl_key, xat->name, xat->name_len) ?:
			      parse_totl_u64(value, val_len, &total);
			if (ret < 0)
				break;
		}

		if (tgs.totl && totl_lock == NULL) {
			ret = scoutfs_lock_xattr_totl(sb, SCOUTFS_LOCK_WRITE_ONLY, 0, &totl_lock);
			if (ret < 0)
				break;
		}

		ret = scoutfs_hold_trans(sb, false);
		if (ret < 0)
			break;
		release = true;

		ret = scoutfs_item_delete(sb, &key, lock);
		if (ret < 0)
			break;

		if (tgs.srch) {
			hash = scoutfs_hash64(xat->name, xat->name_len);
			ret = scoutfs_forest_srch_add(sb, hash, ino,
						      le64_to_cpu(key.skx_id));
		       if (ret < 0)
			       break;
		}

		if (tgs.totl) {
			tval.total = cpu_to_le64(-total);
			tval.count = cpu_to_le64(-1LL);
			ret = apply_totl_delta(sb, &totl_key, &tval, totl_lock);
			if (ret < 0)
				break;
		}

		scoutfs_release_trans(sb);
		release = false;

		/* don't need to inc, next won't see deleted item */
	}

	if (release)
		scoutfs_release_trans(sb);
	scoutfs_unlock(sb, totl_lock, SCOUTFS_LOCK_WRITE_ONLY);
	kfree(xat);
out:
	return ret;
}
