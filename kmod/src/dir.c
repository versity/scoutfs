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
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/xattr.h>
#include <linux/namei.h>

#include "format.h"
#include "file.h"
#include "dir.h"
#include "inode.h"
#include "ioctl.h"
#include "key.h"
#include "msg.h"
#include "super.h"
#include "trans.h"
#include "xattr.h"
#include "item.h"
#include "lock.h"
#include "hash.h"
#include "omap.h"
#include "forest.h"
#include "acl.h"
#include "counters.h"
#include "scoutfs_trace.h"

/*
 * Directory entries are stored in three different items.  Each has the
 * same key format and all have identical values which contain the full
 * entry name.
 *
 * Entries for name lookup are stored at the hash of the name and the
 * readdir position.  Including the position lets us create names
 * without having to read the items to check for hash collisions.
 * Lookup iterates over all the positions with the same hash values and
 * compares the names.
 *
 * Entries for readdir are stored in an increasing unique readdir
 * position.  This results in returning entries in creation order which
 * matches inode allocation order and avoids random inode access
 * patterns during readdir.
 *
 * Entries for link backref traversal are stored at the target inode
 * sorted by the parent dir and the entry's position in the parent dir.
 * This keeps link backref users away from the higher contention area of
 * dirent items in parent dirs.
 *
 * All the entries have a dirent struct with the full name in their
 * value.  The dirent struct contains the name hash and readdir position
 * so that any item use can reference all the items for a given entry.
 */

static unsigned int mode_to_type(umode_t mode)
{
#define S_SHIFT 12
	static unsigned char mode_types[S_IFMT >> S_SHIFT] = {
		[S_IFIFO >> S_SHIFT]	= SCOUTFS_DT_FIFO,
		[S_IFCHR >> S_SHIFT]	= SCOUTFS_DT_CHR,
		[S_IFDIR >> S_SHIFT]	= SCOUTFS_DT_DIR,
		[S_IFBLK >> S_SHIFT]	= SCOUTFS_DT_BLK,
		[S_IFREG >> S_SHIFT]	= SCOUTFS_DT_REG,
		[S_IFLNK >> S_SHIFT]	= SCOUTFS_DT_LNK,
		[S_IFSOCK >> S_SHIFT]	= SCOUTFS_DT_SOCK,
	};

	return mode_types[(mode & S_IFMT) >> S_SHIFT];
#undef S_SHIFT
}

static unsigned int dentry_type(enum scoutfs_dentry_type type)
{
	static unsigned char types[] = {
		[SCOUTFS_DT_FIFO]	= DT_FIFO,
		[SCOUTFS_DT_CHR]	= DT_CHR,
		[SCOUTFS_DT_DIR]	= DT_DIR,
		[SCOUTFS_DT_BLK]	= DT_BLK,
		[SCOUTFS_DT_REG]	= DT_REG,
		[SCOUTFS_DT_LNK]	= DT_LNK,
		[SCOUTFS_DT_SOCK]	= DT_SOCK,
		[SCOUTFS_DT_WHT]	= DT_WHT,
	};

	if (type < ARRAY_SIZE(types))
		return types[type];

	return DT_UNKNOWN;
}

static int scoutfs_d_revalidate(struct dentry *dentry, unsigned int flags);

const struct dentry_operations scoutfs_dentry_ops = {
	.d_revalidate = scoutfs_d_revalidate,
};

static void init_dirent_key(struct scoutfs_key *key, u8 type, u64 ino,
			    u64 major, u64 minor)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.skd_ino = cpu_to_le64(ino),
		.sk_type = type,
		.skd_major = cpu_to_le64(major),
		.skd_minor = cpu_to_le64(minor),
	};
}

static unsigned int dirent_bytes(unsigned int name_len)
{
	return offsetof(struct scoutfs_dirent, name[name_len]);
}

static struct scoutfs_dirent *alloc_dirent(unsigned int name_len)
{
	return kmalloc(dirent_bytes(name_len), GFP_NOFS);
}

/*
 * Test a bit number as though an array of bytes is a large len-bit
 * big-endian value.  nr 0 is the LSB of the final byte, nr (len - 1) is
 * the MSB of the first byte.
 */
static int test_be_bytes_bit(int nr, const char *bytes, int len)
{
	return bytes[(len - 1 - nr) >> 3] & (1 << (nr & 7));
}

/*
 * Generate a 32bit "fingerprint" of the name by extracting 32 evenly
 * distributed bits from the name.  The intent is to have the sort order
 * of the fingerprints reflect the memcmp() sort order of the names
 * while mapping large names down to small fs keys.
 *
 * Names that are smaller than 32bits are biased towards the high bits
 * of the fingerprint so that most significant bits of the fingerprints
 * consistently reflect the initial characters of the names.
 */
static u32 dirent_name_fingerprint(const char *name, unsigned int name_len)
{
	int name_bits = name_len * 8;
	int skip = max(name_bits / 32, 1);
	u32 fp = 0;
	int f;
	int n;

	for (f = 31, n = name_bits - 1; f >= 0 && n >= 0; f--, n -= skip)
		fp |= !!test_be_bytes_bit(n, name, name_bits) << f;

	return fp;
}

static u64 dirent_name_hash(const char *name, unsigned int name_len)
{
       return scoutfs_hash32(name, name_len) |
              ((u64)dirent_name_fingerprint(name, name_len) << 32);
}

static bool dirent_names_equal(const char *a_name, unsigned int a_len,
			      const char *b_name, unsigned int b_len)
{
	return a_len == b_len && memcmp(a_name, b_name, a_len) == 0;
}

/*
 * Looks for the dirent item and fills the caller's dirent if it finds
 * it.  Returns item lookup errors including -ENOENT if it's not found.
 */
static int lookup_dirent(struct super_block *sb, u64 dir_ino, const char *name,
			 unsigned name_len, u64 hash,
			 struct scoutfs_dirent *dent_ret,
			 struct scoutfs_lock *lock)
{
	struct scoutfs_key last_key;
	struct scoutfs_key key;
	struct scoutfs_dirent *dent = NULL;
	int ret;

	dent = alloc_dirent(SCOUTFS_NAME_LEN);
	if (!dent) {
		return -ENOMEM;
	}

	init_dirent_key(&key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, 0);
	init_dirent_key(&last_key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, U64_MAX);

	for (;;) {
		ret = scoutfs_item_next(sb, &key, &last_key, dent,
					dirent_bytes(SCOUTFS_NAME_LEN), lock);
		if (ret < 0)
			break;

		ret -= sizeof(struct scoutfs_dirent);
		if (ret < 1 || ret > SCOUTFS_NAME_LEN) {
			scoutfs_corruption(sb, SC_DIRENT_NAME_LEN,
					   corrupt_dirent_name_len,
					   "dir_ino %llu hash %llu key "SK_FMT" len %d",
					   dir_ino, hash, SK_ARG(&key), ret);
			ret = -EIO;
			goto out;
		}

		if (dirent_names_equal(name, name_len, dent->name, ret)) {
			*dent_ret = *dent;
			ret = 0;
			break;
		}

		if (le64_to_cpu(key.skd_minor) == U64_MAX) {
			ret = -ENOENT;
			break;
		}
		le64_add_cpu(&key.skd_minor, 1);
	}

out:
	kfree(dent);
	return ret;
}

static int lookup_dentry_dirent(struct super_block *sb, u64 dir_ino, struct dentry *dentry,
				struct scoutfs_dirent *dent_ret,
				struct scoutfs_lock *lock)
{
	return lookup_dirent(sb, dir_ino, dentry->d_name.name, dentry->d_name.len,
			     dirent_name_hash(dentry->d_name.name, dentry->d_name.len),
			     dent_ret, lock);
}

static u64 dentry_parent_ino(struct dentry *dentry)
{
	struct dentry *parent = NULL;
	struct inode *dir;
	u64 dir_ino = 0;

	if ((parent = dget_parent(dentry)) && (dir = parent->d_inode))
		dir_ino = scoutfs_ino(dir);

	dput(parent);
	return dir_ino;
}

/* negative dentries return 0, our root ino is non-zero (1) */
static u64 dentry_ino(struct dentry *dentry)
{
	return dentry->d_inode ? scoutfs_ino(dentry->d_inode) : 0;
}

static void set_dentry_fsdata(struct dentry *dentry, struct scoutfs_lock *lock)
{
	void *now = (void *)(unsigned long)lock->refresh_gen;
	void *was;

	/* didn't want to alloc :/ */
	BUILD_BUG_ON(sizeof(dentry->d_fsdata) != sizeof(u64));
	BUILD_BUG_ON(sizeof(dentry->d_fsdata) != sizeof(long));

	do {
		was = dentry->d_fsdata;
	} while (cmpxchg(&dentry->d_fsdata, was, now) != was);
}

static bool test_dentry_fsdata(struct dentry *dentry, u64 refresh)
{
	u64 fsd = (unsigned long)READ_ONCE(dentry->d_fsdata);

	return fsd == refresh;
}

/*
 * Validate an operation caller's input dentry argument.  If the fsdata
 * is valid then the underlying dirent items couldn't have changed and
 * we return 0.  If fsdata is no longer protected by a lock or its
 * fields don't match then we check the dirent item.  If the dirent item
 * doesn't match what the caller expected given their dentry fields then
 * we return an error.
 */
static int validate_dentry(struct super_block *sb, u64 dir_ino, struct dentry *dentry,
			   struct scoutfs_lock *lock)
{
	u64 ino = dentry_ino(dentry);
	struct scoutfs_dirent dent = {0,};
	int ret;

	if (test_dentry_fsdata(dentry, lock->refresh_gen)) {
		ret = 0;
		goto out;
	}

	ret = lookup_dentry_dirent(sb, dir_ino, dentry, &dent, lock);
	if (ret < 0 && ret != -ENOENT)
		goto out;

	/* use negative zeroed dent when lookup gave -ENOENT */
	if (!ino && dent.ino) {
		/* caller expected negative but there was a dirent */
		ret = -EEXIST;
	} else if (ino && !dent.ino) {
		/* caller expected positive but there was no dirent */
		ret = -ENOENT;
	} else if (ino != le64_to_cpu(dent.ino)) {
		/* name linked to different inode than caller's */
		ret = -ESTALE;
	} else {
		/* dirent ino matches dentry ino */
		ret = 0;
	}

out:
	trace_scoutfs_validate_dentry(sb, dentry, dir_ino, ino, le64_to_cpu(dent.ino),
				      lock->refresh_gen, ret);

	return ret;
}

static int scoutfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = dentry->d_sb;
	u64 dir_ino = dentry_parent_ino(dentry);
	int ret;

	/* don't think this happens but we can find out */
	if (IS_ROOT(dentry)) {
		scoutfs_inc_counter(sb, dentry_revalidate_root);
		if (!dentry->d_inode ||
		    (scoutfs_ino(dentry->d_inode) != SCOUTFS_ROOT_INO)) {
			ret = -EIO;
		} else {
			ret = 1;
		}
		goto out;
	}

	/* XXX what are the rules for _RCU? */
	if (flags & LOOKUP_RCU) {
		scoutfs_inc_counter(sb, dentry_revalidate_rcu);
		ret = -ECHILD;
		goto out;
	}

	if (test_dentry_fsdata(dentry, scoutfs_lock_ino_refresh_gen(sb, dir_ino))) {
		scoutfs_inc_counter(sb, dentry_revalidate_valid);
		ret = 1;
	} else {
		scoutfs_inc_counter(sb, dentry_revalidate_invalid);
		ret = 0;
	}

out:
	trace_scoutfs_d_revalidate(sb, dentry, flags, dir_ino, ret);

	if (ret < 0 && ret != -ECHILD)
		scoutfs_inc_counter(sb, dentry_revalidate_error);

	return ret;
}

/*
 * Because of rename, locks are ordered by inode number.  To hold the
 * dir lock while calling iget, we might have to already hold a lesser
 * inode's lock while telling iget whether or not to lock.  Instead of
 * adding all those moving pieces we drop the dir lock before calling
 * iget.  We don't reuse inode numbers so we don't have to worry about
 * the target of the link changing.  We will only follow the entry as it
 * existed before or after whatever modification is happening under the
 * dir lock and that can already legally race before or after our
 * lookup.
 */
static struct dentry *scoutfs_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_dirent dent = {0,};
	struct inode *inode;
	u64 ino = 0;
	u64 hash;
	int ret;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);

	if (dentry->d_name.len > SCOUTFS_NAME_LEN) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, dir, &dir_lock);
	if (ret)
		goto out;

	ret = lookup_dirent(sb, scoutfs_ino(dir), dentry->d_name.name,
			    dentry->d_name.len, hash, &dent, dir_lock);
	if (ret == -ENOENT) {
		ino = 0;
		ret = 0;
	} else if (ret == 0) {
		ino = le64_to_cpu(dent.ino);
	}
	if (ret == 0)
		set_dentry_fsdata(dentry, dir_lock);

	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_READ);

out:
	if (ret < 0)
		inode = ERR_PTR(ret);
	else if (ino == 0)
		inode = NULL;
	else
		inode = scoutfs_iget(sb, ino, 0, 0);

	/*
	 * We can't splice dir aliases into the dcache.  dir entries
	 * might have changed on other nodes so our dcache could still
	 * contain them, rather than having been moved in rename.  For
	 * dirs, we use d_materialize_unique to remove any existing
	 * aliases which must be stale.  Our inode numbers aren't reused
	 * so inodes pointed to by entries can't change types.
	 */
	if (!IS_ERR_OR_NULL(inode) && S_ISDIR(inode->i_mode))
		return d_materialise_unique(dentry, inode);
	else
		return d_splice_alias(inode, dentry);
}

/*
 * readdir simply iterates over the dirent items for the dir inode and
 * uses their offset as the readdir position.
 *
 * It will need to be careful not to read past the region of the dirent
 * hash offset keys that it has access to.
 */
static int KC_DECLARE_READDIR(scoutfs_readdir, struct file *file,
			      void *dirent, kc_readdir_ctx_t ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_dirent *dent = NULL;
	struct scoutfs_key last_key;
	struct scoutfs_key key;
	int name_len;
	u64 pos;
	int ret;

	if (!kc_dir_emit_dots(file, dirent, ctx))
		return 0;

	dent = alloc_dirent(SCOUTFS_NAME_LEN);
	if (!dent) {
		return -ENOMEM;
	}

	init_dirent_key(&last_key, SCOUTFS_READDIR_TYPE, scoutfs_ino(inode),
			SCOUTFS_DIRENT_LAST_POS, 0);

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ, 0, inode, &dir_lock);
	if (ret)
		goto out;

	for (;;) {
		init_dirent_key(&key, SCOUTFS_READDIR_TYPE, scoutfs_ino(inode),
				kc_readdir_pos(file, ctx), 0);

		ret = scoutfs_item_next(sb, &key, &last_key, dent,
					dirent_bytes(SCOUTFS_NAME_LEN),
					dir_lock);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			break;
		}

		name_len = ret - sizeof(struct scoutfs_dirent);
		if (name_len < 1 || name_len > SCOUTFS_NAME_LEN) {
			scoutfs_corruption(sb, SC_DIRENT_READDIR_NAME_LEN,
					   corrupt_dirent_readdir_name_len,
					   "dir_ino %llu pos %llu key "SK_FMT" len %d",
					   scoutfs_ino(inode),
					   kc_readdir_pos(file, ctx),
					   SK_ARG(&key), name_len);
			ret = -EIO;
			goto out;
		}

		pos = le64_to_cpu(key.skd_major);
		kc_readdir_pos(file, ctx) = pos;

		if (!kc_dir_emit(ctx, dirent, dent->name, name_len, pos,
				le64_to_cpu(dent->ino),
				dentry_type(dent->type))) {
			ret = 0;
			break;
		}

		kc_readdir_pos(file, ctx) = pos + 1;
	}

out:
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_READ);

	kfree(dent);
	return ret;
}

/*
 * Add all the items for the named link to the inode in the dir.  Only
 * items are modified.  The caller is responsible for locking, entering
 * a transaction, dirtying items, and managing the vfs structs.
 *
 * If this returns an error then nothing will have changed.
 */
static int add_entry_items(struct super_block *sb, u64 dir_ino, u64 hash,
			   u64 pos, const char *name, unsigned name_len,
			   u64 ino, umode_t mode, struct scoutfs_lock *dir_lock,
			   struct scoutfs_lock *inode_lock)
{
	struct scoutfs_dirent *dent = NULL;
	struct scoutfs_key rdir_key;
	struct scoutfs_key ent_key;
	struct scoutfs_key lb_key;
	bool del_rdir = false;
	bool del_ent = false;
	int ret;

	dent = alloc_dirent(name_len);
	if (!dent) {
		return -ENOMEM;
	}

	/* initialize the dent */
	dent->ino = cpu_to_le64(ino);
	dent->hash = cpu_to_le64(hash);
	dent->pos = cpu_to_le64(pos);
	dent->type = mode_to_type(mode);
	memcpy(dent->name, name, name_len);

	init_dirent_key(&ent_key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, pos);
	init_dirent_key(&rdir_key, SCOUTFS_READDIR_TYPE, dir_ino, pos, 0);
	init_dirent_key(&lb_key, SCOUTFS_LINK_BACKREF_TYPE, ino, dir_ino, pos);

	ret = scoutfs_item_create(sb, &ent_key, dent, dirent_bytes(name_len),
				  dir_lock);
	if (ret)
		goto out;
	del_ent = true;

	ret = scoutfs_item_create(sb, &rdir_key, dent, dirent_bytes(name_len),
				  dir_lock);
	if (ret)
		goto out;
	del_rdir = true;

	ret = scoutfs_item_create(sb, &lb_key, dent, dirent_bytes(name_len),
				  inode_lock);
out:
	if (ret < 0) {
		if (del_ent)
			scoutfs_item_delete(sb, &ent_key, dir_lock);
		if (del_rdir)
			scoutfs_item_delete(sb, &rdir_key, dir_lock);
	}

	kfree(dent);

	return ret;
}

/*
 * Delete all the items for the named link to the inode in the dir.
 * Only items are modified.  The caller is responsible for locking,
 * entering a transaction, dirtying items, and managing the vfs structs.
 *
 * If this returns an error then nothing will have changed.
 */
static int del_entry_items(struct super_block *sb, u64 dir_ino, u64 hash,
			   u64 pos, u64 ino, struct scoutfs_lock *dir_lock,
			   struct scoutfs_lock *inode_lock)
{
	struct scoutfs_key rdir_key;
	struct scoutfs_key ent_key;
	struct scoutfs_key lb_key;
	int ret;

	init_dirent_key(&ent_key, SCOUTFS_DIRENT_TYPE, dir_ino, hash, pos);
	init_dirent_key(&rdir_key, SCOUTFS_READDIR_TYPE, dir_ino, pos, 0);
	init_dirent_key(&lb_key, SCOUTFS_LINK_BACKREF_TYPE, ino, dir_ino, pos);

	ret = scoutfs_item_dirty(sb, &ent_key, dir_lock) ?:
	      scoutfs_item_dirty(sb, &rdir_key, dir_lock) ?:
	      scoutfs_item_dirty(sb, &lb_key, inode_lock);
	if (ret == 0) {
		ret = scoutfs_item_delete(sb, &ent_key, dir_lock) ?:
		      scoutfs_item_delete(sb, &rdir_key, dir_lock) ?:
		      scoutfs_item_delete(sb, &lb_key, inode_lock);
		BUG_ON(ret); /* _dirty should have guaranteed success */
	}

	return ret;
}

/*
 * Inode creation needs to hold dir and inode locks which can be greater
 * or less than each other.  It seems easiest to keep the dual locking
 * here like it is for all the other dual locking of established inodes.
 * Except we don't have the inode struct yet when we're getting locks,
 * so we roll our own comparion between the two instead of pushing
 * complexity down the locking paths that acquire existing inodes in
 * order.
 */
static struct inode *lock_hold_create(struct inode *dir, struct dentry *dentry,
				      umode_t mode, dev_t rdev,
				      struct scoutfs_lock **dir_lock,
				      struct scoutfs_lock **inode_lock,
				      struct scoutfs_lock **orph_lock,
				      struct list_head *ind_locks)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = NULL;
	u64 ind_seq;
	int ret = 0;
	u64 ino;

	ret = scoutfs_alloc_ino(sb, S_ISDIR(mode), &ino);
	if (ret)
		return ERR_PTR(ret);

	if (ino < scoutfs_ino(dir)) {
		ret = scoutfs_lock_ino(sb, SCOUTFS_LOCK_WRITE, 0, ino,
				       inode_lock) ?:
		      scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				         SCOUTFS_LKF_REFRESH_INODE, dir,
					 dir_lock);
	} else {
		ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_WRITE,
				         SCOUTFS_LKF_REFRESH_INODE, dir,
					 dir_lock) ?:
		      scoutfs_lock_ino(sb, SCOUTFS_LOCK_WRITE, 0, ino,
				       inode_lock);
	}
	if (ret)
		goto out_unlock;

	if (orph_lock) {
		ret = scoutfs_lock_orphan(sb, SCOUTFS_LOCK_WRITE_ONLY, 0, ino, orph_lock);
		if (ret < 0)
			goto out_unlock;
	}

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, ind_locks, dir, true) ?:
	      scoutfs_inode_index_prepare_ino(sb, ind_locks, ino, mode) ?:
	      scoutfs_inode_index_try_lock_hold(sb, ind_locks, ind_seq, true);
	if (ret > 0)
		goto retry;
	if (ret)
		goto out_unlock;

	ret = scoutfs_new_inode(sb, dir, mode, rdev, ino, *inode_lock, &inode) ?:
	      scoutfs_init_acl_locked(inode, dir, *inode_lock, *dir_lock, ind_locks);
	if (ret < 0)
		goto out;

	ret = scoutfs_dirty_inode_item(dir, *dir_lock);
out:
	if (ret)
		scoutfs_release_trans(sb);
out_unlock:
	if (ret) {
		scoutfs_inode_index_unlock(sb, ind_locks);
		scoutfs_unlock(sb, *dir_lock, SCOUTFS_LOCK_WRITE);
		*dir_lock = NULL;
		scoutfs_unlock(sb, *inode_lock, SCOUTFS_LOCK_WRITE);
		*inode_lock = NULL;
		if (orph_lock) {
			scoutfs_unlock(sb, *orph_lock, SCOUTFS_LOCK_WRITE_ONLY);
			*orph_lock = NULL;
		}

		if (!IS_ERR_OR_NULL(inode))
			iput(inode);
		inode = ERR_PTR(ret);
	}

	return inode;
}

static int scoutfs_mknod(KC_VFS_NS_DEF
			 struct inode *dir,
			 struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = NULL;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_inode_info *si;
	LIST_HEAD(ind_locks);
	u64 hash;
	u64 pos;
	int ret;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);
	inode = lock_hold_create(dir, dentry, mode, rdev,
				 &dir_lock, &inode_lock, NULL, &ind_locks);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	si = SCOUTFS_I(inode);

	ret = validate_dentry(sb, scoutfs_ino(dir), dentry, dir_lock);
	if (ret < 0)
		goto out;

	pos = SCOUTFS_I(dir)->next_readdir_pos++;

	ret = add_entry_items(sb, scoutfs_ino(dir), hash, pos,
			      dentry->d_name.name, dentry->d_name.len,
			      scoutfs_ino(inode), inode->i_mode, dir_lock,
			      inode_lock);
	if (ret)
		goto out;

	set_dentry_fsdata(dentry, dir_lock);

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = current_time(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = dir->i_mtime;
	si->crtime = inode->i_mtime;
	inode_inc_iversion(dir);
	inode_inc_iversion(inode);
	scoutfs_forest_inc_inode_count(sb);

	if (S_ISDIR(mode)) {
		inc_nlink(inode);
		inc_nlink(dir);
	}

	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);
	scoutfs_inode_index_unlock(sb, &ind_locks);

	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
out:
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);

	/* XXX delete the inode item here */
	if (ret && !IS_ERR_OR_NULL(inode))
		iput(inode);
	return ret;
}

/* XXX hmm, do something with excl? */
static int scoutfs_create(KC_VFS_NS_DEF
			  struct inode *dir,
			  struct dentry *dentry, umode_t mode, bool excl)
{
	return scoutfs_mknod(KC_VFS_NS
			     dir, dentry, mode | S_IFREG, 0);
}

static int scoutfs_mkdir(KC_VFS_NS_DEF
			 struct inode *dir,
			 struct dentry *dentry, umode_t mode)
{
	return scoutfs_mknod(KC_VFS_NS
			     dir, dentry, mode | S_IFDIR, 0);
}

static int scoutfs_link(struct dentry *old_dentry,
			struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct super_block *sb = dir->i_sb;
	struct scoutfs_lock *dir_lock;
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_lock *orph_lock = NULL;
	LIST_HEAD(ind_locks);
	bool del_orphan = false;
	u64 dir_size;
	u64 ind_seq;
	u64 hash;
	u64 pos;
	int ret;
	int err;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	ret = scoutfs_lock_inodes(sb, SCOUTFS_LOCK_WRITE,
				  SCOUTFS_LKF_REFRESH_INODE,
				  dir, &dir_lock, inode, &inode_lock,
				  NULL, NULL, NULL, NULL);
	if (ret)
		return ret;

	ret = validate_dentry(sb, scoutfs_ino(dir), dentry, dir_lock);
	if (ret < 0)
		goto out_unlock;

	if (inode->i_nlink >= SCOUTFS_LINK_MAX) {
		ret = -EMLINK;
		goto out_unlock;
	}

	dir_size = i_size_read(dir) + dentry->d_name.len;

	if (inode->i_nlink == 0) {
		del_orphan = true;
		ret = scoutfs_lock_orphan(sb, SCOUTFS_LOCK_WRITE_ONLY, 0, scoutfs_ino(inode),
					  &orph_lock);
		if (ret < 0)
			goto out_unlock;
	}

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, dir, false) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, inode, false) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq, true);
	if (ret > 0)
		goto retry;
	if (ret)
		goto out_unlock;

	ret = scoutfs_dirty_inode_item(dir, dir_lock);
	if (ret)
		goto out;

	if (del_orphan) {
		ret = scoutfs_inode_orphan_delete(sb, scoutfs_ino(inode), orph_lock, inode_lock);
		if (ret)
			goto out;
	}

	pos = SCOUTFS_I(dir)->next_readdir_pos++;

	ret = add_entry_items(sb, scoutfs_ino(dir), hash, pos,
			      dentry->d_name.name, dentry->d_name.len,
			      scoutfs_ino(inode), inode->i_mode, dir_lock,
			      inode_lock);
	if (ret) {
		err = scoutfs_inode_orphan_create(sb, scoutfs_ino(inode), orph_lock, inode_lock);
		WARN_ON_ONCE(err); /* no orphan, might not scan and delete after crash */
		goto out;
	}
	set_dentry_fsdata(dentry, dir_lock);

	i_size_write(dir, dir_size);
	dir->i_mtime = dir->i_ctime = current_time(inode);
	inode->i_ctime = dir->i_mtime;
	inc_nlink(inode);
	inode_inc_iversion(dir);
	inode_inc_iversion(inode);

	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);

	atomic_inc(&inode->i_count);
	d_instantiate(dentry, inode);
out:
	scoutfs_release_trans(sb);
out_unlock:
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, orph_lock, SCOUTFS_LOCK_WRITE_ONLY);

	return ret;
}

static bool should_orphan(struct inode *inode)
{
	if (inode == NULL)
		return false;

	if (S_ISDIR(inode->i_mode))
		return inode->i_nlink == 2;

	return inode->i_nlink == 1;
}

/*
 * Unlink removes the entry from its item and removes the item if ours
 * was the only remaining entry.
 */
static int scoutfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = dentry->d_inode;
	struct kc_timespec ts = current_time(inode);
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_lock *orph_lock = NULL;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_dirent dent;
	LIST_HEAD(ind_locks);
	u64 ind_seq;
	u64 hash;
	int ret;

	ret = scoutfs_lock_inodes(sb, SCOUTFS_LOCK_WRITE,
				  SCOUTFS_LKF_REFRESH_INODE,
				  dir, &dir_lock, inode, &inode_lock,
				  NULL, NULL, NULL, NULL);
	if (ret)
		return ret;

	ret = validate_dentry(sb, scoutfs_ino(dir), dentry, dir_lock);
	if (ret < 0)
		goto unlock;

	if (S_ISDIR(inode->i_mode) && i_size_read(inode)) {
		ret = -ENOTEMPTY;
		goto unlock;
	}

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);

	ret = lookup_dirent(sb, scoutfs_ino(dir), dentry->d_name.name, dentry->d_name.len, hash,
			    &dent, dir_lock);
	if (ret < 0)
		goto out;

	if (should_orphan(inode)) {
		ret = scoutfs_lock_orphan(sb, SCOUTFS_LOCK_WRITE_ONLY, 0, scoutfs_ino(inode),
					  &orph_lock);
		if (ret < 0)
			goto unlock;
	}

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, dir, false) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, inode, false) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq, false);
	if (ret > 0)
		goto retry;
	if (ret)
		goto unlock;

	if (should_orphan(inode)) {
		ret = scoutfs_inode_orphan_create(sb, scoutfs_ino(inode), orph_lock, inode_lock);
		if (ret < 0)
			goto out;
	}

	ret = del_entry_items(sb, scoutfs_ino(dir), le64_to_cpu(dent.hash), le64_to_cpu(dent.pos),
			      scoutfs_ino(inode), dir_lock, inode_lock);
	if (ret) {
		ret = scoutfs_inode_orphan_delete(sb, scoutfs_ino(inode), orph_lock, inode_lock);
		WARN_ON_ONCE(ret); /* should have been dirty */
		goto out;
	}

	set_dentry_fsdata(dentry, dir_lock);

	dir->i_ctime = ts;
	dir->i_mtime = ts;
	i_size_write(dir, i_size_read(dir) - dentry->d_name.len);
	inode_inc_iversion(dir);
	inode_inc_iversion(inode);

	inode->i_ctime = ts;
	drop_nlink(inode);
	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(dir);
		drop_nlink(inode);
	}
	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);

out:
	scoutfs_release_trans(sb);
unlock:
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, orph_lock, SCOUTFS_LOCK_WRITE_ONLY);

	return ret;
}

static void init_symlink_key(struct scoutfs_key *key, u64 ino, u8 nr)
{
	*key = (struct scoutfs_key) {
		.sk_zone = SCOUTFS_FS_ZONE,
		.sks_ino = cpu_to_le64(ino),
		.sk_type = SCOUTFS_SYMLINK_TYPE,
		.sks_nr = cpu_to_le64(nr),
	};
}

/*
 * Operate on all the items that make up a symlink whose target might
 * have to be split up into multiple items each with a maximally sized
 * value.
 *
 * returns 0 or -errno from the item calls, particularly including
 * EEXIST, EIO, or ENOENT if the item population doesn't match what was
 * expected given the op.
 *
 * The target name can be null for deletion when val isn't used.  Size
 * still has to be provided to determine the number of items.
 */
enum symlink_ops {
	SYM_CREATE = 0,
	SYM_LOOKUP,
	SYM_DELETE,
};
static int symlink_item_ops(struct super_block *sb, enum symlink_ops op, u64 ino,
			    struct scoutfs_lock *lock, const char *target,
			    size_t size)
{
	struct scoutfs_key key;
	unsigned bytes;
	unsigned nr;
	int ret;
	int i;

	if (WARN_ON_ONCE(size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE ||
		         op > SYM_DELETE))
		return -EINVAL;

	nr = DIV_ROUND_UP(size, SCOUTFS_MAX_VAL_SIZE);
	for (i = 0; i < nr; i++) {

		init_symlink_key(&key, ino, i);
		bytes = min_t(u64, size, SCOUTFS_MAX_VAL_SIZE);

		if (op == SYM_CREATE)
			ret = scoutfs_item_create(sb, &key, (void *)target,
						  bytes, lock);
		else if (op == SYM_LOOKUP)
			ret = scoutfs_item_lookup_exact(sb, &key,
						        (void *)target, bytes,
							lock);
		else if (op == SYM_DELETE)
			ret = scoutfs_item_delete(sb, &key, lock);
		if (ret)
			break;

		target += SCOUTFS_MAX_VAL_SIZE;
		size -= bytes;
	}

	return ret;
}

/*
 * Fill a buffer with the null terminated symlink, and return it
 * so callers can free it once the vfs is done.
 *
 * We chose to pay the runtime cost of per-call allocation and copy
 * overhead instead of wiring up symlinks to the page cache, storing
 * each small link in a full page, and later having to reclaim them.
 */
static void *scoutfs_get_link_target(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct scoutfs_lock *inode_lock = NULL;
	char *path = NULL;
	loff_t size;
	int ret;

	ret = scoutfs_lock_inode(sb, SCOUTFS_LOCK_READ,
				 SCOUTFS_LKF_REFRESH_INODE, inode, &inode_lock);
	if (ret)
		return ERR_PTR(ret);

	size = i_size_read(inode);

	if (size == 0 || size > SCOUTFS_SYMLINK_MAX_SIZE) {
		scoutfs_corruption(sb, SC_SYMLINK_INODE_SIZE,
				   corrupt_symlink_inode_size,
				   "ino %llu size %llu",
				   scoutfs_ino(inode), (u64)size);
		ret = -EIO;
		goto out;
	}

	/* unlikely, but possible I suppose */
	if (size > PATH_MAX) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	path = kmalloc(size, GFP_NOFS);
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	ret = symlink_item_ops(sb, SYM_LOOKUP, scoutfs_ino(inode), inode_lock,
			       path, size);

	if (ret == -ENOENT) {
		scoutfs_corruption(sb, SC_SYMLINK_MISSING_ITEM,
				   corrupt_symlink_missing_item,
				   "ino %llu size %llu", scoutfs_ino(inode),
				   size);
		ret = -EIO;

	} else if (ret == 0 && path[size - 1]) {
		scoutfs_corruption(sb, SC_SYMLINK_NOT_NULL_TERM,
				   corrupt_symlink_not_null_term,
				   "ino %llu last %u",
				   scoutfs_ino(inode), path[size - 1]);
		ret = -EIO;
	}

out:
	if (ret < 0) {
		kfree(path);
		path = ERR_PTR(ret);
	}

	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_READ);
	return path;
}

#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
static void *scoutfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *path;

	path = scoutfs_get_link_target(dentry);
	if (!IS_ERR_OR_NULL(path))
		nd_set_link(nd, path);
	return path;
}

static void scoutfs_put_link(struct dentry *dentry, struct nameidata *nd,
			     void *cookie)
{
	if (!IS_ERR_OR_NULL(cookie))
		kfree(cookie);
}
#else
static const char *scoutfs_get_link(struct dentry *dentry, struct inode *inode, struct delayed_call *done)
{
	char *path;

	path = scoutfs_get_link_target(dentry);
	if (!IS_ERR_OR_NULL(path))
		set_delayed_call(done, kfree_link, path);

	return path;
}
#endif

/*
 * Symlink target paths can be annoyingly large.  We store relatively
 * rare large paths in multiple items.
 */
static int scoutfs_symlink(KC_VFS_NS_DEF
			   struct inode *dir, struct dentry *dentry,
			   const char *symname)
{
	struct super_block *sb = dir->i_sb;
	const int name_len = strlen(symname) + 1;
	struct inode *inode = NULL;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_inode_info *si;
	LIST_HEAD(ind_locks);
	u64 hash;
	u64 pos;
	int ret;

	hash = dirent_name_hash(dentry->d_name.name, dentry->d_name.len);

	/* path_max includes null as does our value for nd_set_link */
	if (dentry->d_name.len > SCOUTFS_NAME_LEN ||
	    name_len > PATH_MAX || name_len > SCOUTFS_SYMLINK_MAX_SIZE)
		return -ENAMETOOLONG;

	inode = lock_hold_create(dir, dentry, S_IFLNK|S_IRWXUGO, 0,
				 &dir_lock, &inode_lock, NULL, &ind_locks);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	si = SCOUTFS_I(inode);

	ret = validate_dentry(sb, scoutfs_ino(dir), dentry, dir_lock);
	if (ret < 0)
		goto out;

	ret = symlink_item_ops(sb, SYM_CREATE, scoutfs_ino(inode), inode_lock,
			       symname, name_len);
	if (ret)
		goto out;

	pos = SCOUTFS_I(dir)->next_readdir_pos++;

	ret = add_entry_items(sb, scoutfs_ino(dir), hash, pos,
			      dentry->d_name.name, dentry->d_name.len,
			      scoutfs_ino(inode), inode->i_mode, dir_lock,
			      inode_lock);
	if (ret)
		goto out;

	set_dentry_fsdata(dentry, dir_lock);

	i_size_write(dir, i_size_read(dir) + dentry->d_name.len);
	dir->i_mtime = dir->i_ctime = current_time(inode);
	inode_inc_iversion(dir);

	inode->i_ctime = dir->i_mtime;
	si->crtime = inode->i_ctime;
	i_size_write(inode, name_len);
	inode_inc_iversion(inode);
	scoutfs_forest_inc_inode_count(sb);

	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);

	insert_inode_hash(inode);
	/* XXX need to set i_op/fop before here for sec callbacks */
	d_instantiate(dentry, inode);
	inode = NULL;
	ret = 0;
out:
	if (ret < 0) {
		/* XXX remove inode items */

		symlink_item_ops(sb, SYM_DELETE, scoutfs_ino(inode), inode_lock,
				 NULL, name_len);
	}

	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);

	if (!IS_ERR_OR_NULL(inode))
		iput(inode);

	return ret;
}

int scoutfs_symlink_drop(struct super_block *sb, u64 ino,
			 struct scoutfs_lock *lock, u64 i_size)
{
	int ret;

	ret = symlink_item_ops(sb, SYM_DELETE, ino, lock, NULL, i_size);
	if (ret == -ENOENT)
		ret = 0;

	return ret;
}

/*
 * Find the next link backref items for the given ino starting from the
 * given dir inode and final entry position.  For each backref item we
 * add an allocated copy of it to the head of the caller's list.
 *
 * Callers who are building a path can add one entry for each parent.
 * They're left with a list of entries from the root down in list order.
 *
 * Callers who are gathering multiple entries for one inode get the
 * entries in the opposite order that their items are found.
 *
 * Returns +ve for number of entries added, -ENOENT if no entries were
 * found, or -errno on error.  It weirdly won't return 0, but early
 * callers preferred -ENOENT so we use that for the case of no entries.
 *
 * Callers are comfortable with the race inherent to incrementally
 * gathering backrefs across multiple lock acquisitions.
 */
int scoutfs_dir_add_next_linkrefs(struct super_block *sb, u64 ino, u64 dir_ino, u64 dir_pos,
				  int count, struct list_head *list)
{
	struct scoutfs_link_backref_entry *prev_ent = NULL;
	struct scoutfs_link_backref_entry *ent = NULL;
	struct scoutfs_lock *lock = NULL;
	struct scoutfs_key last_key;
	struct scoutfs_key key;
	int nr = 0;
	int len;
	int ret;

	init_dirent_key(&key, SCOUTFS_LINK_BACKREF_TYPE, ino, dir_ino, dir_pos);
	init_dirent_key(&last_key, SCOUTFS_LINK_BACKREF_TYPE, ino, U64_MAX, U64_MAX);

	ret = scoutfs_lock_ino(sb, SCOUTFS_LOCK_READ, 0, ino, &lock);
	if (ret)
		goto out;

	while (nr < count) {
		ent = kmalloc(offsetof(struct scoutfs_link_backref_entry,
				       dent.name[SCOUTFS_NAME_LEN]), GFP_NOFS);
		if (!ent) {
			ret = -ENOMEM;
			goto out;
		}

		INIT_LIST_HEAD(&ent->head);

		ret = scoutfs_item_next(sb, &key, &last_key, &ent->dent,
					dirent_bytes(SCOUTFS_NAME_LEN), lock);
		if (ret < 0) {
			if (ret == -ENOENT && prev_ent)
				prev_ent->last = true;
			goto out;
		}

		len = ret - sizeof(struct scoutfs_dirent);
		if (len < 1 || len > SCOUTFS_NAME_LEN) {
			scoutfs_corruption(sb, SC_DIRENT_BACKREF_NAME_LEN,
					   corrupt_dirent_backref_name_len,
					   "ino %llu dir_ino %llu pos %llu key "SK_FMT" len %d",
					   ino, dir_ino, dir_pos, SK_ARG(&key), len);
			ret = -EIO;
			goto out;
		}

		ent->dir_ino = le64_to_cpu(key.skd_major);
		ent->dir_pos = le64_to_cpu(key.skd_minor);
		ent->name_len = len;
		ent->d_type = dentry_type(ent->dent.type);
		ent->last = false;

		trace_scoutfs_dir_add_next_linkref_found(sb, ino, ent->dir_ino, ent->dir_pos,
							 ent->name_len);

		list_add(&ent->head, list);
		prev_ent = ent;
		ent = NULL;
		nr++;
		scoutfs_key_inc(&key);
	}

	ret = 0;
out:
	scoutfs_unlock(sb, lock, SCOUTFS_LOCK_READ);
	trace_scoutfs_dir_add_next_linkrefs(sb, ino, dir_ino, dir_pos, count, nr, ret);

	kfree(ent);
	return nr ?: ret;
}

static u64 first_backref_dir_ino(struct list_head *list)
{
	struct scoutfs_link_backref_entry *ent;

	ent = list_first_entry(list, struct scoutfs_link_backref_entry, head);
	return ent->dir_ino;
}

void scoutfs_dir_free_backref_path(struct super_block *sb,
				   struct list_head *list)
{
	struct scoutfs_link_backref_entry *ent;
	struct scoutfs_link_backref_entry *pos;

	list_for_each_entry_safe(ent, pos, list, head) {
		list_del_init(&ent->head);
		kfree(ent);
	}
}

/*
 * Give the caller the next path from the root to the inode by walking
 * backref items from the dir and name position, putting the backref keys
 * we find in the caller's list.
 *
 * Return 0 if we found a path, -ENOENT if we didn't, and -errno on error.
 *
 * If parents get unlinked while we're searching we can fail to make it
 * up to the root.  We restart the search in that case.  Parent dirs
 * couldn't have been unlinked while they still had entries and we won't
 * see links to the inode that have been unlinked.
 *
 * XXX Each path component traversal is consistent but that doesn't mean
 * that the total traversed path is consistent.  If renames hit dirs
 * that have been visited and then dirs to be visited we can return a
 * path that was never present in the system:
 *
 * path to inode     mv performed           built up path
 * ----
 * a/b/c/d/e/f
 *                                          d/e/f
 *                   mv a/b/c/d/e a/b/c/
 * a/b/c/e/f
 *                   mv a/b/c     a/
 * a/c/e/f
 *                                          a/c/d/e/f
 *
 * XXX We'll protect against this by sampling the seq before the
 * traversal and restarting if we saw backref items whose seq was
 * greater than the start point.  It's not precise in that it doesn't
 * also capture the rename of a dir that we already traversed but it
 * lets us complete the traversal in one pass that very rarely restarts.
 *
 * XXX and worry about traversing entirely dirty backref items with
 * equal seqs that have seen crazy modification?  seems like we have to
 * sync if we see our dirty seq.
 */
int scoutfs_dir_get_backref_path(struct super_block *sb, u64 ino, u64 dir_ino,
				 u64 dir_pos, struct list_head *list)
{
	int retries = 10;
	u64 par_ino;
	int ret;

retry:
	if (retries-- == 0) {
		scoutfs_inc_counter(sb, dir_backref_excessive_retries);
		ret = -ELOOP;
		goto out;
	}

	/* get the next link name to the given inode */
	ret = scoutfs_dir_add_next_linkrefs(sb, ino, dir_ino, dir_pos, 1, list);
	if (ret < 0)
		goto out;

	/* then get the names of all the parent dirs */
	par_ino = first_backref_dir_ino(list);
	while (par_ino != SCOUTFS_ROOT_INO) {

		ret = scoutfs_dir_add_next_linkrefs(sb, par_ino, 0, 0, 1, list);
		if (ret < 0) {
			if (ret == -ENOENT) {
				/* restart if there was no parent component */
				scoutfs_dir_free_backref_path(sb, list);
				goto retry;
			}
			goto out;
		}

		par_ino = first_backref_dir_ino(list);
	}

	ret = 0;
out:
	if (ret < 0)
		scoutfs_dir_free_backref_path(sb, list);
	return ret;
}

/*
 * Given two parent dir inos, return the ancestor of p2 that is p1's
 * child when p1 is also an ancestor of p2: p1/p/[...]/p2.  This can
 * return p2.
 *
 * We do this by walking link backref items.  Each entry can be thought
 * of as a dirent stored at the target.  So the parent dir is stored in
 * the target.
 *
 * The caller holds the global rename lock and link backref walk locks
 * each inode as it looks up backrefs.
 */
static int item_d_ancestor(struct super_block *sb, u64 p1, u64 p2, u64 *p_ret)
{
	struct scoutfs_link_backref_entry *ent;
	LIST_HEAD(list);
	int ret;
	u64 p;

	*p_ret = 0;

	if (p2 == SCOUTFS_ROOT_INO) {
		ret = 0;
		goto out;
	}

	ret = scoutfs_dir_get_backref_path(sb, p2, 0, 0, &list);
	if (ret)
		goto out;

	p = p2;
	list_for_each_entry(ent, &list, head) {
		if (ent->dir_ino == p1) {
			*p_ret = p;
			ret = 0;
			break;
		}
		p = ent->dir_ino;
	}

out:
	scoutfs_dir_free_backref_path(sb, &list);
	return ret;
}

/*
 * The vfs checked the relationship between dirs, the source, and target
 * before acquiring clusters locks.  All that could have changed.  If
 * we're renaming between parent dirs then we try to verify the basics
 * of those checks using our backref items.
 *
 * Compare this to lock_rename()'s use of d_ancestor() and what it's
 * caller does with the returned ancestor.
 *
 * The caller only holds the global rename cluster lock.
 * item_d_ancestor is going to walk backref paths and acquire and
 * release locks for each target inode in the path.
 */
static int verify_ancestors(struct super_block *sb, u64 p1, u64 p2,
			    u64 old_ino, u64 new_ino)
{
	int ret;
	u64 p;

	ret = item_d_ancestor(sb, p1, p2, &p);
	if (ret == 0 && p == 0)
		ret = item_d_ancestor(sb, p2, p1, &p);
	if (ret == 0 && p && (p == old_ino || p == new_ino))
		ret = -EINVAL;

	return ret;
}

/*
 * The vfs performs checks on cached inodes and dirents before calling
 * here.  It doesn't hold any locks so all of those checks can be based
 * on cached state that has been invalidated by other operations in the
 * cluster before we get here.
 *
 * We do the expedient thing today and verify the basic structural
 * checks after we get cluster locks.  We perform  topology checks
 * analagous to the d_ancestor() walks in lock_rename() after acquiring
 * a clustered equivalent of the vfs rename lock.  We then lock the dir
 * and target inodes and verify that the entries assumed by the function
 * arguments still exist.
 *
 * We don't duplicate all the permissions checking in the vfs
 * (may_create(), etc, are all static.).  This means racing renames can
 * succeed after other nodes have gotten success out of changes to
 * permissions that should have forbidden renames.
 *
 * All of this wouldn't be necessary if we could get prepare/complete
 * callbacks around rename that'd let us lock the inodes, dirents, and
 * topology while the vfs walks dentries and uses inodes.
 *
 * We acquire the inode locks in inode number order.  Because of our
 * inode group locking we can't define lock ordering correctness by
 * properties that can be different in a given group.  This prevents us
 * from using parent/child locking orders as two groups can have both
 * parent and child relationships to each other.
 */
static int scoutfs_rename_common(KC_VFS_NS_DEF
				 struct inode *old_dir,
				 struct dentry *old_dentry, struct inode *new_dir,
				 struct dentry *new_dentry, unsigned int flags)
{
	struct super_block *sb = old_dir->i_sb;
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct scoutfs_lock *rename_lock = NULL;
	struct scoutfs_lock *old_dir_lock = NULL;
	struct scoutfs_lock *new_dir_lock = NULL;
	struct scoutfs_lock *old_inode_lock = NULL;
	struct scoutfs_lock *new_inode_lock = NULL;
	struct scoutfs_lock *orph_lock = NULL;
	struct scoutfs_dirent new_dent;
	struct scoutfs_dirent old_dent;
	struct kc_timespec now;
	bool ins_new = false;
	bool del_new = false;
	bool ins_old = false;
	LIST_HEAD(ind_locks);
	u64 ind_seq;
	u64 old_hash;
	u64 new_hash;
	u64 new_pos;
	int ret;
	int err;

	trace_scoutfs_rename(sb, old_dir, old_dentry, new_dir, new_dentry);

	old_hash = dirent_name_hash(old_dentry->d_name.name,
				    old_dentry->d_name.len);
	new_hash = dirent_name_hash(new_dentry->d_name.name,
				    new_dentry->d_name.len);

	if (new_dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	/* if dirs are different make sure ancestor relationships are valid */
	if (old_dir != new_dir) {
		ret = scoutfs_lock_rename(sb, SCOUTFS_LOCK_WRITE, 0,
					  &rename_lock);
		if (ret)
			return ret;

		ret = verify_ancestors(sb, scoutfs_ino(old_dir),
				       scoutfs_ino(new_dir),
				       scoutfs_ino(old_inode),
				       new_inode ? scoutfs_ino(new_inode) : 0);
		if (ret)
			goto out_unlock;
	}

	/* lock all the inodes */
	ret = scoutfs_lock_inodes(sb, SCOUTFS_LOCK_WRITE,
				  SCOUTFS_LKF_REFRESH_INODE,
				  old_dir, &old_dir_lock,
				  new_dir, &new_dir_lock,
				  old_inode, &old_inode_lock,
				  new_inode, &new_inode_lock);
	if (ret)
		goto out_unlock;

	/* make sure that the entries assumed by the argument still exist */
	ret = validate_dentry(sb, scoutfs_ino(old_dir), old_dentry, old_dir_lock) ?:
	      validate_dentry(sb, scoutfs_ino(new_dir), new_dentry, new_dir_lock);
	if (ret)
		goto out_unlock;

	/* test dir i_size now that it's refreshed */
	if (new_inode && S_ISDIR(new_inode->i_mode) && i_size_read(new_inode)) {
		ret = -ENOTEMPTY;
		goto out_unlock;
	}


	if ((flags & RENAME_NOREPLACE) && (new_inode != NULL)) {
		ret = -EEXIST;
		goto out_unlock;
	}

	if (should_orphan(new_inode)) {
		ret = scoutfs_lock_orphan(sb, SCOUTFS_LOCK_WRITE_ONLY, 0, scoutfs_ino(new_inode),
					  &orph_lock);
		if (ret < 0)
			goto out_unlock;
	}

retry:
	ret = scoutfs_inode_index_start(sb, &ind_seq) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, old_dir, false) ?:
	      scoutfs_inode_index_prepare(sb, &ind_locks, old_inode, false) ?:
	      (new_dir == old_dir ? 0 :
	       scoutfs_inode_index_prepare(sb, &ind_locks, new_dir, false)) ?:
	      (new_inode == NULL ? 0 :
	       scoutfs_inode_index_prepare(sb, &ind_locks, new_inode, false)) ?:
	      scoutfs_inode_index_try_lock_hold(sb, &ind_locks, ind_seq, true);
	if (ret > 0)
		goto retry;
	if (ret)
		goto out_unlock;

	/* get a pos for the new entry */
	new_pos = SCOUTFS_I(new_dir)->next_readdir_pos++;

	/* dirty the inodes so that updating doesn't fail */
	ret = scoutfs_dirty_inode_item(old_dir, old_dir_lock) ?:
	      scoutfs_dirty_inode_item(old_inode, old_inode_lock) ?:
	      (old_dir != new_dir ?
		scoutfs_dirty_inode_item(new_dir, new_dir_lock) : 0) ?:
	      (new_inode ?
		scoutfs_dirty_inode_item(new_inode, new_inode_lock) : 0);
	if (ret)
		goto out;

	/* remove the new entry if it exists */
	if (new_inode) {
		ret = lookup_dirent(sb, scoutfs_ino(new_dir), new_dentry->d_name.name,
				    new_dentry->d_name.len, new_hash, &new_dent, new_dir_lock);
		if (ret < 0)
			goto out;
		ret = del_entry_items(sb, scoutfs_ino(new_dir), le64_to_cpu(new_dent.hash),
				      le64_to_cpu(new_dent.pos), scoutfs_ino(new_inode),
				      new_dir_lock, new_inode_lock);
		if (ret)
			goto out;
		ins_new = true;
	}

	/* create the new entry */
	ret = add_entry_items(sb, scoutfs_ino(new_dir), new_hash, new_pos,
			      new_dentry->d_name.name, new_dentry->d_name.len,
			      scoutfs_ino(old_inode), old_inode->i_mode,
			      new_dir_lock, old_inode_lock);
	if (ret)
		goto out;
	del_new = true;

	ret = lookup_dirent(sb, scoutfs_ino(old_dir), old_dentry->d_name.name,
			    old_dentry->d_name.len, old_hash, &old_dent, old_dir_lock);
	if (ret < 0)
		goto out;

	/* remove the old entry */
	ret = del_entry_items(sb, scoutfs_ino(old_dir), le64_to_cpu(old_dent.hash),
			      le64_to_cpu(old_dent.pos), scoutfs_ino(old_inode),
			      old_dir_lock, old_inode_lock);
	if (ret)
		goto out;
	ins_old = true;

	if (should_orphan(new_inode)) {
		ret = scoutfs_inode_orphan_create(sb, scoutfs_ino(new_inode), orph_lock,
						  new_inode_lock);
		if (ret)
			goto out;
	}

	/* won't fail from here on out, update all the vfs structs */

	/* the caller will use d_move to move the old_dentry into place */
	set_dentry_fsdata(old_dentry, new_dir_lock);

       i_size_write(old_dir, i_size_read(old_dir) - old_dentry->d_name.len);
       if (!new_inode)
               i_size_write(new_dir, i_size_read(new_dir) +
                            new_dentry->d_name.len);

	if (new_inode) {
		drop_nlink(new_inode);
		if (S_ISDIR(new_inode->i_mode)) {
			drop_nlink(new_dir);
			drop_nlink(new_inode);
		}

	}

	if (S_ISDIR(old_inode->i_mode) && (old_dir != new_dir)) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}

	now = current_time(old_inode);
	old_dir->i_ctime = now;
	old_dir->i_mtime = now;
	if (new_dir != old_dir) {
		new_dir->i_ctime = now;
		new_dir->i_mtime = now;
	}
	old_inode->i_ctime = now;
	if (new_inode)
		old_inode->i_ctime = now;

	inode_inc_iversion(old_dir);
	inode_inc_iversion(old_inode);
	if (new_dir != old_dir)
		inode_inc_iversion(new_dir);
	if (new_inode)
		inode_inc_iversion(new_inode);

	scoutfs_update_inode_item(old_dir, old_dir_lock, &ind_locks);
	scoutfs_update_inode_item(old_inode, old_inode_lock, &ind_locks);
	if (new_dir != old_dir)
		scoutfs_update_inode_item(new_dir, new_dir_lock, &ind_locks);
	if (new_inode)
		scoutfs_update_inode_item(new_inode, new_inode_lock,
					  &ind_locks);
	ret = 0;
out:
	if (ret) {
		/*
		 * XXX We have to clean up partial item deletions today
		 * because we can't have two dirents existing in a
		 * directory that point to different inodes.  If we
		 * could we'd create the new name then everything after
		 * that is deletion that will only fail cleanly or
		 * succeed.  Maybe we could have an item replace call
		 * that gives us the dupe to re-insert on cleanup?  Not
		 * sure.
		 *
		 * It's safe to use dentry_info here 'cause they haven't
		 * been updated if we saw an error.
		 */
		err = 0;
		if (ins_old)
			err = add_entry_items(sb, scoutfs_ino(old_dir),
					      le64_to_cpu(old_dent.hash),
					      le64_to_cpu(old_dent.pos),
					      old_dentry->d_name.name,
					      old_dentry->d_name.len,
					      scoutfs_ino(old_inode),
					      old_inode->i_mode,
					      old_dir_lock,
					      old_inode_lock);

		if (del_new && err == 0)
			err = del_entry_items(sb, scoutfs_ino(new_dir),
					      new_hash, new_pos,
					      scoutfs_ino(old_inode),
					      new_dir_lock, old_inode_lock);

		if (ins_new && err == 0)
			err = add_entry_items(sb, scoutfs_ino(new_dir),
					      le64_to_cpu(new_dent.hash),
					      le64_to_cpu(new_dent.pos),
					      new_dentry->d_name.name,
					      new_dentry->d_name.len,
					      scoutfs_ino(new_inode),
					      new_inode->i_mode,
					      new_dir_lock,
					      new_inode_lock);
		/* XXX freak out: panic, go read only, etc */
		BUG_ON(err);
	}

	scoutfs_release_trans(sb);

out_unlock:
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, old_inode_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, new_inode_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, old_dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, new_dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, rename_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, orph_lock, SCOUTFS_LOCK_WRITE_ONLY);

	return ret;
}

#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
static int scoutfs_rename(struct inode *old_dir,
			  struct dentry *old_dentry, struct inode *new_dir,
			  struct dentry *new_dentry)
{
	return scoutfs_rename_common(KC_VFS_INIT_NS
				     old_dir, old_dentry, new_dir, new_dentry, 0);
}
#endif

static int scoutfs_rename2(KC_VFS_NS_DEF
			  struct inode *old_dir,
			  struct dentry *old_dentry, struct inode *new_dir,
			  struct dentry *new_dentry, unsigned int flags)
{
	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	return scoutfs_rename_common(KC_VFS_NS
				     old_dir, old_dentry, new_dir, new_dentry, flags);
}

#ifdef KC_FMODE_KABI_ITERATE
/* we only need this to set the iterate flag for kabi :/ */
static int scoutfs_dir_open(struct inode *inode, struct file *file)
{
        file->f_mode |= FMODE_KABI_ITERATE;
        return 0;
}
#endif

static int scoutfs_tmpfile(KC_VFS_NS_DEF
			   struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = NULL;
	struct scoutfs_lock *dir_lock = NULL;
	struct scoutfs_lock *inode_lock = NULL;
	struct scoutfs_lock *orph_lock = NULL;
	struct scoutfs_inode_info *si;
	LIST_HEAD(ind_locks);
	int ret;

	if (dentry->d_name.len > SCOUTFS_NAME_LEN)
		return -ENAMETOOLONG;

	inode = lock_hold_create(dir, dentry, mode, 0,
				 &dir_lock, &inode_lock, &orph_lock, &ind_locks);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	si = SCOUTFS_I(inode);

	ret = scoutfs_inode_orphan_create(sb, scoutfs_ino(inode), orph_lock, inode_lock);
	if (ret < 0)
		goto out; /* XXX returning error but items created */

	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	si->crtime = inode->i_mtime;
	insert_inode_hash(inode);
	ihold(inode); /* need to update inode modifications in d_tmpfile */
	d_tmpfile(dentry, inode);
	inode_inc_iversion(inode);
	scoutfs_forest_inc_inode_count(sb);

	scoutfs_update_inode_item(inode, inode_lock, &ind_locks);
	scoutfs_update_inode_item(dir, dir_lock, &ind_locks);
	scoutfs_inode_index_unlock(sb, &ind_locks);

out:
	scoutfs_release_trans(sb);
	scoutfs_inode_index_unlock(sb, &ind_locks);
	scoutfs_unlock(sb, dir_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, inode_lock, SCOUTFS_LOCK_WRITE);
	scoutfs_unlock(sb, orph_lock, SCOUTFS_LOCK_WRITE_ONLY);

	if (!IS_ERR_OR_NULL(inode))
		iput(inode);

	return ret;
}

const struct inode_operations scoutfs_symlink_iops = {
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.readlink       = generic_readlink,
	.follow_link    = scoutfs_follow_link,
	.put_link       = scoutfs_put_link,
#else
	.get_link	= scoutfs_get_link,
#endif
	.getattr	= scoutfs_getattr,
	.setattr	= scoutfs_setattr,
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
#endif
	.listxattr	= scoutfs_listxattr,
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.removexattr	= generic_removexattr,
#endif
	.get_acl	= scoutfs_get_acl,
#ifndef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.tmpfile	= scoutfs_tmpfile,
	.rename		= scoutfs_rename_common,
	.symlink	= scoutfs_symlink,
	.unlink		= scoutfs_unlink,
	.link		= scoutfs_link,
	.mkdir		= scoutfs_mkdir,
	.create		= scoutfs_create,
	.lookup		= scoutfs_lookup,
#endif
};

const struct file_operations scoutfs_dir_fops = {
	.KC_FOP_READDIR	= scoutfs_readdir,
#ifdef KC_FMODE_KABI_ITERATE
	.open		= scoutfs_dir_open,
#endif
	.unlocked_ioctl	= scoutfs_ioctl,
	.fsync		= scoutfs_file_fsync,
	.llseek		= generic_file_llseek,
};


#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
const struct inode_operations_wrapper scoutfs_dir_iops = {
	.ops = {
#else
const struct inode_operations scoutfs_dir_iops = {
#endif
	.lookup		= scoutfs_lookup,
	.mknod		= scoutfs_mknod,
	.create		= scoutfs_create,
	.mkdir		= scoutfs_mkdir,
	.link		= scoutfs_link,
	.unlink		= scoutfs_unlink,
	.rmdir		= scoutfs_unlink,
	.getattr	= scoutfs_getattr,
	.setattr	= scoutfs_setattr,
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.rename		= scoutfs_rename,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.removexattr	= generic_removexattr,
#endif
	.listxattr	= scoutfs_listxattr,
	.get_acl	= scoutfs_get_acl,
	.symlink	= scoutfs_symlink,
	.permission	= scoutfs_permission,
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	},
#endif
	.tmpfile	= scoutfs_tmpfile,
#ifdef KC_LINUX_HAVE_RHEL_IOPS_WRAPPER
	.rename2	= scoutfs_rename2,
#else
	.rename		= scoutfs_rename2,
#endif
};
