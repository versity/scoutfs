/*
 * Copyright (C) 2015 Versity Software, Inc.  All rights reserved.
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
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/magic.h>
#include <linux/random.h>
#include <linux/statfs.h>
#include <linux/sched.h>
#include <linux/debugfs.h>

#include "super.h"
#include "block.h"
#include "export.h"
#include "format.h"
#include "inode.h"
#include "dir.h"
#include "msg.h"
#include "counters.h"
#include "triggers.h"
#include "trans.h"
#include "data.h"
#include "lock.h"
#include "net.h"
#include "client.h"
#include "server.h"
#include "options.h"
#include "sysfs.h"
#include "quorum.h"
#include "forest.h"
#include "srch.h"
#include "item.h"
#include "alloc.h"
#include "recov.h"
#include "omap.h"
#include "volopt.h"
#include "fence.h"
#include "xattr.h"
#include "scoutfs_trace.h"

static struct dentry *scoutfs_debugfs_root;

/* the statfs file fields can be small (and signed?) :/ */
static __statfs_word saturate_truncated_word(u64 files)
{
	__statfs_word word = files;

	if (word != files) {
		word = ~0ULL;
		if (word < 0)
			word = (unsigned long)word >> 1;
	}

	return word;
}

/*
 * The server gives us the current sum of free blocks and the total
 * inode count that it can see across all the clients' log trees.  It
 * won't see allocations and inode creations or deletions that are dirty
 * in client memory as it builds a transaction.
 *
 * We don't have static limits on the number of files so the statfs
 * fields for the total possible files and the number free isn't
 * particularly helpful.  What we do want to report is the number of
 * inodes, so we fake a max possible number of inodes given a
 * conservative estimate of the total space consumption per file and
 * then find the free by subtracting our precise count of active inodes.
 * This seems like the least surprising compromise where the file max
 * doesn't change and the caller gets the correct count of used inodes.
 *
 * The fsid that we report is constructed from the xor of the first two
 * and second two little endian u32s that make up the uuid bytes.
 */
static int scoutfs_statfs(struct dentry *dentry, struct kstatfs *kst)
{
	struct super_block *sb = dentry->d_inode->i_sb;
	struct scoutfs_net_statfs nst;
	u64 files;
	u64 ffree;
	__le32 uuid[4];
	int ret;

	scoutfs_inc_counter(sb, statfs);

	ret = scoutfs_client_statfs(sb, &nst);
	if (ret)
		goto out;

	kst->f_bfree = (le64_to_cpu(nst.free_meta_blocks) << SCOUTFS_BLOCK_SM_LG_SHIFT) +
		       le64_to_cpu(nst.free_data_blocks);
	kst->f_type = SCOUTFS_SUPER_MAGIC;
	kst->f_bsize = SCOUTFS_BLOCK_SM_SIZE;
	kst->f_blocks = (le64_to_cpu(nst.total_meta_blocks) << SCOUTFS_BLOCK_SM_LG_SHIFT) +
			le64_to_cpu(nst.total_data_blocks);
	kst->f_bavail = kst->f_bfree;

	files = div_u64(le64_to_cpu(nst.total_meta_blocks) << SCOUTFS_BLOCK_LG_SHIFT, 2048);
	ffree = files - le64_to_cpu(nst.inode_count);
	kst->f_files = saturate_truncated_word(files);
	kst->f_ffree = saturate_truncated_word(ffree);

	BUILD_BUG_ON(sizeof(uuid) != sizeof(nst.uuid));
	memcpy(uuid, nst.uuid, sizeof(uuid));
	kst->f_fsid.val[0] = le32_to_cpu(uuid[0]) ^ le32_to_cpu(uuid[1]);
	kst->f_fsid.val[1] = le32_to_cpu(uuid[2]) ^ le32_to_cpu(uuid[3]);
	kst->f_namelen = SCOUTFS_NAME_LEN;
	kst->f_frsize = SCOUTFS_BLOCK_SM_SIZE;

	/* the vfs fills f_flags */
	ret = 0;
out:
	/*
	 * We don't take cluster locks in statfs which makes it a very
	 * convenient place to trigger lock reclaim for debugging. We
	 * try to free as many locks as possible.
	 */
	if (scoutfs_trigger(sb, STATFS_LOCK_PURGE))
		scoutfs_free_unused_locks(sb);

	return ret;
}

static int scoutfs_sync_fs(struct super_block *sb, int wait)
{
	trace_scoutfs_sync_fs(sb, wait);
	scoutfs_inc_counter(sb, trans_commit_sync_fs);

	return scoutfs_trans_sync(sb, wait);
}

/*
 * Data dev is closed by generic code, but we have to explicitly close the meta
 * dev.
 */
static void scoutfs_metadev_close(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (sbi->meta_bdev) {
		/*
		 * Some kernels have blkdev_reread_part which calls
		 * fsync_bdev while holding the bd_mutex which inverts
		 * the s_umount hold in deactivate_super and blkdev_put
		 * from kill_sb->put_super.
		 */
		lockdep_off();
		blkdev_put(sbi->meta_bdev, SCOUTFS_META_BDEV_MODE);
		lockdep_on();
		sbi->meta_bdev = NULL;
	}
}

/*
 * This destroys all the state that's built up in the sb info during
 * mount.  It's called by us on errors during mount if we haven't set
 * s_root, by mount after returning errors if we have set s_root, and by
 * unmount after having synced the super.
 */
static void scoutfs_put_super(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	trace_scoutfs_put_super(sb);

	/*
	 * Wait for invalidation and iput to finish with any lingering
	 * inode references that escaped the evict_inodes in
	 * generic_shutdown_super.  SB_ACTIVE is clear so final iput
	 * will always evict.
	 */
	scoutfs_lock_flush_invalidate(sb);
	scoutfs_inode_flush_iput(sb);
	WARN_ON_ONCE(!list_empty(&sb->s_inodes));

	scoutfs_forest_stop(sb);
	scoutfs_srch_destroy(sb);

	scoutfs_lock_shutdown(sb);

	scoutfs_shutdown_trans(sb);
	scoutfs_volopt_destroy(sb);
	scoutfs_client_destroy(sb);
	scoutfs_inode_destroy(sb);
	scoutfs_item_destroy(sb);
	scoutfs_forest_destroy(sb);
	scoutfs_data_destroy(sb);

	scoutfs_quorum_destroy(sb);
	scoutfs_server_destroy(sb);
	scoutfs_recov_destroy(sb);
	scoutfs_net_destroy(sb);
	scoutfs_lock_destroy(sb);
	scoutfs_omap_destroy(sb);

	scoutfs_block_destroy(sb);
	scoutfs_destroy_triggers(sb);
	scoutfs_fence_destroy(sb);
	scoutfs_options_destroy(sb);
	debugfs_remove(sbi->debug_root);
	scoutfs_destroy_counters(sb);
	scoutfs_destroy_sysfs(sb);
	scoutfs_metadev_close(sb);

	kfree(sbi);

	sb->s_fs_info = NULL;
}

/*
 * Record that we're performing a forced unmount.  As put_super drives
 * destruction of the filesystem we won't issue more network or storage
 * operations because we assume that they'll hang.  Pending operations
 * can return errors when it's possible to do so.  We may be racing with
 * pending operations which can't be canceled.
 */
static void scoutfs_umount_begin(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	scoutfs_warn(sb, "forcing unmount, can return errors and lose unsynced data");
	sbi->forced_unmount = true;

	scoutfs_client_net_shutdown(sb);
}

static const struct super_operations scoutfs_super_ops = {
	.alloc_inode = scoutfs_alloc_inode,
	.drop_inode = scoutfs_drop_inode,
	.evict_inode = scoutfs_evict_inode,
	.destroy_inode = scoutfs_destroy_inode,
	.sync_fs = scoutfs_sync_fs,
	.statfs = scoutfs_statfs,
	.show_options = scoutfs_options_show,
	.put_super = scoutfs_put_super,
	.umount_begin = scoutfs_umount_begin,
};

/*
 * Write the caller's super.  The caller has always read a valid super
 * before modifying and writing it.  The caller's super is modified
 * to reflect the write.
 */
int scoutfs_write_super(struct super_block *sb,
			struct scoutfs_super_block *super)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	le64_add_cpu(&super->hdr.seq, 1);

	return scoutfs_block_write_sm(sb, sbi->meta_bdev, SCOUTFS_SUPER_BLKNO,
				      &super->hdr,
				      sizeof(struct scoutfs_super_block));
}

static bool small_bdev(struct super_block *sb, char *which, u64 blocks,
		       struct block_device *bdev, int shift)
{
	u64 size = (u64)i_size_read(bdev->bd_inode);
	u64 count = size >> shift;

	if (blocks > count) {
		scoutfs_err(sb, "super block records %llu %s blocks, but device %u:%u size %llu only allows %llu blocks",
			blocks, which, MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev), size, count);

		return true;
	}

	return false;
}

/*
 * Read super, specifying bdev.
 */
static int scoutfs_read_super_from_bdev(struct super_block *sb,
					struct block_device *bdev,
					struct scoutfs_super_block *super_res)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	struct scoutfs_super_block *super;
	__le32 calc;
	int ret;

	super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	if (!super)
		return -ENOMEM;

	ret = scoutfs_block_read_sm(sb, bdev, SCOUTFS_SUPER_BLKNO, &super->hdr,
				    sizeof(struct scoutfs_super_block), &calc, true);
	if (ret < 0)
		goto out;

	if (super->hdr.magic != cpu_to_le32(SCOUTFS_BLOCK_MAGIC_SUPER)) {
		scoutfs_err(sb, "super block has invalid magic value 0x%08x",
			    le32_to_cpu(super->hdr.magic));
		ret = -EINVAL;
		goto out;
	}

	if (calc != super->hdr.crc) {
		scoutfs_err(sb, "super block has invalid crc 0x%08x, calculated 0x%08x",
			    le32_to_cpu(super->hdr.crc), le32_to_cpu(calc));
		ret = -EINVAL;
		goto out;
	}

	if (le64_to_cpu(super->hdr.blkno) != SCOUTFS_SUPER_BLKNO) {
		scoutfs_err(sb, "super block has invalid block number %llu, data read from %llu",
		le64_to_cpu(super->hdr.blkno), SCOUTFS_SUPER_BLKNO);
		ret = -EINVAL;
		goto out;
	}

	if (le64_to_cpu(super->fmt_vers) < SCOUTFS_FORMAT_VERSION_MIN ||
	    le64_to_cpu(super->fmt_vers) > SCOUTFS_FORMAT_VERSION_MAX) {
		scoutfs_err(sb, "super block has format version %llu outside of supported version range %u-%u",
			    le64_to_cpu(super->fmt_vers), SCOUTFS_FORMAT_VERSION_MIN,
			    SCOUTFS_FORMAT_VERSION_MAX);
		ret = -EINVAL;
		goto out;
	}

	/*
	 * fill_supers checks the fmt_vers in both supers and then decides to use it.
	 * From then on we verify that the supers we read have that version.
	 */
	if (sbi->fmt_vers != 0 && le64_to_cpu(super->fmt_vers) != sbi->fmt_vers) {
		scoutfs_err(sb, "super block has format version %llu than %llu read at mount",
			    le64_to_cpu(super->fmt_vers), sbi->fmt_vers);
		ret = -EINVAL;
		goto out;
	}

	/* XXX do we want more rigorous invalid super checking? */

	if (small_bdev(sb, "metadata", le64_to_cpu(super->total_meta_blocks), sbi->meta_bdev,
		       SCOUTFS_BLOCK_LG_SHIFT) ||
	    small_bdev(sb, "data", le64_to_cpu(super->total_data_blocks), sb->s_bdev,
		       SCOUTFS_BLOCK_SM_SHIFT)) {
		ret = -EINVAL;
	}

out:
	if (ret == 0)
		*super_res = *super;
	kfree(super);

	return ret;
}

/*
 * Read the super block from meta dev.
 */
int scoutfs_read_super(struct super_block *sb,
		       struct scoutfs_super_block *super_res)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	return scoutfs_read_super_from_bdev(sb, sbi->meta_bdev, super_res);
}

/*
 * This needs to be setup after reading the super because it uses the
 * fsid found in the super block.
 */
static int scoutfs_debugfs_setup(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	char name[32];

	snprintf(name, ARRAY_SIZE(name), SCSBF, SCSB_ARGS(sb));

	sbi->debug_root = debugfs_create_dir(name, scoutfs_debugfs_root);
	if (!sbi->debug_root)
		return -ENOMEM;

	return 0;
}

/*
 * Calculate a random id for the mount very early, it's used in tracing
 * and message output.  The system assumes that a rid of 0 can't exist.  We're
 * also paranoid and avoid rids that are likely the result of bad rng.
 */
static int assign_random_id(struct scoutfs_sb_info *sbi)
{
	unsigned int attempts = 0;

	do {
		if (++attempts == 100)
			return -EIO;
		get_random_bytes(&sbi->rid, sizeof(sbi->rid));
	} while (sbi->rid == 0 || sbi->rid == ~0ULL);

	return 0;
}

/*
 * Ensure superblock copies in metadata and data block devices are valid, and
 * fill in in-memory superblock if so.
 */
static int scoutfs_read_supers(struct super_block *sb)
{
	struct scoutfs_super_block *meta_super = NULL;
	struct scoutfs_super_block *data_super = NULL;
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);
	int ret = 0;

	meta_super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	data_super = kmalloc(sizeof(struct scoutfs_super_block), GFP_NOFS);
	if (!meta_super || !data_super) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scoutfs_read_super_from_bdev(sb, sbi->meta_bdev, meta_super);
	if (ret < 0) {
		scoutfs_err(sb, "could not get meta_super: error %d", ret);
		goto out;
	}

	ret = scoutfs_read_super_from_bdev(sb, sb->s_bdev, data_super);
	if (ret < 0) {
		scoutfs_err(sb, "could not get data_super: error %d", ret);
		goto out;
	}

	if (!SCOUTFS_IS_META_BDEV(meta_super)) {
		scoutfs_err(sb, "meta_super META flag not set");
		ret = -EINVAL;
		goto out;
	}

	if (SCOUTFS_IS_META_BDEV(data_super)) {
		scoutfs_err(sb, "data_super META flag set");
		ret = -EINVAL;
		goto out;
	}

	if (memcmp(meta_super->uuid, data_super->uuid, SCOUTFS_UUID_BYTES)) {
		scoutfs_err(sb, "superblock UUID mismatch");
		ret = -EINVAL;
		goto out;
	}

	if (le64_to_cpu(meta_super->fmt_vers) != le64_to_cpu(data_super->fmt_vers)) {
		scoutfs_err(sb, "meta device format version %llu != data device format version %llu",
			    le64_to_cpu(meta_super->fmt_vers), le64_to_cpu(data_super->fmt_vers));
		goto out;
	}

	sbi->fsid = le64_to_cpu(meta_super->hdr.fsid);
	sbi->fmt_vers = le64_to_cpu(meta_super->fmt_vers);
out:
	kfree(meta_super);
	kfree(data_super);
	return ret;
}

static int scoutfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct scoutfs_mount_options opts;
	struct block_device *meta_bdev;
	struct scoutfs_sb_info *sbi;
	struct inode *inode;
	int ret;

	trace_scoutfs_fill_super(sb);

	sb->s_magic = SCOUTFS_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_op = &scoutfs_super_ops;
	sb->s_d_op = &scoutfs_dentry_ops;
	sb->s_export_op = &scoutfs_export_ops;
	sb->s_xattr = scoutfs_xattr_handlers;
	sb->s_flags |= SB_I_VERSION | SB_POSIXACL;
	sb->s_time_gran = 1;

	/* btree blocks use long lived bh->b_data refs */
	mapping_set_gfp_mask(sb->s_bdev->bd_inode->i_mapping, GFP_NOFS);

	sbi = kzalloc(sizeof(struct scoutfs_sb_info), GFP_KERNEL);
	sb->s_fs_info = sbi;
	sbi->sb = sb;
	if (!sbi)
		return -ENOMEM;

	ret = assign_random_id(sbi);
	if (ret < 0)
		goto out;

	spin_lock_init(&sbi->next_ino_lock);
	spin_lock_init(&sbi->data_wait_root.lock);
	sbi->data_wait_root.root = RB_ROOT;

	/* parse options early for use during setup */
	ret = scoutfs_options_early_setup(sb, data);
	if (ret < 0)
		goto out;
	scoutfs_options_read(sb, &opts);

	ret = sb_set_blocksize(sb, SCOUTFS_BLOCK_SM_SIZE);
	if (ret != SCOUTFS_BLOCK_SM_SIZE) {
		scoutfs_err(sb, "failed to set blocksize, returned %d", ret);
		ret = -EIO;
		goto out;
	}

	meta_bdev = blkdev_get_by_path(opts.metadev_path, SCOUTFS_META_BDEV_MODE, sb);
	if (IS_ERR(meta_bdev)) {
		scoutfs_err(sb, "could not open metadev: error %ld",
			    PTR_ERR(meta_bdev));
		ret = PTR_ERR(meta_bdev);
		goto out;
	}
	sbi->meta_bdev = meta_bdev;
	ret = set_blocksize(sbi->meta_bdev, SCOUTFS_BLOCK_SM_SIZE);
	if (ret != 0) {
		scoutfs_err(sb, "failed to set metadev blocksize, returned %d",
			    ret);
		goto out;
	}

	ret = scoutfs_block_setup(sb) ?:
		scoutfs_read_supers(sb) ?:
	      scoutfs_debugfs_setup(sb) ?:
	      scoutfs_setup_sysfs(sb) ?:
	      scoutfs_setup_counters(sb) ?:
	      scoutfs_options_setup(sb) ?:
	      scoutfs_setup_triggers(sb) ?:
	      scoutfs_fence_setup(sb) ?:
	      scoutfs_forest_setup(sb) ?:
	      scoutfs_item_setup(sb) ?:
	      scoutfs_inode_setup(sb) ?:
	      scoutfs_data_setup(sb) ?:
	      scoutfs_setup_trans(sb) ?:
	      scoutfs_omap_setup(sb) ?:
	      scoutfs_lock_setup(sb) ?:
	      scoutfs_net_setup(sb) ?:
	      scoutfs_recov_setup(sb) ?:
	      scoutfs_server_setup(sb) ?:
	      scoutfs_quorum_setup(sb) ?:
	      scoutfs_client_setup(sb) ?:
	      scoutfs_volopt_setup(sb) ?:
	      scoutfs_srch_setup(sb);
	if (ret)
		goto out;

	/* this interruptible iget lets hung mount be aborted with ctl-c */
	inode = scoutfs_iget(sb, SCOUTFS_ROOT_INO, SCOUTFS_LKF_INTERRUPTIBLE, 0);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		if (ret == -ERESTARTSYS)
			ret = -EINTR;
		goto out;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto out;
	}

	/* send requests once iget progress shows we had a server */
	ret = scoutfs_trans_get_log_trees(sb);
	if (ret)
		goto out;

	/* start up background services that use everything else */
	scoutfs_inode_start(sb);
	scoutfs_forest_start(sb);
	scoutfs_trans_restart_sync_deadline(sb);
	ret = 0;
out:
	/* on error, generic_shutdown_super calls put_super if s_root */
	if (ret && !sb->s_root)
		scoutfs_put_super(sb);

	return ret;
}

static struct dentry *scoutfs_mount(struct file_system_type *fs_type, int flags,
				    const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, scoutfs_fill_super);
}

/*
 * kill_block_super eventually calls ->put_super if s_root is set
 */
static void scoutfs_kill_sb(struct super_block *sb)
{
	struct scoutfs_sb_info *sbi = SCOUTFS_SB(sb);

	if (sbi) {
		sbi->unmounting = true;
		smp_wmb();
	}

	if (SCOUTFS_HAS_SBI(sb)) {
		scoutfs_options_stop(sb);
		scoutfs_inode_orphan_stop(sb);
		scoutfs_lock_unmount_begin(sb);
	}

	kill_block_super(sb);
}

static struct file_system_type scoutfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "scoutfs",
	.mount		= scoutfs_mount,
	.kill_sb	= scoutfs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("scoutfs");

/* safe to call at any failure point in _init */
static void teardown_module(void)
{
	debugfs_remove(scoutfs_debugfs_root);
	scoutfs_inode_exit();
	scoutfs_sysfs_exit();
}

static int __init scoutfs_module_init(void)
{
	int ret;

	/*
	 * gcc only recently learned to let __attribute__(section) add
	 * SHT_NOTE notes.  But the assembler always could.
	 */
	__asm__ __volatile__ (
		".section	.note.git_describe,\"a\"\n"
		".ascii		\""SCOUTFS_GIT_DESCRIBE"\\n\"\n"
		".previous\n");
	__asm__ __volatile__ (
		".section	.note.scoutfs_format_version_min,\"a\"\n"
		".ascii		\""SCOUTFS_FORMAT_VERSION_MIN_STR"\\n\"\n"
		".previous\n");
	__asm__ __volatile__ (
		".section	.note.scoutfs_format_version_max,\"a\"\n"
		".ascii		\""SCOUTFS_FORMAT_VERSION_MAX_STR"\\n\"\n"
		".previous\n");

	scoutfs_init_counters();

	ret = scoutfs_sysfs_init();
	if (ret)
		return ret;

	scoutfs_debugfs_root = debugfs_create_dir("scoutfs", NULL);
	if (!scoutfs_debugfs_root) {
		ret = -ENOMEM;
		goto out;
	}
	ret = scoutfs_inode_init() ?:
	      register_filesystem(&scoutfs_fs_type);
out:
	if (ret)
		teardown_module();
	return ret;
}
module_init(scoutfs_module_init);

static void __exit scoutfs_module_exit(void)
{
	unregister_filesystem(&scoutfs_fs_type);
	teardown_module();
}
module_exit(scoutfs_module_exit);

MODULE_AUTHOR("Zach Brown <zab@versity.com>");
MODULE_LICENSE("GPL");
MODULE_INFO(git_describe, SCOUTFS_GIT_DESCRIBE);
MODULE_INFO(scoutfs_format_version_min, SCOUTFS_FORMAT_VERSION_MIN_STR);
MODULE_INFO(scoutfs_format_version_max, SCOUTFS_FORMAT_VERSION_MAX_STR);
