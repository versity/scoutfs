#ifndef _SCOUTFS_KERNELCOMPAT_H_
#define _SCOUTFS_KERNELCOMPAT_H_

#include <linux/kernel.h>
#include <linux/fs.h>

/*
 * v4.15-rc3-4-gae5e165d855d
 *
 * new API for handling inode->i_version. This forces us to
 * include this API where we need. We include it here for
 * convenience instead of where it's needed.
 */
#ifdef KC_NEED_LINUX_IVERSION_H
#include <linux/iversion.h>
#else
/*
 * Kernels before above version will need to fall back to
 * manipulating inode->i_version as previous with degraded
 * methods.
 */
#define inode_set_iversion_queried(inode, val)	\
do {						\
	(inode)->i_version = val;		\
} while (0)
#define inode_peek_iversion(inode)		\
({						\
	(inode)->i_version;			\
})
#endif

#ifndef KC_ITERATE_DIR_CONTEXT
typedef filldir_t kc_readdir_ctx_t;
#define KC_DECLARE_READDIR(name, file, dirent, ctx) name(file, dirent, ctx)
#define KC_FOP_READDIR readdir
#define kc_readdir_pos(filp, ctx) (filp)->f_pos
#define kc_dir_emit_dots(file, dirent, ctx) dir_emit_dots(file, dirent, ctx)
#define kc_dir_emit(ctx, dirent, name, name_len, pos, ino, dt) \
	(ctx(dirent, name, name_len, pos, ino, dt) == 0)
#else
typedef struct dir_context * kc_readdir_ctx_t;
#define KC_DECLARE_READDIR(name, file, dirent, ctx) name(file, ctx)
#define KC_FOP_READDIR iterate
#define kc_readdir_pos(filp, ctx) (ctx)->pos
#define kc_dir_emit_dots(file, dirent, ctx) dir_emit_dots(file, ctx)
#define kc_dir_emit(ctx, dirent, name, name_len, pos, ino, dt) \
	dir_emit(ctx, name, name_len, ino, dt)
#endif

#ifndef KC_DIR_EMIT_DOTS
/*
 * Kernels before ->iterate and don't have dir_emit_dots so we give them
 * one that works with the ->readdir() filldir() method.
 */
static inline int dir_emit_dots(struct file *file, void *dirent,
				filldir_t filldir)
{
	if (file->f_pos == 0) {
		if (filldir(dirent, ".", 1, 1,
			    file->f_path.dentry->d_inode->i_ino, DT_DIR))
			return 0;
		file->f_pos = 1;
	}

	if (file->f_pos == 1) {
		if (filldir(dirent, "..", 2, 1,
			    parent_ino(file->f_path.dentry), DT_DIR))
			return 0;
		file->f_pos = 2;
	}

	return 1;
}
#endif

#ifdef KC_POSIX_ACL_VALID_USER_NS
#define kc_posix_acl_valid(user_ns, acl) posix_acl_valid(user_ns, acl)
#else
#define kc_posix_acl_valid(user_ns, acl) posix_acl_valid(acl)
#endif

/*
 * v3.6-rc1-24-gdbf2576e37da
 *
 * All workqueues are now non-reentrant, and the bit flag is removed
 * shortly after its uses were removed.
 */
#ifndef WQ_NON_REENTRANT
#define WQ_NON_REENTRANT 0
#endif

/*
 * v3.18-rc2-19-gb5ae6b15bd73
 *
 * Folds d_materialise_unique into d_splice_alias. Note reversal
 * of arguments (Also note Documentation/filesystems/porting.rst)
 */
#ifndef KC_D_MATERIALISE_UNIQUE
#define d_materialise_unique(dentry, inode) d_splice_alias(inode, dentry)
#endif

/*
 * v4.8-rc1-29-g31051c85b5e2
 *
 * fall back to inode_change_ok() if setattr_prepare() isn't available
 */
#ifndef KC_SETATTR_PREPARE
#define setattr_prepare(dentry, attr) inode_change_ok(d_inode(dentry), attr)
#endif

#ifndef KC___POSIX_ACL_CREATE
#define __posix_acl_create posix_acl_create
#define __posix_acl_chmod posix_acl_chmod
#endif

#ifndef KC_PERCPU_COUNTER_ADD_BATCH
#define percpu_counter_add_batch __percpu_counter_add
#endif

#ifndef KC_MEMALLOC_NOFS_SAVE
#define memalloc_nofs_save memalloc_noio_save
#define memalloc_nofs_restore memalloc_noio_restore
#endif

#endif
