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

#ifdef KC_BIO_BI_OPF
#define kc_bio_get_opf(bio)		\
({					\
	(bio)->bi_opf;			\
})
#define kc_bio_set_opf(bio, opf)	\
do {					\
	(bio)->bi_opf = opf;		\
} while (0)
#define kc_bio_set_sector(bio, sect)	\
do {					\
	(bio)->bi_iter.bi_sector = sect;\
} while (0)
#define kc_submit_bio(bio) submit_bio(bio)
#else
#define kc_bio_get_opf(bio)		\
({					\
	(bio)->bi_rw;			\
})
#define kc_bio_set_opf(bio, opf)	\
do {					\
	(bio)->bi_rw = opf;		\
} while (0)
#define kc_bio_set_sector(bio, sect)	\
do {					\
	(bio)->bi_sector = sect;	\
} while (0)
#define kc_submit_bio(bio)		\
do {					\
	submit_bio((bio)->bi_rw, bio);	\
} while (0)
#define bio_set_dev(bio, bdev)		\
do {					\
	(bio)->bi_bdev = (bdev);	\
} while (0)
#endif

#ifdef KC_BIO_BI_STATUS
#define KC_DECLARE_BIO_END_IO(name, bio)	name(bio)
#define kc_bio_get_errno(bio)			({ blk_status_to_errno((bio)->bi_status); })
#else
#define KC_DECLARE_BIO_END_IO(name, bio)	name(bio, int _error_arg)
#define kc_bio_get_errno(bio)			({ (int)((void)(bio), _error_arg); })
#endif

/*
 * v4.13-rc1-6-ge462ec50cb5f
 *
 * MS_* (mount) flags from <linux/mount.h> should not be used in the kernel
 * anymore from 4.x onwards. Instead, we need to use the SB_* (superblock) flags
 */
#ifndef SB_POSIXACL
#define SB_POSIXACL MS_POSIXACL
#define SB_I_VERSION MS_I_VERSION
#endif

#ifndef KC_SHRINKER_SHRINK

#define KC_DEFINE_SHRINKER(name) struct shrinker name
#define KC_INIT_SHRINKER_FUNCS(name, countfn, scanfn) do {	\
	__typeof__(name) _shrink = (name);			\
	_shrink->count_objects = (countfn);			\
	_shrink->scan_objects = (scanfn);			\
	_shrink->seeks = DEFAULT_SEEKS;			\
} while (0)

#define KC_SHRINKER_CONTAINER_OF(ptr, type) container_of(ptr, type, shrinker)
#define KC_REGISTER_SHRINKER(ptr) (register_shrinker(ptr))
#define KC_UNREGISTER_SHRINKER(ptr) (unregister_shrinker(ptr))
#define KC_SHRINKER_FN(ptr) (ptr)
#else

#include <linux/shrinker.h>
#ifndef SHRINK_STOP
#define SHRINK_STOP (~0UL)
#define SHRINK_EMPTY (~0UL - 1)
#endif

int kc_shrink_wrapper_fn(struct shrinker *shrink, struct shrink_control *sc);
struct kc_shrinker_wrapper {
	unsigned long (*count_objects)(struct shrinker *, struct shrink_control *sc);
	unsigned long (*scan_objects)(struct shrinker *, struct shrink_control *sc);
	struct shrinker shrink;
};

#define KC_DEFINE_SHRINKER(name) struct kc_shrinker_wrapper name;
#define KC_INIT_SHRINKER_FUNCS(name, countfn, scanfn) do {	\
	struct kc_shrinker_wrapper *_wrap = (name);		\
	_wrap->count_objects = (countfn);			\
	_wrap->scan_objects = (scanfn);				\
	_wrap->shrink.shrink = kc_shrink_wrapper_fn;		\
	_wrap->shrink.seeks = DEFAULT_SEEKS;			\
} while (0)
#define KC_SHRINKER_CONTAINER_OF(ptr, type) container_of(container_of(ptr, struct kc_shrinker_wrapper, shrink), type, shrinker)
#define KC_REGISTER_SHRINKER(ptr) (register_shrinker(ptr.shrink))
#define KC_UNREGISTER_SHRINKER(ptr) (unregister_shrinker(ptr.shrink))
#define KC_SHRINKER_FN(ptr) (ptr.shrink)

#endif /* KC_SHRINKER_SHRINK */

#ifdef KC_KERNEL_GETSOCKNAME_ADDRLEN
#include <linux/net.h>
#include <linux/inet.h>
static inline int kc_kernel_getsockname(struct socket *sock, struct sockaddr *addr)
{
	int addrlen = sizeof(struct sockaddr_in);
	int ret = kernel_getsockname(sock, addr, &addrlen);
	if (ret == 0 && addrlen != sizeof(struct sockaddr_in))
		return -EAFNOSUPPORT;
	else if (ret < 0)
		return ret;

	return sizeof(struct sockaddr_in);
}
static inline int kc_kernel_getpeername(struct socket *sock, struct sockaddr *addr)
{
	int addrlen = sizeof(struct sockaddr_in);
	int ret = kernel_getpeername(sock, addr, &addrlen);
	if (ret == 0 && addrlen != sizeof(struct sockaddr_in))
		return -EAFNOSUPPORT;
	else if (ret < 0)
		return ret;

	return sizeof(struct sockaddr_in);
}
#else
#define kc_kernel_getsockname(sock, addr) kernel_getsockname(sock, addr)
#define kc_kernel_getpeername(sock, addr) kernel_getpeername(sock, addr)
#endif

#ifdef KC_SOCK_CREATE_KERN_NET
#define kc_sock_create_kern(family, type, proto, res) sock_create_kern(&init_net, family, type, proto, res)
#else
#define kc_sock_create_kern sock_create_kern
#endif

#endif
