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

#ifndef KC_CURRENT_TIME_INODE
struct timespec64 kc_current_time(struct inode *inode);
#define current_time kc_current_time
#define kc_timespec timespec
#else
#define kc_timespec timespec64
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
#ifdef KC_SHRINKER_NAME
#define KC_REGISTER_SHRINKER register_shrinker
#else
#define KC_REGISTER_SHRINKER(ptr, fmt, ...) (register_shrinker(ptr))
#endif /* KC_SHRINKER_NAME */
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
#define KC_REGISTER_SHRINKER(ptr, fmt, ...) (register_shrinker(ptr.shrink))
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

#ifndef KC_GENERIC_FILE_BUFFERED_WRITE
ssize_t kc_generic_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
               unsigned long nr_segs, loff_t pos, loff_t *ppos,
               size_t count, ssize_t written);
#define generic_file_buffered_write kc_generic_file_buffered_write
#ifdef KC_GENERIC_PERFORM_WRITE_KIOCB_IOV_ITER
static inline int kc_generic_perform_write(struct kiocb *iocb, struct iov_iter *iter, loff_t pos)
{
	iocb->ki_pos = pos;
	return generic_perform_write(iocb, iter);
}
#else
static inline int kc_generic_perform_write(struct kiocb *iocb, struct iov_iter *iter, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	return generic_perform_write(file, iter, pos);
}
#endif
#endif // KC_GENERIC_FILE_BUFFERED_WRITE

#ifndef KC_HAVE_BLK_OPF_T
/* typedef __u32 __bitwise blk_opf_t; */
typedef unsigned int blk_opf_t;
#endif

#ifdef KC_LIST_CMP_CONST_ARG_LIST_HEAD
#define KC_LIST_CMP_CONST const
#else
#define KC_LIST_CMP_CONST
#endif

#ifdef KC_VMALLOC_PGPROT_T
#define kc__vmalloc(size, gfp_mask) __vmalloc(size, gfp_mask, PAGE_KERNEL)
#else
#define kc__vmalloc __vmalloc
#endif

#ifdef KC_VFS_METHOD_MNT_IDMAP_ARG
#define KC_VFS_NS_DEF struct mnt_idmap *mnt_idmap,
#define KC_VFS_NS mnt_idmap,
#define KC_VFS_INIT_NS &nop_mnt_idmap,
#else
#ifdef KC_VFS_METHOD_USER_NAMESPACE_ARG
#define KC_VFS_NS_DEF struct user_namespace *mnt_user_ns,
#define KC_VFS_NS mnt_user_ns,
#define KC_VFS_INIT_NS &init_user_ns,
#else
#define KC_VFS_NS_DEF
#define KC_VFS_NS
#define KC_VFS_INIT_NS
#endif
#endif /* KC_VFS_METHOD_MNT_IDMAP_ARG */

#ifdef KC_BIO_ALLOC_DEV_OPF_ARGS
#define kc_bio_alloc bio_alloc
#else
#include <linux/bio.h>
static inline struct bio *kc_bio_alloc(struct block_device *bdev, unsigned short nr_vecs,
				       blk_opf_t opf, gfp_t gfp_mask)
{
	struct bio *b = bio_alloc(gfp_mask, nr_vecs);
	if (b) {
		kc_bio_set_opf(b, opf);
		bio_set_dev(b, bdev);
	}
	return b;
}
#endif

#ifndef KC_FIEMAP_PREP
#define fiemap_prep(inode, fieinfo, start, len, flags) fiemap_check_flags(fieinfo, flags)
#endif

#ifndef KC_KERNEL_OLD_TIMEVAL_STRUCT
#define __kernel_old_timeval timeval
#define ns_to_kernel_old_timeval(ktime) ns_to_timeval(ktime.tv64)
#endif

#ifdef KC_SOCK_SET_SNDTIMEO
#include <net/sock.h>
static inline int kc_sock_set_sndtimeo(struct socket *sock, s64 secs)
{
	sock_set_sndtimeo(sock->sk, secs);
	return 0;
}
static inline int kc_tcp_sock_set_rcvtimeo(struct socket *sock, ktime_t to)
{
	struct __kernel_old_timeval tv;
	sockptr_t kopt;

	tv = ns_to_kernel_old_timeval(to);

	kopt = KERNEL_SOCKPTR(&tv);

	return sock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_NEW,
			       kopt, sizeof(tv));
}
#else
#include <net/sock.h>
static inline int kc_sock_set_sndtimeo(struct socket *sock, s64 secs)
{
	struct timeval tv = { .tv_sec = secs, .tv_usec = 0 };
	return kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
				 (char *)&tv, sizeof(tv));
}
static inline int kc_tcp_sock_set_rcvtimeo(struct socket *sock, ktime_t to)
{
	struct __kernel_old_timeval tv;

	tv = ns_to_kernel_old_timeval(to);
	return kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
				 (char *)&tv, sizeof(tv));
}
#endif

#ifdef KC_SETSOCKOPT_SOCKPTR_T
static inline int kc_sock_setsockopt(struct socket *sock, int level, int op, int *optval, unsigned int optlen)
{
	sockptr_t kopt = KERNEL_SOCKPTR(optval);
	return sock_setsockopt(sock, level, op, kopt, sizeof(optval));
}
#else
static inline int kc_sock_setsockopt(struct socket *sock, int level, int op, int *optval, unsigned int optlen)
{
	return kernel_setsockopt(sock, level, op, (char *)optval, sizeof(optval));
}
#endif

#ifdef KC_HAVE_TCP_SET_SOCKFN
#include <linux/net.h>
#include <net/tcp.h>
static inline int kc_tcp_sock_set_keepintvl(struct socket *sock, int val)
{
	return tcp_sock_set_keepintvl(sock->sk, val);
}
static inline int kc_tcp_sock_set_keepidle(struct socket *sock, int val)
{
	return tcp_sock_set_keepidle(sock->sk, val);
}
static inline int kc_tcp_sock_set_user_timeout(struct socket *sock, int val)
{
	tcp_sock_set_user_timeout(sock->sk, val);
	return 0;
}
static inline int kc_tcp_sock_set_nodelay(struct socket *sock)
{
	tcp_sock_set_nodelay(sock->sk);
	return 0;
}
#else
#include <linux/net.h>
#include <net/tcp.h>
static inline int kc_tcp_sock_set_keepintvl(struct socket *sock, int val)
{
	int optval = val;
	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (char *)&optval, sizeof(optval));
}
static inline int kc_tcp_sock_set_keepidle(struct socket *sock, int val)
{
	int optval = val;
	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (char *)&optval, sizeof(optval));
}
static inline int kc_tcp_sock_set_user_timeout(struct socket *sock, int val)
{
	int optval = val;
	return kernel_setsockopt(sock, SOL_TCP, TCP_USER_TIMEOUT, (char *)&optval, sizeof(optval));
}
static inline int kc_tcp_sock_set_nodelay(struct socket *sock)
{
	int optval = 1;
	return kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
}
#endif

#ifdef KC_INODE_DIO_END
#define kc_inode_dio_end inode_dio_end
#else
#define kc_inode_dio_end inode_dio_done
#endif

#ifndef KC_MM_VM_FAULT_T
typedef unsigned int vm_fault_t;
static inline vm_fault_t vmf_error(int err)
{
	if (err == -ENOMEM)
		return VM_FAULT_OOM;
	return VM_FAULT_SIGBUS;
}
#endif

#endif
