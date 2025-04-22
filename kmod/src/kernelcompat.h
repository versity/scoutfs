#ifndef _SCOUTFS_KERNELCOMPAT_H_
#define _SCOUTFS_KERNELCOMPAT_H_

#include <linux/kernel.h>
#include <linux/fs.h>

#ifdef KC_SHRINKER_ALLOC
// el10+

#define KC_DEFINE_SHRINKER(name) struct shrinker *(name)
#define KC_SHRINKER_CONTAINER_OF(ptr, type) ptr->private_data
#define KC_SETUP_SHRINKER(ptr, priv, flags, countfn, scanfn, fmt, args)	\
do {								\
	ptr = shrinker_alloc(flags, fmt, args);			\
	if (ptr) {						\
		ptr->private_data = (priv);			\
		ptr->seeks = DEFAULT_SEEKS;			\
		ptr->count_objects = countfn;			\
		ptr->scan_objects = scanfn;			\
		shrinker_register(ptr);				\
	}							\
} while (0)
#define KC_UNREGISTER_SHRINKER(ptr) shrinker_free(ptr)
#define KC_SHRINKER_FN(ptr) (ptr)
#define KC_SHRINKER_IS_NULL(ptr) (!(ptr))

#else /* KC_SHRINKER_ALLOC */
// el9, el8

#define KC_DEFINE_SHRINKER(name) struct shrinker (name)
#define KC_SHRINKER_CONTAINER_OF(ptr, type) container_of(ptr, type, shrinker)
#ifdef KC_SHRINKER_NAME
#define KC_SETUP_SHRINKER(ptr, priv, flags, countfn, scanfn, fmt, args)	\
do {								\
	(ptr).count_objects = (countfn);			\
	(ptr).scan_objects = (scanfn);				\
	(ptr).seeks = DEFAULT_SEEKS;				\
	register_shrinker(&(ptr), fmt, args);			\
} while (0)
#else
#define KC_SETUP_SHRINKER(ptr, priv, flags, countfn, scanfn, fmt, args)	\
do {								\
	(ptr).count_objects = (countfn);			\
	(ptr).scan_objects = (scanfn);				\
	(ptr).seeks = DEFAULT_SEEKS;				\
	register_shrinker(&(ptr));				\
} while (0)
#endif /* KC_SHRINKER_NAME */
#define KC_UNREGISTER_SHRINKER(ptr) (unregister_shrinker(&(ptr)))
#define KC_SHRINKER_FN(ptr) (&ptr)
#define KC_SHRINKER_IS_NULL(ptr) (0)

#endif /* KC_SHRINKER_ALLOC */

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
		b->bi_opf = opf;
		bio_set_dev(b, bdev);
	}
	return b;
}
#endif

#ifndef KC_FIEMAP_PREP
#define fiemap_prep(inode, fieinfo, start, len, flags) fiemap_check_flags(fieinfo, flags)
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

#include <linux/list_lru.h>

#ifndef KC_LIST_LRU_ADD_OBJ
#define list_lru_add_obj list_lru_add
#define list_lru_del_obj list_lru_del
#endif

#if defined(KC_LIST_LRU_WALK_CB_LIST_LOCK)
struct list_lru_one;
typedef enum lru_status (*kc_list_lru_walk_cb_t)(struct list_head *item, struct list_lru_one *list,
						 void *cb_arg);
struct kc_isolate_args {
	kc_list_lru_walk_cb_t isolate;
	void *cb_arg;
};
unsigned long kc_list_lru_walk(struct list_lru *lru, kc_list_lru_walk_cb_t isolate, void *cb_arg,
			       unsigned long nr_to_walk);
unsigned long kc_list_lru_shrink_walk(struct list_lru *lru, struct shrink_control *sc,
				      kc_list_lru_walk_cb_t isolate, void *cb_arg);
#else
#define kc_list_lru_shrink_walk list_lru_shrink_walk
#endif

#ifndef KC_HAVE_GET_RANDOM_U32_BELOW
#define get_random_u32_below prandom_u32_max
#endif

#ifndef KC_FS_INODE_C_TIME_ACCESSOR
struct timespec64 inode_set_ctime_current(struct inode *inode);
static inline struct timespec64 inode_set_ctime_to_ts(struct inode *inode,
						      struct timespec64 ts)
{
	inode->i_ctime.tv_sec = ts.tv_sec;
	inode->i_ctime.tv_nsec = ts.tv_nsec;
	return ts;
}

static inline struct timespec64 inode_set_ctime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };

	return inode_set_ctime_to_ts(inode, ts);
}

static inline struct timespec64 inode_get_ctime(const struct inode *inode)
{
	struct timespec64 ts = { .tv_sec  = inode->i_ctime.tv_sec,
				 .tv_nsec = inode->i_ctime.tv_nsec };
	return ts;
}
#endif

#ifndef KC_FS_INODE_AM_TIME_ACCESSOR
static inline struct timespec64 inode_get_mtime(const struct inode *inode)
{
	struct timespec64 ts = { .tv_sec  = inode->i_mtime.tv_sec,
				 .tv_nsec = inode->i_mtime.tv_nsec };
	return ts;
}

static inline struct timespec64 inode_set_mtime_to_ts(struct inode *inode,
						      struct timespec64 ts)
{
	inode->i_mtime.tv_sec = ts.tv_sec;
	inode->i_mtime.tv_nsec = ts.tv_nsec;
	return ts;
}

static inline struct timespec64 inode_set_mtime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };

	return inode_set_mtime_to_ts(inode, ts);
}

static inline struct timespec64 inode_set_atime_to_ts(struct inode *inode,
						      struct timespec64 ts)
{
	inode->i_atime.tv_sec = ts.tv_sec;
	inode->i_atime.tv_nsec = ts.tv_nsec;
	return ts;
}

static inline struct timespec64 inode_set_atime(struct inode *inode,
						time64_t sec, long nsec)
{
	struct timespec64 ts = { .tv_sec  = sec,
				 .tv_nsec = nsec };

	return inode_set_atime_to_ts(inode, ts);
}

static inline time64_t inode_get_ctime_sec(const struct inode *inode)
{
	return inode->i_ctime.tv_sec;
}
static inline long inode_get_ctime_nsec(const struct inode *inode)
{
	return inode->i_ctime.tv_nsec;
}
static inline time64_t inode_get_mtime_sec(const struct inode *inode)
{
	return inode->i_mtime.tv_sec;
}
static inline long inode_get_mtime_nsec(const struct inode *inode)
{
	return inode->i_mtime.tv_nsec;
}
static inline time64_t inode_get_atime_sec(const struct inode *inode)
{
	return inode->i_atime.tv_sec;
}
static inline long inode_get_atime_nsec(const struct inode *inode)
{
	return inode->i_atime.tv_nsec;
}
#endif

#ifdef KC_HAVE_BD_INODE
#define KC_BDEV_INODE(b) (b)->bd_inode
#define KC_BDEV_MAPPING(b) (b)->bd_inode->i_mapping
#else
#define KC_BDEV_INODE(b) (b)->bd_mapping->host
#define KC_BDEV_MAPPING(b) (b)->bd_mapping
#endif

#ifdef KC_HAVE_ASSIGN_STR_PARMS
#define kc__assign_str(a, b) __assign_str(a, b)
#else
#define kc__assign_str(a, b) __assign_str(a)
#endif

#ifndef KC_TIMER_CONTAINER_OF
#define timer_container_of(var, callback_timer, timer_fieldname) \
	from_timer(var, callback_timer, timer_fieldname)
#endif

#endif
