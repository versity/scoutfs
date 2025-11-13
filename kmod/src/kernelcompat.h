#ifndef _SCOUTFS_KERNELCOMPAT_H_
#define _SCOUTFS_KERNELCOMPAT_H_

#include <linux/kernel.h>
#include <linux/fs.h>

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

#include <linux/list_lru.h>

#ifndef KC_LIST_LRU_SHRINK_COUNT_WALK
/* we don't bother with sc->{nid,memcg} (which doesn't exist in oldest kernels) */
static inline unsigned long list_lru_shrink_count(struct list_lru *lru,
                                                  struct shrink_control *sc)
{
        return list_lru_count(lru);
}
static inline unsigned long
list_lru_shrink_walk(struct list_lru *lru, struct shrink_control *sc,
		     list_lru_walk_cb isolate, void *cb_arg)
{
	return list_lru_walk(lru, isolate, cb_arg, sc->nr_to_scan);
}
#endif

#ifndef KC_LIST_LRU_ADD_OBJ
#define list_lru_add_obj list_lru_add
#define list_lru_del_obj list_lru_del
#endif

#if defined(KC_LIST_LRU_WALK_CB_LIST_LOCK) || defined(KC_LIST_LRU_WALK_CB_ITEM_LOCK)
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

#if defined(KC_LIST_LRU_WALK_CB_ITEM_LOCK)
/* isolate moved by hand, nr_items updated in walk as _REMOVE returned */
static inline void list_lru_isolate_move(struct list_lru_one *list, struct list_head *item,
					 struct list_head *head)
{
        list_move(item, head);
}
#endif

#ifndef KC_STACK_TRACE_SAVE
#include <linux/stacktrace.h>
static inline unsigned int stack_trace_save(unsigned long *store, unsigned int size,
					    unsigned int skipnr)
{
        struct stack_trace trace = {
                .entries        = store,
                .max_entries    = size,
                .skip           = skipnr,
        };

        save_stack_trace(&trace);
        return trace.nr_entries;
}

static inline void stack_trace_print(unsigned long *entries, unsigned int nr_entries, int spaces)
{
        struct stack_trace trace = {
                .entries        = entries,
                .nr_entries     = nr_entries,
        };

	print_stack_trace(&trace, spaces);
}
#endif

#ifndef KC_TIMER_CONTAINER_OF
#define timer_container_of(var, callback_timer, timer_fieldname) \
	from_timer(var, callback_timer, timer_fieldname)
#endif

#endif
