
#include <linux/uio.h>

#include "kernelcompat.h"


#ifndef KC_CURRENT_TIME_INODE
struct timespec64 kc_current_time(struct inode *inode)
{
	struct timespec64 now;
	unsigned gran;

	getnstimeofday64(&now);

	if (unlikely(!inode->i_sb)) {
		WARN(1, "current_time() called with uninitialized super_block in the inode");
		return now;
	}

	gran = inode->i_sb->s_time_gran;

	/* Avoid division in the common cases 1 ns and 1 s. */
	if (gran == 1) {
		/* nothing */
	} else if (gran == NSEC_PER_SEC) {
		now.tv_nsec = 0;
	} else if (gran > 1 && gran < NSEC_PER_SEC) {
		now.tv_nsec -= now.tv_nsec % gran;
	} else {
		WARN(1, "illegal file time granularity: %u", gran);
	}

	return now;
}
#endif

#ifndef KC_GENERIC_FILE_BUFFERED_WRITE
ssize_t
kc_generic_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
			       unsigned long nr_segs, loff_t pos, loff_t *ppos,
			       size_t count, ssize_t written)
{
	ssize_t status;
	struct iov_iter i;

	iov_iter_init(&i, WRITE, iov, nr_segs, count);
	status = kc_generic_perform_write(iocb, &i, pos);

	if (likely(status >= 0)) {
		written += status;
		*ppos = pos + status;
	}

	return written ? written : status;
}
#endif

#include <linux/list_lru.h>

#ifdef KC_LIST_LRU_WALK_CB_ITEM_LOCK
static enum lru_status kc_isolate(struct list_head *item, spinlock_t *lock, void *cb_arg)
{
	struct kc_isolate_args *args = cb_arg;

	/* isolate doesn't use list, nr_items updated in caller */
	return args->isolate(item, NULL, args->cb_arg);
}

unsigned long kc_list_lru_walk(struct list_lru *lru, kc_list_lru_walk_cb_t isolate, void *cb_arg,
				      unsigned long nr_to_walk)
{
	struct kc_isolate_args args = {
		.isolate = isolate,
		.cb_arg = cb_arg,
	};

	return list_lru_walk(lru, kc_isolate, &args, nr_to_walk);
}

unsigned long kc_list_lru_shrink_walk(struct list_lru *lru, struct shrink_control *sc,
				      kc_list_lru_walk_cb_t isolate, void *cb_arg)
{
	struct kc_isolate_args args = {
		.isolate = isolate,
		.cb_arg = cb_arg,
	};

	return list_lru_shrink_walk(lru, sc, kc_isolate, &args);
}
#endif

#ifdef KC_LIST_LRU_WALK_CB_LIST_LOCK
static enum lru_status kc_isolate(struct list_head *item, struct list_lru_one *list,
				  spinlock_t *lock, void *cb_arg)
{
	struct kc_isolate_args *args = cb_arg;

	return args->isolate(item, list, args->cb_arg);
}

unsigned long kc_list_lru_walk(struct list_lru *lru, kc_list_lru_walk_cb_t isolate, void *cb_arg,
				      unsigned long nr_to_walk)
{
	struct kc_isolate_args args = {
		.isolate = isolate,
		.cb_arg = cb_arg,
	};

	return list_lru_walk(lru, kc_isolate, &args, nr_to_walk);
}
unsigned long kc_list_lru_shrink_walk(struct list_lru *lru, struct shrink_control *sc,
				      kc_list_lru_walk_cb_t isolate, void *cb_arg)
{
	struct kc_isolate_args args = {
		.isolate = isolate,
		.cb_arg = cb_arg,
	};

	return list_lru_shrink_walk(lru, sc, kc_isolate, &args);
}

#endif
