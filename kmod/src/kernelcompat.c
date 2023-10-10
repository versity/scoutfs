
#include <linux/uio.h>

#include "kernelcompat.h"

#ifdef KC_SHRINKER_SHRINK
#include <linux/shrinker.h>
/*
 * If a target doesn't have that .{count,scan}_objects() interface then
 * we have a .shrink() helper that performs the shrink work in terms of
 * count/scan.
 */
int kc_shrink_wrapper_fn(struct shrinker *shrink, struct shrink_control *sc)
{
	struct kc_shrinker_wrapper *wrapper = container_of(shrink, struct kc_shrinker_wrapper, shrink);
	unsigned long nr;
	unsigned long rc;

	if (sc->nr_to_scan != 0) {
		rc = wrapper->scan_objects(shrink, sc);
		/* translate magic values to the equivalent for older kernels */
		if (rc == SHRINK_STOP)
			return -1;
		else if (rc == SHRINK_EMPTY)
			return 0;
	}

	nr = wrapper->count_objects(shrink, sc);

	return min_t(unsigned long, nr, INT_MAX);
}
#endif

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
	struct file *file = iocb->ki_filp;
	ssize_t status;
	struct iov_iter i;

	iov_iter_init(&i, WRITE, iov, nr_segs, count);
	status = generic_perform_write(file, &i, pos);

	if (likely(status >= 0)) {
		written += status;
		*ppos = pos + status;
	}

	return written ? written : status;
}
#endif
