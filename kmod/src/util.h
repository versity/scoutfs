#ifndef _SCOUTFS_UTIL_H_
#define _SCOUTFS_UTIL_H_

/*
 * Little utility helpers that probably belong upstream.
 */

static inline void down_write_two(struct rw_semaphore *a,
				  struct rw_semaphore *b)
{
	BUG_ON(a == b);

	if (a > b)
		swap(a, b);

	down_write(a);
	down_write_nested(b, SINGLE_DEPTH_NESTING);
}

#endif
