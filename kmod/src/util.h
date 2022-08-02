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

/*
 * When returning shrinker counts from scan_objects, we should steer
 * clear of the magic SHRINK_STOP and SHRINK_EMPTY values, which are near
 * ~0UL values. Hence, we cap count to ~0L, which is arbitarily high
 * enough to avoid it.
 */
static inline unsigned long shrinker_min_t_long(unsigned long count)
{
	return min_t(u64, count, LONG_MAX);
}

#endif
