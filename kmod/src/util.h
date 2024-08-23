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
static inline long shrinker_min_long(long count)
{
	return min(count, LONG_MAX);
}


/*
 * We've tried to make a generic (off, len) overflow type detection
 * macro but we can't easily automatically convert a signed integer
 * like loff_t to get the unsigned _type max positive value in a macro,
 * since (unsigned)__typeof__(var) doesn't work (it always makes an int)
 *
 * So we're stuck making per-type wrap detection macros like this until
 * we find a better solution
 */
#define loff_t_region_wraps(off, len)					\
({									\
	__typeof__(off) _max = LLONG_MAX;				\
	bool _wrap;							\
									\
	BUILD_BUG_ON(sizeof(__typeof__(len)) != 8);			\
	BUILD_BUG_ON(sizeof(__typeof__(off)) != 8);			\
									\
	if (len < 0) {							\
		_wrap = true;						\
	} else if (len <= 1) {						\
		_wrap = false;						\
	} else  {							\
		_wrap = (_max - off) < (len - 1);			\
	}								\
									\
	_wrap;								\
})

#define u64_region_wraps(off, len)					\
({									\
	__typeof__(off) _max = ULLONG_MAX;				\
	bool _wrap;							\
									\
	BUILD_BUG_ON(sizeof(__typeof__(len)) != 8);			\
	BUILD_BUG_ON(sizeof(__typeof__(off)) != 8);			\
									\
	if (len <= 1) {					\
		_wrap = false;						\
	} else  {							\
		_wrap = (_max - off) < (len - 1);			\
	}								\
									\
	_wrap;								\
})

#endif
