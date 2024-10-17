#ifndef _SCOUTFS_UTILS_CHECK_ITER_H_
#define _SCOUTFS_UTILS_CHECK_ITER_H_

/*
 * Callbacks can return a weird -errno that we'll never use to indicate
 * that iteration can stop and return 0 for success.
 */
#define ECHECK_ITER_DONE EL2HLT

static inline int xlate_iter_errno(int ret)
{
	return ret == -ECHECK_ITER_DONE ? 0 : ret;
}

#endif
