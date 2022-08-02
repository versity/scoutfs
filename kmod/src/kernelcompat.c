
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
