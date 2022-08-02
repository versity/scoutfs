
#include "kernelcompat.h"

#ifdef KC_SHRINKER_SHRINK
#include <linux/shrinker.h>
/*
 * If a target doesn't have that .{count,scan}_objects() interface then
 * we have a .shrink() helper that performs the shrink work in terms of
 * count/scan.
 */
int kc_shrink_wrapper(struct shrinker *shrink, struct shrink_control *sc)
{
	struct kc_shrinker_funcs *funcs = KC_SHRINKER_FUNCS(shrink);
	unsigned long nr;

	if (sc->nr_to_scan != 0)
		funcs->scan_objects(shrink, sc);

	nr = funcs->count_objects(shrink, sc);

	return min_t(unsigned long, nr, INT_MAX);
}
#endif
