
#include <linux/uio.h>

#include "kernelcompat.h"

#include <linux/list_lru.h>

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
