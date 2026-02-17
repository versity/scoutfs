#ifndef _SCOUTFS_BSEARCH_INDEX_H_
#define _SCOUTFS_BSEARCH_INDEX_H_

size_t bsearch_index(const void *key, const void *base, size_t num, size_t size,
		     int (*cmp)(const void *key, const void *elt));

#endif
