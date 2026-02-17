/*
 * Copyright (C) 2026 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/bsearch.h>

#include "bsearch_index.h"

struct bsearch_index_key {
	int (*cmp)(const void *key, const void *elt);
	/* the key has to be const, so we have to update the index through a pointer */
	void **index_elt;
	const void *key;
	size_t size;
};

static int cmp_index(const void *key, const void *elt)
{
	const struct bsearch_index_key *bik = key;
	int cmp = bik->cmp(bik->key, elt);

	if (cmp > 0)
		*(bik->index_elt) = (void *)elt + bik->size;
	else
		*(bik->index_elt) = (void *)elt;

	return cmp;
}

/*
 * A bsearch() wrapper that returns the index of the element of the
 * array that the key would be stored in to maintain sort order.  It's
 * the first element where the existing element is greater than the key.
 * It returns the size of the array if the key is greater than the last
 * element in the array.
 */
size_t bsearch_index(const void *key, const void *base, size_t num, size_t size,
		     int (*cmp)(const void *key, const void *elt))
{
	void *index_elt = (void *)base;
	struct bsearch_index_key bik = {
		.cmp = cmp,
		.index_elt = &index_elt,
		.key = key,
		.size = size,
	};

	bsearch(&bik, base, num, size, cmp_index);
	return ((unsigned long)index_elt - (unsigned long)base) / size;
}
