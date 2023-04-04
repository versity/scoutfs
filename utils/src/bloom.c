#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "hash.h"
#include "bloom.h"

void calc_bloom_nrs(struct scoutfs_key *key, unsigned int *nrs)
{
	u64 hash;
	int i;

	hash = scoutfs_hash64(key, sizeof(struct scoutfs_key));

	for (i = 0; i < SCOUTFS_FOREST_BLOOM_NRS; i++) {
		nrs[i] = (u32)hash % SCOUTFS_FOREST_BLOOM_BITS;
		hash >>= SCOUTFS_FOREST_BLOOM_FUNC_BITS;
	}
}
