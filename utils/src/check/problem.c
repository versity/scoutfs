#include <stdio.h>
#include <stdint.h>

#include "problem.h"

#define PROB_STR(pb) [pb] = #pb
char *prob_strs[] = {
	PROB_STR(PB_META_EXTENT_INVALID),
	PROB_STR(PB_META_REF_OVERLAPS_EXISTING),
	PROB_STR(PB_META_FREE_OVERLAPS_EXISTING),
	PROB_STR(PB_BTREE_BLOCK_BAD_LEVEL),
	PROB_STR(PB_SB_HDR_CRC_INVALID),
};

static struct problem_data {
	uint64_t counts[PB__NR];
	uint64_t count;
} global_pdat;

void problem_record(prob_t pb)
{
	struct problem_data *pdat = &global_pdat;

	pdat->counts[pb]++;
	pdat->count++;
}

uint64_t problems_count(void)
{
	struct problem_data *pdat = &global_pdat;

	return pdat->count;
}
