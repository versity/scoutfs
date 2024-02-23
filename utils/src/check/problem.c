#include <stdio.h>
#include <stdint.h>

#include "problem.h"

#if 0
#define PROB_STR(pb) [pb] = #pb
static char *prob_strs[] = {
	PROB_STR(PB_META_EXTENT_INVALID),
	PROB_STR(PB_META_EXTENT_OVERLAPS_EXISTING),
};
#endif

static struct problem_data {
	uint64_t counts[PB__NR];
} global_pdat;

void problem_record(prob_t pb)
{
	struct problem_data *pdat = &global_pdat;

	pdat->counts[pb]++;
}
