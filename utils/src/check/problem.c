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
	PROB_STR(PB_SB_HDR_MAGIC_INVALID),
	PROB_STR(PB_FS_IN_USE),
	PROB_STR(PB_MOUNTED_CLIENTS_REF_BLKNO),
	PROB_STR(PB_SB_BAD_FLAG),
	PROB_STR(PB_SB_BAD_FMT_VERS),
	PROB_STR(PB_QCONF_WRONG_VERSION),
	PROB_STR(PB_QSLOT_BAD_ADDR),
	PROB_STR(PB_DATA_DEV_SB_INVALID),
};

static struct problem_data {
	uint64_t counts[PB__NR];
	uint64_t count;
	uint64_t corrected_counts[PB__NR];
	uint64_t corrected_count;
} global_pdat;

void problem_record(prob_t pb)
{
	struct problem_data *pdat = &global_pdat;

	pdat->counts[pb]++;
	pdat->count++;
}

void problem_corrected_record(prob_t pb)
{
	struct problem_data *pdat = &global_pdat;

	pdat->corrected_counts[pb]++;
	pdat->corrected_count++;
}

uint64_t problems_count(void)
{
	struct problem_data *pdat = &global_pdat;

	return pdat->count;
}

uint64_t problems_corrected_count(void)
{
	struct problem_data *pdat = &global_pdat;

	return pdat->corrected_count;
}
