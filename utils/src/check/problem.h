#ifndef _SCOUTFS_UTILS_CHECK_PROBLEM_H_
#define _SCOUTFS_UTILS_CHECK_PROBLEM_H_

#include "debug.h"
#include "sns.h"

typedef enum {
	PB_META_EXTENT_INVALID,
	PB_META_REF_OVERLAPS_EXISTING,
	PB_META_FREE_OVERLAPS_EXISTING,
	PB_BTREE_BLOCK_BAD_LEVEL,
	PB__NR,
} prob_t;

#define problem(pb, fmt, ...)							\
do {										\
	debug("problem found: "#pb": %s: "fmt, sns_str(), __VA_ARGS__);	\
	problem_record(pb);							\
} while (0)

void problem_record(prob_t pb);

#endif
