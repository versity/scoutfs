#ifndef _SCOUTFS_UTILS_CHECK_PROBLEM_H_
#define _SCOUTFS_UTILS_CHECK_PROBLEM_H_

#include "debug.h"
#include "sns.h"

typedef enum {
	PB_META_EXTENT_INVALID,
	PB_META_REF_OVERLAPS_EXISTING,
	PB_META_FREE_OVERLAPS_EXISTING,
	PB_BTREE_BLOCK_BAD_LEVEL,
	PB_SB_HDR_CRC_INVALID,
	PB_SB_HDR_MAGIC_INVALID,
	PB_FS_IN_USE,
	PB_MOUNTED_CLIENTS_REF_BLKNO,
	PB_SB_BAD_FLAG,
	PB_QCONF_WRONG_VERSION,
	PB_QSLOT_BAD_FAM,
	PB_QSLOT_BAD_PORT,
	PB_QSLOT_NO_ADDR,
	PB_QSLOT_BAD_ADDR,
	PB__NR,
} prob_t;

extern char *prob_strs[];

#define problem(pb, fmt, ...)							\
do {										\
	debug("problem found: "#pb": %s: "fmt, sns_str(), __VA_ARGS__);	\
	problem_record(pb);							\
} while (0)

void problem_record(prob_t pb);
uint64_t problems_count(void);

#endif
