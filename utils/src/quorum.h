#ifndef _QUORUM_H_
#define _QUORUM_H_

#include <stdbool.h>

bool quorum_slot_present(struct scoutfs_super_block *super, int i);

#endif
