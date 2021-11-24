#ifndef _QUORUM_H_
#define _QUORUM_H_

#include <stdbool.h>

bool quorum_slot_present(struct scoutfs_super_block *super, int i);
bool valid_quorum_slots(struct scoutfs_quorum_slot *slots);
void print_quorum_slots(struct scoutfs_quorum_slot *slots, int nr, char *indent);

#endif
