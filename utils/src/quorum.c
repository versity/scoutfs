#include "sparse.h"
#include "util.h"
#include "format.h"

#include "quorum.h"

bool quorum_slot_present(struct scoutfs_super_block *super, int i)
{
	return super->qconf.slots[i].addr.v4.family == cpu_to_le16(SCOUTFS_AF_IPV4);
}
