#include <unistd.h>
#include <stdlib.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "item.h"

/* utils uses bit contiguous allocations */
static void *off_ptr(struct scoutfs_segment_block *sblk, u32 off)
{
	return (char *)sblk + off;
}

static u32 pos_off(struct scoutfs_segment_block *sblk, u32 pos)
{
	return offsetof(struct scoutfs_segment_block, items[pos]);
}

static void *pos_ptr(struct scoutfs_segment_block *sblk, u32 pos)
{
	return off_ptr(sblk, pos_off(sblk, pos));
}

void load_item(struct scoutfs_segment_block *sblk, u32 pos,
	       struct native_item *item)
{
	struct scoutfs_segment_item *sitem = pos_ptr(sblk, pos);
	u32 packed;

	item->seq = le64_to_cpu(sitem->seq);

	packed = le32_to_cpu(sitem->key_off_len);
	item->key_off = packed >> SCOUTFS_SEGMENT_ITEM_OFF_SHIFT;
	item->key_len = packed & SCOUTFS_SEGMENT_ITEM_LEN_MASK;

	packed = le32_to_cpu(sitem->val_off_len);
	item->val_off = packed >> SCOUTFS_SEGMENT_ITEM_OFF_SHIFT;
	item->val_len = packed & SCOUTFS_SEGMENT_ITEM_LEN_MASK;
}

void store_item(struct scoutfs_segment_block *sblk, u32 pos,
	        struct native_item *item)
{
	struct scoutfs_segment_item *sitem = pos_ptr(sblk, pos);
	u32 packed;

	sitem->seq = cpu_to_le64(item->seq);

	packed = (item->key_off << SCOUTFS_SEGMENT_ITEM_OFF_SHIFT) |
		 (item->key_len & SCOUTFS_SEGMENT_ITEM_LEN_MASK);
	sitem->key_off_len = cpu_to_le32(packed);

	packed = (item->val_off << SCOUTFS_SEGMENT_ITEM_OFF_SHIFT) |
		 (item->val_len & SCOUTFS_SEGMENT_ITEM_LEN_MASK);
	sitem->val_off_len = cpu_to_le32(packed);
}
