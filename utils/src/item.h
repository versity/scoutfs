#ifndef _ITEM_H_
#define _ITEM_H_

/*
 * The persistent item fields that are stored in the segment are packed
 * with funny precision.  We translate those to and from a much more
 * natural native representation of the fields.
 */
struct native_item {
	u64 seq;
	u32 key_off;
	u32 val_off;
	u16 key_len;
	u16 val_len;
};

void load_item(struct scoutfs_segment_block *sblk, u32 pos,
	       struct native_item *item);
void store_item(struct scoutfs_segment_block *sblk, u32 pos,
	        struct native_item *item);

#endif
