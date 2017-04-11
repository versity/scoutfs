#ifndef _BITMAP_H_
#define _BITMAP_H_

void set_bit(unsigned long *bits, u64 nr);
void clear_bit(unsigned long *bits, u64 nr);
u64 find_next_set_bit(unsigned long *start, u64 from, u64 total);
unsigned long *alloc_bits(u64 max);

#endif
