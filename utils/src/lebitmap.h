#ifndef _LEBITMAP_H_
#define _LEBITMAP_H_

#include "sparse.h"

void set_le_bit(__le64 *bits, u64 nr);
void clear_le_bit(__le64 *bits, u64 nr);
int test_le_bit(__le64 *bits, u64 nr);
s64 find_first_le_bit(__le64 *bits, s64 count);

#endif
