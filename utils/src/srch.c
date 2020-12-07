#include <errno.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "srch.h"

/* shifting by width is undefined :/ */
#define BYTE_MASK(b) ((1ULL << (b << 3)) - 1)
static u64 byte_masks[] = {
	0, BYTE_MASK(1), BYTE_MASK(2), BYTE_MASK(3),
	BYTE_MASK(4), BYTE_MASK(5), BYTE_MASK(6), BYTE_MASK(7), U64_MAX,
};

static u64 decode_u64(void *buf, int bytes)
{
	u64 val = get_unaligned_le64(buf) & byte_masks[bytes];

	return (val >> 1) ^ (-(val & 1));
}

int srch_decode_entry(void *buf, struct scoutfs_srch_entry *sre,
		      struct scoutfs_srch_entry *prev)
{
	u64 diffs[3];
	u16 lengths;
	int bytes;
	int tot;
	int i;

	lengths = get_unaligned_le16(buf);
	tot = 2;

	for (i = 0; i < array_size(diffs); i++) {
		bytes = min(8, lengths & 15);
		diffs[i] = decode_u64(buf + tot, bytes);
		tot += bytes;
		lengths >>= 4;
	}

	sre->hash = cpu_to_le64(le64_to_cpu(prev->hash) + diffs[0]);
	sre->ino = cpu_to_le64(le64_to_cpu(prev->ino) + diffs[1]);
	sre->id = cpu_to_le64(le64_to_cpu(prev->id) + diffs[2]);

	return tot;
}
