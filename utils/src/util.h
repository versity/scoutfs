#ifndef _UTIL_H_
#define _UTIL_H_

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "sparse.h"

/*
 * Generate build warnings if the condition is false but generate no
 * code at run time if it's true.
 */
#define build_assert(cond) ((void)sizeof(char[1 - 2*!(cond)]))

#define min(a, b) 		\
({				\
	__typeof__(a) _a = (a);	\
	__typeof__(b) _b = (b);	\
				\
	_a < _b ? _a : _b;	\
})

#define max(a, b) 		\
({				\
	__typeof__(a) _a = (a);	\
	__typeof__(b) _b = (b);	\
				\
	_a > _b ? _a : _b;	\
})

#define swap(a, b) 		\
do {				\
	__typeof__(a) _t = (a);	\
 	(a) = (b);		\
 	(b) = (_t);		\
} while (0)

#define array_size(arr) (sizeof(arr) / sizeof(arr[0]))

#define __packed __attribute__((packed))

/*
 * Round the 'a' value up to the next 'b' power of two boundary.  It
 * casts the mask to the value type before masking to avoid truncation
 * problems.
 */
#define round_up(a, b)			\
({					\
	__typeof__(a) _b = (b);		\
					\
	((a) + _b - 1) & ~(_b - 1);	\
})
#define round_down(a, b)		\
({					\
	__typeof__(a) _b = (b);		\
					\
	((a) & ~(_b - 1));		\
})

#define DIV_ROUND_UP(x, y)  (((x) + (y) - 1) / (y))
#define ALIGN(x, y)  (((x) + (y) - 1) & ~((y) - 1))

#ifndef offsetof
#define offsetof(type, memb) ((unsigned long)&((type *)0)->memb)
#endif

#define container_of(ptr, type, memb) \
	((type *)((void *)(ptr) - offsetof(type, memb)))

#define BITS_PER_LONG (sizeof(long) * 8)
#define U8_MAX ((u8)~0ULL)
#define U16_MAX ((u16)~0ULL)
#define U32_MAX ((u32)~0ULL)
#define U64_MAX ((u64)~0ULL)

#define flsll(x)					\
({							\
	unsigned long long _x = (x);			\
							\
	(_x == 0 ? 0 : 64 - __builtin_clzll(_x));	\
})
#define fls64(x) flsll(x)

#define ilog2(x)					\
({							\
	((unsigned long)log2l((long double)x));		\
})

#define emit_get_unaligned_le(nr)			\
static inline __u##nr get_unaligned_le##nr(void *buf)	\
{							\
	__le##nr x;					\
	memcpy(&x, buf, sizeof(x));			\
	return le##nr##_to_cpu(x);			\
}
emit_get_unaligned_le(16)
emit_get_unaligned_le(32)
emit_get_unaligned_le(64)

/*
 * return -1,0,+1 based on the memcmp comparison of the minimum of their
 * two lengths.  If their min shared bytes are equal but the lengths
 * are not then the larger length is considered greater.
 */
static inline int memcmp_lens(const void *a, int a_len,
			      const void *b, int b_len)
{
	unsigned int len = min(a_len, b_len);

	return memcmp(a, b, len) ?: a_len - b_len;
}

int get_path(char *path, int flags);
int read_block(int fd, u64 blkno, int shift, void **ret_val);
int read_block_crc(int fd, u64 blkno, int shift, void **ret_val);
int read_block_verify(int fd, u32 magic, u64 fsid, u64 blkno, int shift, void **ret_val);

struct scoutfs_block_header;
struct scoutfs_super_block;
int write_block(int fd, u32 magic, __le64 fsid, u64 seq, u64 blkno,
		int shift, struct scoutfs_block_header *hdr);
int write_block_sync(int fd, u32 magic, __le64 fsid, u64 seq, u64 blkno,
		     int shift, struct scoutfs_block_header *hdr);
int meta_super_in_use(int meta_fd, struct scoutfs_super_block *meta_super);

#define __stringify_1(x) #x
#define __stringify(x) __stringify_1(x)

#endif
