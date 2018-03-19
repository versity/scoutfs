#ifndef _SPARSE_H_
#define _SPARSE_H_

#include <endian.h>
#include <stdint.h>

#ifdef __CHECKER__
# undef __force
# define __force		__attribute__((force))
# undef __sp_biwise
# define __sp_biwise		__attribute__((bitwise))
/* sparse seems to get confused by some builtins */
extern int __builtin_ia32_rdrand64_step(unsigned long long *);
extern unsigned int __builtin_ia32_crc32di(unsigned int, unsigned long long);
extern unsigned int __builtin_ia32_crc32si(unsigned int, unsigned int);
extern unsigned int __builtin_ia32_crc32hi(unsigned int, unsigned short);
extern unsigned int __builtin_ia32_crc32qi(unsigned int, unsigned char);

#else
# define __force
# define __sp_biwise
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef signed long long s64;

typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef s32 __s32;
typedef u64 __u64;

typedef u16 __sp_biwise __le16;
typedef u16 __sp_biwise __be16;
typedef u32 __sp_biwise __le32;
typedef u32 __sp_biwise __be32;
typedef u64 __sp_biwise __le64;
typedef u64 __sp_biwise __be64;

static inline u16 ___swab16(u16 x)
{
	return	((x & (u16)0x00ffU) << 8) |
		((x & (u16)0xff00U) >> 8);
}

static inline u32 ___swab32(u32 x)
{
	return	((x & (u32)0x000000ffUL) << 24) |
		((x & (u32)0x0000ff00UL) << 8) |
		((x & (u32)0x00ff0000UL) >> 8) |
		((x & (u32)0xff000000UL) >> 24);
}

static inline u64 ___swab64(u64 x)
{
	return  (u64)((x & (u64)0x00000000000000ffULL) << 56) |
		(u64)((x & (u64)0x000000000000ff00ULL) << 40) |
		(u64)((x & (u64)0x0000000000ff0000ULL) << 24) |
		(u64)((x & (u64)0x00000000ff000000ULL) << 8) |
		(u64)((x & (u64)0x000000ff00000000ULL) >> 8) |
		(u64)((x & (u64)0x0000ff0000000000ULL) >> 24) |
		(u64)((x & (u64)0x00ff000000000000ULL) >> 40) |
		(u64)((x & (u64)0xff00000000000000ULL) >> 56);
}

#define __gen_cast_tofrom(end, size)					\
static inline __##end##size cpu_to_##end##size(u##size x)	\
{									\
	return (__force __##end##size)x;				\
}									\
static inline u##size end##size##_to_cpu(__##end##size x)	\
{									\
	return (__force u##size)x;				\
}

#define __gen_swap_tofrom(end, size)					\
static inline __##end##size cpu_to_##end##size(u##size x)	\
{									\
	return (__force __##end##size)___swab##size(x);		\
}									\
static inline u##size end##size##_to_cpu(__##end##size x)	\
{									\
	return ___swab##size((__force u##size) x);		\
}

#define __gen_functions(which, end)	\
	__gen_##which##_tofrom(end, 16)	\
	__gen_##which##_tofrom(end, 32)	\
	__gen_##which##_tofrom(end, 64)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
__gen_functions(swap, be)
__gen_functions(cast, le)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
__gen_functions(swap, le)
__gen_functions(cast, be)
#else
#error "machine is neither BIG_ENDIAN nor LITTLE_ENDIAN"
#endif

static inline void le32_add_cpu(__le32 *val, u32 delta)
{
	*val = cpu_to_le32(le32_to_cpu(*val) + delta);
}

#endif
