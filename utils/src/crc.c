#include <zlib.h>

#include "crc.h"
#include "util.h"
#include "format.h"

u32 crc32c(u32 crc, const void *data, unsigned int len)
{
	return crc32(crc, data, len);
}

/* A simple hack to get reasonably solid 64bit hash values */
u64 crc32c_64(u32 crc, const void *data, unsigned int len)
{
	unsigned int half = (len + 1) / 2;

	return ((u64)crc32c(crc, data, half) << 32) |
		     crc32c(~crc, data + len - half, half);
}

u32 crc_block(struct scoutfs_block_header *hdr, u32 size)
{
	return crc32c(~0, (char *)hdr + sizeof(hdr->crc),
		      size - sizeof(hdr->crc));
}
