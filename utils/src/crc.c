#include "crc.h"
#include "util.h"
#include "format.h"

u32 crc32c(u32 crc, const void *data, unsigned int len)
{
	while (len >= 8) {
		crc = __builtin_ia32_crc32di(crc, *(u64 *)data);
		len -= 8;
		data += 8;
	}
	if (len & 4) {
		crc = __builtin_ia32_crc32si(crc, *(u32 *)data);
		data += 4;
	}
	if (len & 2) {
		crc = __builtin_ia32_crc32hi(crc, *(u16 *)data);
		data += 2;
	}
	if (len & 1)
		crc = __builtin_ia32_crc32qi(crc, *(u8 *)data);

	return crc;
}

/* A simple hack to get reasonably solid 64bit hash values */
u64 crc32c_64(u32 crc, const void *data, unsigned int len)
{
	unsigned int half = (len + 1) / 2;

	return ((u64)crc32c(crc, data, half) << 32) |
		     crc32c(~crc, data + len - half, half);
}

u32 crc_header(struct scoutfs_header *hdr, size_t size)
{
	return crc32c(~0, (char *)hdr + sizeof(hdr->crc),
		      size - sizeof(hdr->crc));
}
