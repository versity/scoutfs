#ifndef _CRC_H_
#define _CRC_H_

#include "sparse.h"
#include "util.h"
#include "format.h"

u32 crc32c(u32 crc, const void *data, unsigned int len);
u64 crc32c_64(u32 crc, const void *data, unsigned int len);
u32 crc_block(struct scoutfs_block_header *hdr);

#endif
