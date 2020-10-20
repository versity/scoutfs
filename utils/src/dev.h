#ifndef _DEV_H_
#define _DEV_H_

#define BASE_SIZE_FMT "%.2f %s"
#define BASE_SIZE_ARGS(sz) size_flt(sz, 1), size_str(sz, 1)

#define SIZE_FMT "%llu (%.2f %s)"
#define SIZE_ARGS(nr, sz) (nr), size_flt(nr, sz), size_str(nr, sz)

int device_size(char *path, int fd,
		u64 min_size, u64 max_size,
		char *use_type, u64 *size_ret);
float size_flt(u64 nr, unsigned size);
char *size_str(u64 nr, unsigned size);

#endif
