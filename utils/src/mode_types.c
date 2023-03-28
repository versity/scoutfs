#include <unistd.h>
#include <sys/stat.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "mode_types.h"

unsigned int mode_to_type(mode_t mode)
{
#define S_SHIFT 12
	static unsigned char mode_types[S_IFMT >> S_SHIFT] = {
		[S_IFIFO >> S_SHIFT]	= SCOUTFS_DT_FIFO,
		[S_IFCHR >> S_SHIFT]	= SCOUTFS_DT_CHR,
		[S_IFDIR >> S_SHIFT]	= SCOUTFS_DT_DIR,
		[S_IFBLK >> S_SHIFT]	= SCOUTFS_DT_BLK,
		[S_IFREG >> S_SHIFT]	= SCOUTFS_DT_REG,
		[S_IFLNK >> S_SHIFT]	= SCOUTFS_DT_LNK,
		[S_IFSOCK >> S_SHIFT]	= SCOUTFS_DT_SOCK,
	};

	return mode_types[(mode & S_IFMT) >> S_SHIFT];
#undef S_SHIFT
}
