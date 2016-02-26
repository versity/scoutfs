#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>

#include "sparse.h"
#include "dev.h"

int device_size(char *path, int fd, u64 *size)
{
        struct stat st;
        int ret;

        if (fstat(fd, &st)) {
                ret = -errno;
                fprintf(stderr, "failed to stat '%s': %s (%d)\n",
                        path, strerror(errno), errno);
                return ret;
        }

        if (S_ISREG(st.st_mode)) {
                *size = st.st_size;
        } else if (S_ISBLK(st.st_mode)) {
                if (ioctl(fd, BLKGETSIZE64, size)) {
                        ret = -errno;
                        fprintf(stderr, "BLKGETSIZE64 failed '%s': %s (%d)\n",
                                path, strerror(errno), errno);
                        return ret;
                }
        } else {
                fprintf(stderr, "path isn't regular or device file '%s'\n",
                        path);
                return -EINVAL;
        }

        return 0;
}

