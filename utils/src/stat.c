#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"

static int stat_more_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_stat_more stm;
	char *path;
	int ret;
	int fd;
	int i;

	if (argc == 0) {
		fprintf(stderr, "must specify at least one path argument\n");
		return -EINVAL;
	}

	for (i = 0; i < argc; i++) {
		path = argv[i];

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			ret = -errno;
			fprintf(stderr, "failed to open '%s': %s (%d)\n",
				path, strerror(errno), errno);
			continue;
		}

		memset(&stm, 0, sizeof(stm));
		stm.valid_bytes = sizeof(stm);

		ret = ioctl(fd, SCOUTFS_IOC_STAT_MORE, &stm);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "stat_more ioctl failed on '%s': "
				"%s (%d)\n", path, strerror(errno), errno);
		} else {
			printf("          File: '%s'\n"
			       "  data_version: %-20llu\n",
				path, stm.data_version);
		}

		close(fd);
	}

	return 0;
}

static void __attribute__((constructor)) stat_more_ctor(void)
{
	cmd_register("stat", "<path>",
		     "print scoutfs stat information for path", stat_more_cmd);
}
