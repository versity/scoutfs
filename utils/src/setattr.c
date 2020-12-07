#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "parse.h"
#include "cmd.h"

static struct option long_ops[] = {
	{ "ctime", 1, NULL, 'c' },
	{ "data_version", 1, NULL, 'd' },
	{ "file", 1, NULL, 'f' },
	{ "offline", 0, NULL, 'o' },
	{ "i_size", 1, NULL, 's' },
	{ NULL, 0, NULL, 0}
};

static int setattr_more_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_setattr_more sm;
	struct timespec ctime;
	char *path = NULL;
	int ret;
	int fd = -1;
	int c;

	memset(&sm, 0, sizeof(sm));

	while ((c = getopt_long(argc, argv, "c:d:f:os:", long_ops, NULL)) != -1) {
		switch (c) {
		case 'c':
			ret = parse_timespec(optarg, &ctime);
			if (ret)
				goto out;
			break;
		case 'd':
			ret = parse_u64(optarg, &sm.data_version);
			if (ret)
				goto out;
			break;
		case 'f':
			path = strdup(optarg);
			if (!path) {
				fprintf(stderr, "path mem alloc failed\n");
				ret = -ENOMEM;
				goto out;
			}
			break;
		case 'o':
			sm.flags |= SCOUTFS_IOC_SETATTR_MORE_OFFLINE;
			break;
		case 's':
			ret = parse_u64(optarg, &sm.i_size);
			if (ret)
				goto out;
			break;
		case '?':
		default:
			ret = -EINVAL;
			goto out;
		}
	}

	if (path == NULL) {
		fprintf(stderr, "must specify -f path to file\n");
		ret = -EINVAL;
		goto out;
	}

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	sm.ctime_sec = ctime.tv_sec;
	sm.ctime_nsec = ctime.tv_nsec;

	ret = ioctl(fd, SCOUTFS_IOC_SETATTR_MORE, &sm);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "setattr_more ioctl failed on '%s': "
			"%s (%d)\n", path, strerror(errno), errno);
		goto out;
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static void __attribute__((constructor)) setattr_more_ctor(void)
{
	cmd_register("setattr", "-c ctime -d data_version -o -s i_size -f <path>",
		     "set attributes on file with no data",  
		     setattr_more_cmd);
}
