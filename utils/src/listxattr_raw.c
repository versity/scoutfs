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
#include <ctype.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"

static struct option long_ops[] = {
	{ "file", 1, NULL, 'f' },
	{ NULL, 0, NULL, 0}
};

static int listxattr_raw_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_listxattr_raw lxr;
	char *path = NULL;
	char *buf = NULL;
	char *name;
	int fd = -1;
	int bytes;
	int len;
	int ret;
	int c;
	int i;

	while ((c = getopt_long(argc, argv, "f:", long_ops, NULL)) != -1) {
		switch (c) {
		case 'f':
			path = strdup(optarg);
			if (!path) {
				fprintf(stderr, "path mem alloc failed\n");
				ret = -ENOMEM;
				goto out;
			}
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

	memset(&lxr, 0, sizeof(lxr));
	lxr.id_pos = 0;
	lxr.hash_pos = 0;
	lxr.buf_bytes = 256 * 1024;

	buf = malloc(lxr.buf_bytes);
	if (!buf) {
		fprintf(stderr, "xattr name buf alloc failed\n");
		return -ENOMEM;
	}
	lxr.buf_ptr = (unsigned long)buf;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	for (;;) {

		ret = ioctl(fd, SCOUTFS_IOC_LISTXATTR_RAW, &lxr);
		if (ret == 0)
			break;
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "listxattr_raw ioctl failed: "
				"%s (%d)\n", strerror(errno), errno);
			goto out;
		}

		bytes = ret;

		if (bytes > lxr.buf_bytes) {
			fprintf(stderr, "listxattr_raw overflowed\n");
			ret = -EFAULT;
			goto out;
		}
		if (buf[bytes - 1] != '\0') {
			fprintf(stderr, "listxattr_raw didn't term\n");
			ret = -EINVAL;
			goto out;
		}

		name = buf;

		do {
			len = strlen(name);
			if (len == 0) {
				fprintf(stderr, "listxattr_raw empty name\n");
				ret = -EINVAL;
				goto out;
			}

			if (len > SCOUTFS_XATTR_MAX_NAME_LEN) {
				fprintf(stderr, "listxattr_raw long name\n");
				ret = -EINVAL;
				goto out;
			}

			for (i = 0; i < len; i++) {
				if (!isprint(name[i]))
					name[i] = '?';
			}

			printf("%s\n", name);
			name += len + 1;
			bytes -= len + 1;

		} while (bytes > 0);
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(buf);

	return ret;
};

static void __attribute__((constructor)) listxattr_raw_ctor(void)
{
	cmd_register("listxattr-raw", "-f <path>",
		     "print only the names of all xattrs on the file",
		     listxattr_raw_cmd);
}
