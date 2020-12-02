#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <argp.h>

#include "sparse.h"
#include "parse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"

struct list_hidden_xattr_args {
	char *filename;
};

static int do_list_hidden_xattrs(struct list_hidden_xattr_args *args)
{
	struct scoutfs_ioctl_listxattr_hidden lxh;
	char *buf = NULL;
	char *name;
	int fd = -1;
	int bytes;
	int len;
	int ret;
	int i;

	memset(&lxh, 0, sizeof(lxh));
	lxh.id_pos = 0;
	lxh.hash_pos = 0;
	lxh.buf_bytes = 256 * 1024;

	buf = malloc(lxh.buf_bytes);
	if (!buf) {
		fprintf(stderr, "xattr name buf alloc failed\n");
		return -ENOMEM;
	}
	lxh.buf_ptr = (unsigned long)buf;

	fd = open(args->filename, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->filename, strerror(errno), errno);
		goto out;
	}

	for (;;) {

		ret = ioctl(fd, SCOUTFS_IOC_LISTXATTR_HIDDEN, &lxh);
		if (ret == 0)
			break;
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "listxattr_hidden ioctl failed: "
				"%s (%d)\n", strerror(errno), errno);
			goto out;
		}

		bytes = ret;

		if (bytes > lxh.buf_bytes) {
			fprintf(stderr, "listxattr_hidden overflowed\n");
			ret = -EFAULT;
			goto out;
		}
		if (buf[bytes - 1] != '\0') {
			fprintf(stderr, "listxattr_hidden didn't term\n");
			ret = -EINVAL;
			goto out;
		}

		name = buf;

		do {
			len = strlen(name);
			if (len == 0) {
				fprintf(stderr, "listxattr_hidden empty name\n");
				ret = -EINVAL;
				goto out;
			}

			if (len > SCOUTFS_XATTR_MAX_NAME_LEN) {
				fprintf(stderr, "listxattr_hidden long name\n");
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

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct list_hidden_xattr_args *args = state->input;

	switch (key) {
	case ARGP_KEY_ARG:
		if (args->filename)
			argp_error(state, "more than one filename argument given");

		args->filename = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_FINI:
		if (!args->filename) {
			argp_error(state, "must specify filename");
		}
		break;
	default:
		break;
	}

	return 0;
}

static int list_hidden_xattrs_cmd(int argc, char **argv)
{
	struct argp argp = {
		NULL,
		parse_opt,
		"FILE",
		"Print the names of hidden xattrs on a file"
	};
	struct list_hidden_xattr_args list_hidden_xattr_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &list_hidden_xattr_args);
	if (ret)
		return ret;

	return do_list_hidden_xattrs(&list_hidden_xattr_args);
}


static void __attribute__((constructor)) listxattr_hidden_ctor(void)
{
	cmd_register("list-hidden-xattrs", "<path>",
		     "print the names of hidden xattrs on a file",
		     list_hidden_xattrs_cmd);
}
