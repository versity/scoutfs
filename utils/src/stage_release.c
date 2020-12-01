#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <argp.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "parse.h"
#include "cmd.h"

struct stage_args {
	char *archive_path;
	char *path;
	u64 data_version;
	u64 offset;
	u64 length;
};

static int do_stage(struct stage_args *args)
{
	struct scoutfs_ioctl_stage ioctl_args;
	unsigned int buf_len = 1024 * 1024;
	unsigned int bytes;
	char *buf = NULL;
	int afd = -1;
	int fd = -1;
	int ret;

	afd = open(args->archive_path, O_RDONLY);
	if (afd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->archive_path, strerror(errno), errno);
		goto out;
	}

	fd = open(args->path, O_RDWR);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->path, strerror(errno), errno);
		return ret;
	}

	buf = malloc(buf_len);
	if (!buf) {
		fprintf(stderr, "couldn't allocate %u byte buffer\n", buf_len);
		ret = -ENOMEM;
		goto out;
	}

	while (args->length) {

		bytes = min(args->length, buf_len);

		ret = read(afd, buf, bytes);
		if (ret <= 0) {
			fprintf(stderr, "archive read returned %d: error %s (%d)\n",
				ret, strerror(errno), errno);
			ret = -EIO;
			goto out;
		}

		bytes = ret;

		ioctl_args.data_version = args->data_version;
		ioctl_args.buf_ptr = (unsigned long)buf;
		ioctl_args.offset = args->offset;
		ioctl_args.count = bytes;

		args->length -= bytes;
		args->offset += bytes;

		ret = ioctl(fd, SCOUTFS_IOC_STAGE, &ioctl_args);
		if (ret != bytes) {
			fprintf(stderr, "stage returned %d, not %u: error %s (%d)\n",
				ret, bytes, strerror(errno), errno);
			ret = -EIO;
			goto out;
		}
	}

	ret = 0;
out:
	free(buf);
	if (fd > -1)
		close(fd);
	if (afd > -1)
		close(afd);
	return ret;
};

static int parse_stage_opts(int key, char *arg, struct argp_state *state)
{
	struct stage_args *args = state->input;
	int ret;

	switch (key) {
	case 'V':
		ret = parse_u64(arg, &args->data_version);
		if (ret)
			return ret;
		break;
	case 'o': /* offset */
		ret = parse_human(arg, &args->offset);
		if (ret)
			return ret;
		break;
	case 'l': /* length */
		ret = parse_human(arg, &args->length);
		if (ret)
			return ret;
		break;
	case ARGP_KEY_ARG:
		if (!args->archive_path)
			args->archive_path = strdup_or_error(state, arg);
		else if (!args->path)
			args->path = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two arguments given");
		break;
	case ARGP_KEY_FINI:
		if (!args->archive_path) {
			argp_error(state, "must provide archive file path");
		}
		if (!args->path) {
			argp_error(state, "must provide to-stage file path");
		}
		if (!args->data_version) {
			argp_error(state, "must provide file version with --data-version");
		}
		if (!args->length) {
			struct stat statbuf = {0};

			ret = stat(args->archive_path, &statbuf);
			if (ret < 0)
				argp_failure(state, 1, -errno, "Could not get file size");

			args->length = statbuf.st_size;
		}
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "data-version", 'V', "VERSION", 0, "Data version of the file [Required]"},
	{ "offset", 'o', "OFFSET", 0, "Offset (bytes or KMGTP units) in file to stage (default: 0)"},
	{ "length", 'l', "LENGTH", 0, "Length of range (bytes or KMGTP units) of file to stage. (default: size of ARCHIVE-FILE)"},
	{ NULL }
};

static int stage_cmd(int argc, char **argv)
{
	struct argp argp = {
		options,
		parse_stage_opts,
		"ARCHIVE-FILE STAGE-FILE --data-version VERSION",
		"Write archive file contents to an offline file"
	};
	struct stage_args stage_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &stage_args);
	if (ret)
		return ret;

	return do_stage(&stage_args);
}

static void __attribute__((constructor)) stage_ctor(void)
{
	cmd_register("stage", "<archive file> <file> -V <version>",
		     "write archive file contents to an offline file", stage_cmd);
}

struct release_args {
	char *path;
	u64 data_version;
	u64 offset;
	u64 length;
};

static int do_release(struct release_args *args)
{
	struct scoutfs_ioctl_release ioctl_args = {0};
	int ret;
	int fd;

	fd = open(args->path, O_RDWR);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			args->path, strerror(errno), errno);
		return ret;
	}

	assert(args->offset % SCOUTFS_BLOCK_SM_SIZE == 0);
	assert(args->length % SCOUTFS_BLOCK_SM_SIZE == 0);

	ioctl_args.block = args->offset / SCOUTFS_BLOCK_SM_SIZE;
	ioctl_args.count = args->length / SCOUTFS_BLOCK_SM_SIZE;
	ioctl_args.data_version = args->data_version;

	ret = ioctl(fd, SCOUTFS_IOC_RELEASE, &ioctl_args);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "release ioctl failed: %s (%d)\n",
			strerror(errno), errno);
	}

	close(fd);
	return ret;
};

static int parse_release_opts(int key, char *arg, struct argp_state *state)
{
	struct release_args *args = state->input;
	int ret;

	switch (key) {
	case 'V':
		ret = parse_u64(arg, &args->data_version);
		if (ret)
			return ret;
		break;
	case 'o': /* offset */
		ret = parse_human(arg, &args->offset);
		if (ret)
			return ret;
		break;
	case 'l': /* length */
		ret = parse_human(arg, &args->length);
		if (ret)
			return ret;
		break;
	case ARGP_KEY_ARG:
		if (args->path)
			argp_error(state, "more than one argument given");
		args->path = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_FINI:
		if (!args->path) {
			argp_error(state, "must provide file path");
		}
		if (!args->data_version) {
			argp_error(state, "must provide file version --data-version");
		}
		if (!args->length) {
			int ret;
			struct stat statbuf = {0};

			ret = stat(args->path, &statbuf);
			if (ret < 0)
				argp_failure(state, 1, -errno, "Could not get file size");

			args->length = round_up(statbuf.st_size, SCOUTFS_BLOCK_SM_SIZE);
		}
		break;
	default:
		break;
	}

	return 0;
}

static int release_cmd(int argc, char **argv)
{
	struct argp argp = {
		options,
		parse_release_opts,
		"FILE --data-version VERSION",
		"Mark file region offline and free extents"
	};
	struct release_args release_args = {NULL};
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &release_args);
	if (ret)
		return ret;

	return do_release(&release_args);
}

static void __attribute__((constructor)) release_ctor(void)
{
	cmd_register("release", "<path> <vers>",
		     "mark file region offline and free extents", release_cmd);
}
