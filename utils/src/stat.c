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
#include "cmd.h"

#define FIELD(f) {						\
	.name = #f,						\
	.offset = offsetof(struct scoutfs_ioctl_stat_more, f),	\
}

static struct stat_more_field {
	char *name;
	size_t offset;
} fields[] = {
	FIELD(meta_seq),
	FIELD(data_seq),
	FIELD(data_version),
	FIELD(online_blocks),
	FIELD(offline_blocks),
	{ NULL, }
};

#define for_each_field(f) \
	for (f = fields; f->name; f++)

static struct option long_ops[] = {
	{ "single_field", 1, NULL, 's' },
	{ NULL, 0, NULL, 0}
};

static int stat_more_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_stat_more stm;
	struct stat_more_field *single = NULL;
	struct stat_more_field *fi;
	char *single_name = NULL;
	char *path;
	int ret;
	int fd;
	int i;
	int c;

	while ((c = getopt_long(argc, argv, "s:", long_ops, NULL)) != -1) {
		switch (c) {
		case 's':
			single_name = strdup(optarg);
			assert(single_name);
			break;
		case '?':
		default:
			return -EINVAL;
		}
	}

	if (single_name) {
		for_each_field(fi) {
			if (strcmp(fi->name, single_name) == 0) {
				single = fi;
				break;
			}
		}
		if (!single) {
			fprintf(stderr, "unknown stat_more field: '%s'\n",
				single_name);
			return -EINVAL;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "must specify at least one path argument\n");
		return -EINVAL;
	}

	for (i = optind; i < argc; i++) {
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

		} else if (single) {
			printf("%llu\n",
			       *(u64 *)((void *)&stm + single->offset));

		} else {
			printf("%-17s %s\n", "path", path);
			for_each_field(fi) {
				printf("%-17s %llu\n", fi->name,
				       *(u64 *)((void *)&stm + fi->offset));
			}
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
