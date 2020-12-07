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

struct stat_more_field {
	char *name;
	size_t offset;
};

#define FIELD(f, o) {	\
	.name = #f,	\
	.offset = o,	\
}

#define INODE_FIELD_OFF(f) offsetof(struct scoutfs_ioctl_stat_more, f)
#define INODE_FIELD(f) FIELD(f, INODE_FIELD_OFF(f))

static struct stat_more_field inode_fields[] = {
	INODE_FIELD(meta_seq),
	INODE_FIELD(data_seq),
	INODE_FIELD(data_version),
	INODE_FIELD(online_blocks),
	INODE_FIELD(offline_blocks),
	{ NULL, }
};

static void print_inode_field(void *st, size_t off)
{
	struct scoutfs_ioctl_stat_more *stm = st;

	switch(off) {
		case INODE_FIELD_OFF(meta_seq):
			printf("%llu", stm->meta_seq);
			break;
		case INODE_FIELD_OFF(data_seq):
			printf("%llu", stm->data_seq);
			break;
		case INODE_FIELD_OFF(data_version):
			printf("%llu", stm->data_version);
			break;
		case INODE_FIELD_OFF(online_blocks):
			printf("%llu", stm->online_blocks);
			break;
		case INODE_FIELD_OFF(offline_blocks):
			printf("%llu", stm->offline_blocks);
			break;
	};
}

#define FS_FIELD_OFF(f) offsetof(struct scoutfs_ioctl_statfs_more, f)
#define FS_FIELD(f) FIELD(f, FS_FIELD_OFF(f))

static struct stat_more_field fs_fields[] = {
	FS_FIELD(fsid),
	FS_FIELD(rid),
	FS_FIELD(committed_seq),
	FS_FIELD(total_meta_blocks),
	FS_FIELD(total_data_blocks),
	{ NULL, }
};

static void print_fs_field(void *st, size_t off)
{
	struct scoutfs_ioctl_statfs_more *sfm = st;

	switch(off) {
		case FS_FIELD_OFF(fsid):
			printf("%016llx", sfm->fsid);
			break;
		case FS_FIELD_OFF(rid):
			printf("%016llx", sfm->rid);
			break;
		case FS_FIELD_OFF(committed_seq):
			printf("%llu", sfm->committed_seq);
			break;
		case FS_FIELD_OFF(total_meta_blocks):
			printf("%llu", sfm->total_meta_blocks);
			break;
		case FS_FIELD_OFF(total_data_blocks):
			printf("%llu", sfm->total_data_blocks);
			break;
	};
}

#define for_each_field(f, fields) \
	for (f = fields; f->name; f++)

typedef void (*print_field_t)(void *st, size_t off);

static struct option long_ops[] = {
	{ "single_field", 1, NULL, 's' },
	{ NULL, 0, NULL, 0}
};

static int do_stat(int argc, char **argv, int is_inode)
{
	union {
		struct scoutfs_ioctl_stat_more stm;
		struct scoutfs_ioctl_statfs_more sfm;
	} st;
	struct stat_more_field *single = NULL;
	struct stat_more_field *fields;
	struct stat_more_field *fi;
	char *single_name = NULL;
	print_field_t pr = NULL;
	char *path;
	int cmd;
	int ret;
	int fd;
	int i;
	int c;

	memset(&st, 0, sizeof(st));
	if (is_inode) {
		cmd = SCOUTFS_IOC_STAT_MORE;
		fields = inode_fields;
		st.stm.valid_bytes = sizeof(struct scoutfs_ioctl_stat_more);
		pr = print_inode_field;
	} else {
		cmd = SCOUTFS_IOC_STATFS_MORE;
		fields = fs_fields;
		st.sfm.valid_bytes = sizeof(struct scoutfs_ioctl_statfs_more);
		pr = print_fs_field;
	}

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
		for_each_field(fi, fields) {
			if (strcmp(fi->name, single_name) == 0) {
				single = fi;
				break;
			}
		}
		if (!single) {
			fprintf(stderr, "unknown field: '%s'\n", single_name);
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

		ret = ioctl(fd, cmd, &st);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "ioctl failed on '%s': "
				"%s (%d)\n", path, strerror(errno), errno);

		} else if (single) {
			pr(&st, single->offset);
			printf("\n");
		} else {
			printf("%-17s %s\n", "path", path);
			for_each_field(fi, fields) {
				printf("%-17s ", fi->name);
				pr(&st, fi->offset);
				printf("\n");
			}
		}

		close(fd);
	}

	return 0;
}

static int stat_more_cmd(int argc, char **argv)
{
	return do_stat(argc, argv, 1);
}

static int statfs_more_cmd(int argc, char **argv)
{
	return do_stat(argc, argv, 0);
}

static void __attribute__((constructor)) stat_more_ctor(void)
{
	cmd_register("stat", "<path>",
		     "show scoutfs inode information", stat_more_cmd);
}

static void __attribute__((constructor)) statfs_more_ctor(void)
{
	cmd_register("statfs", "<path>",
		     "show scoutfs file system information", statfs_more_cmd);
}
