#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <argp.h>
#include <stdbool.h>

#include "sparse.h"
#include "parse.h"
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

struct stat_args {
	char *path;
	char *single_field;
	bool is_inode;
	u8 __pad[7];
};

static int do_stat(struct stat_args *args)
{
	union {
		struct scoutfs_ioctl_stat_more stm;
		struct scoutfs_ioctl_statfs_more sfm;
	} st;
	struct stat_more_field *single = NULL;
	struct stat_more_field *fields;
	struct stat_more_field *fi;
	print_field_t pr = NULL;
	int cmd;
	int ret;
	int fd;

	memset(&st, 0, sizeof(st));
	if (args->is_inode) {
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

	if (args->single_field) {
		for_each_field(fi, fields) {
			if (strcmp(fi->name, args->single_field) == 0) {
				single = fi;
				break;
			}
		}
		if (!single) {
			fprintf(stderr, "unknown field: '%s'\n", args->single_field);
			return -EINVAL;
		}
	}

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	ret = ioctl(fd, cmd, &st);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "ioctl failed: %s (%d)\n", strerror(errno), errno);
	} else if (single) {
		pr(&st, single->offset);
		printf("\n");
	} else {
		for_each_field(fi, fields) {
			printf("%-17s ", fi->name);
			pr(&st, fi->offset);
			printf("\n");
		}
	}

	return 0;
}

static int stat_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct stat_args *args = state->input;

	switch (key) {
	case 's':
		args->single_field = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_ARG:
		if (!args->path)
			args->path = strdup_or_error(state, arg);
		else
			argp_error(state, "more than one argument");
		break;
	case ARGP_KEY_FINI:
		if (!args->path)
			argp_error(state, "missing operand");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option stat_options[] = {
	{ "single-field", 's', "FIELD-NAME", 0, "Specify single field to print" },
	{ NULL }
};

static struct argp stat_argp = {
	stat_options,
	stat_parse_opt,
	"FILE",
	"Show ScoutFS extra inode information"
};

static int stat_more_cmd(int argc, char **argv)
{
	struct stat_args stat_args = {NULL};
	int ret;

	ret = argp_parse(&stat_argp, argc, argv, 0, NULL, &stat_args);
	if (ret)
		return ret;
	stat_args.is_inode = true;

	return do_stat(&stat_args);
}

static struct argp_option statfs_options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "single-field", 's', "FIELD-NAME", 0, "Specify single field to print" },
	{ NULL }
};

static int statfs_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct stat_args *args = state->input;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case 's':
		args->single_field = strdup_or_error(state, arg);
		break;
	default:
		break;
	}

	return 0;
}

static struct argp statfs_argp = {
	statfs_options,
	statfs_parse_opt,
	"",
	"Show ScoutFS file system information"
};

static int statfs_more_cmd(int argc, char **argv)
{
	struct stat_args stat_args = {NULL};
	int ret;

	ret = argp_parse(&statfs_argp, argc, argv, 0, NULL, &stat_args);
	if (ret)
		return ret;
	stat_args.is_inode = false;

	return do_stat(&stat_args);
}

static void __attribute__((constructor)) stat_more_ctor(void)
{
	cmd_register_argp("stat", &stat_argp, GROUP_INFO, stat_more_cmd);
}

static void __attribute__((constructor)) statfs_more_ctor(void)
{
	cmd_register_argp("statfs", &statfs_argp, GROUP_INFO, statfs_more_cmd);
}
