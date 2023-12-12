#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>

#include "sparse.h"
#include "parse.h"
#include "util.h"
#include "format.h"
#include "ioctl.h"
#include "cmd.h"
#include "list.h"

struct str_head {
	struct list_head head;
	char str[0];
};

struct proj_args {
	struct list_head paths;
	char *which;
	u64 proj;
	unsigned int cmd;
	bool have_proj;
};

static bool single_entry(struct list_head *list)
{
	return list->next->next == list;
}

static int do_proj(struct proj_args *args)
{
	struct str_head *shead;
	int fd = -1;
	int ret;

	list_for_each_entry(shead, &args->paths, head) {

		if (fd >= 0)
			close(fd);
		fd = get_path(shead->str, O_RDONLY);
		if (fd < 0) {
			ret = fd;
			goto out;
		}

		ret = ioctl(fd, args->cmd, &args->proj);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "%s project ioctl failed: %s (%d)\n",
				args->which, strerror(errno), errno);
			goto out;
		}

		if (args->cmd == SCOUTFS_IOC_GET_PROJECT_ID) {
			if (single_entry(&args->paths))
				printf("%llu\n", args->proj);
			else
				printf("%s: %llu\n", shead->str, args->proj);
		}
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);

	return ret;
}

static bool add_strdup_head(struct list_head *list, char *str)
{
	struct str_head *shead;
	size_t bytes;

	bytes = strlen(str) + 1;
	shead = malloc(offsetof(struct str_head, str[bytes]));
	if (!shead)
		return false;

	memcpy(shead->str, str, bytes);
	list_add_tail(&shead->head, list);
	return true;
}

static int parse_proj_opt(int key, char *arg, struct argp_state *state)
{
	struct proj_args *args = state->input;
	int ret;

	switch (key) {
	case 'g':
		args->cmd = SCOUTFS_IOC_GET_PROJECT_ID;
		args->which = "get";
		break;
	case 's':
		ret = parse_u64(arg, &args->proj);
		if (ret)
			argp_error(state, "error parsing project ID");
		args->cmd = SCOUTFS_IOC_SET_PROJECT_ID;
		args->which = "set";
		break;
	case ARGP_KEY_ARG:
		if (!add_strdup_head(&args->paths, arg))
			argp_error(state, "error allocating memory for path");
		break;
	case ARGP_KEY_FINI:
		if (!args->cmd)
			argp_error(state, "must specify either -g (get) or -s (set)");
		if (list_empty(&args->paths))
			argp_error(state, "must final path arguments");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option proj_opts[] = {
	{ "get", 'g', NULL, 0, "Get and print existing project ID from inodes"},
	{ "set", 's', "ID", 0, "Set unsigned 64bit project ID on inodes (0 clears)"},
	{ NULL }
};

static struct argp proj_argp = {
	proj_opts,
	parse_proj_opt,
	"",
	"Manipulate Project ID on inodes"
};

static int proj_cmd(int argc, char **argv)
{
	struct proj_args args = {
		.paths = LIST_HEAD_INIT(args.paths),
		.have_proj = false,
	};

	return argp_parse(&proj_argp, argc, argv, 0, NULL, &args) ?:
	       do_proj(&args);
}

static void __attribute__((constructor)) proj_ctor(void)
{
	cmd_register_argp("project-id", &proj_argp, GROUP_CORE, proj_cmd);
}
