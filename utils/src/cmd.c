#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <argp.h>

#include "cmd.h"
#include "util.h"

static struct argp_command {
	char *name;
	struct argp *argp;
	int group;
	int (*func)(int argc, char **argv);
} argp_cmds[100], *next_argp_cmd = argp_cmds;

#define cmd_for_each(com) for (com = argp_cmds; com->func; com++)

void cmd_register_argp(char *name, struct argp *argp, int group,
		  int (*func)(int argc, char **argv))
{
	struct argp_command *com = next_argp_cmd++;

	assert((com - argp_cmds) < array_size(argp_cmds));

	com->name = name;
	com->argp = argp;
	com->group = group;
	com->func = func;
}


static struct argp_command *find_command(char *name)
{
	struct argp_command *com;

	cmd_for_each(com) {
		if (!strcmp(name, com->name))
			return com;
	}

	return NULL;
}

static void print_cmds_for_group(int group)
{
	struct argp_command *com;
	int largest = 0;

	/* Base alignment on all groups */
	cmd_for_each(com)
		largest = max(strlen(com->name), largest);

	cmd_for_each(com) {
		if (com->group == group) {
			fprintf(stderr, "  %*s %s\n  %*s %s\n",
				largest, com->name, com->argp->args_doc,
				largest, "", com->argp->doc);
		}
	}

}

static void usage(void)
{
	fprintf(stderr, "usage: scoutfs <command> [<args>]\n\n");
	fprintf(stderr, "Selected fs defaults to current working directory.\n");
	fprintf(stderr, "See <command> --help for more details.\n");

	fprintf(stderr, "\nCore admin:\n");
	print_cmds_for_group(GROUP_CORE);
	fprintf(stderr, "\nAdditional Information:\n");
	print_cmds_for_group(GROUP_INFO);
	fprintf(stderr, "\nSearch Acceleration:\n");
	print_cmds_for_group(GROUP_SEARCH);
	fprintf(stderr, "\nArchival Agent Support:\n");
	print_cmds_for_group(GROUP_AGENT);
	fprintf(stderr, "\nDebugging commands:\n");
	print_cmds_for_group(GROUP_DEBUG);
}

/* this returns a positive unix return code on error for some reason */
char cmd_execute(int argc, char **argv)
{
	struct argp_command *com = NULL;
	int ret;

	if (argc > 1) {
		com = find_command(argv[1]);
		if (!com)
			fprintf(stderr, "scoutfs: unrecognized command: '%s'\n",
				argv[1]);
	}
	if (!com) {
		usage();
		return 1;
	}

	ret = com->func(argc - 1, argv + 1);
	if (ret < 0) {
		fprintf(stderr, "scoutfs: %s failed: %s (%d)\n",
			com->name, strerror(-ret), -ret);
		return 1;
	}

	return 0;
}
