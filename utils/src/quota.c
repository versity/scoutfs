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
#include "util.h"
#include "key.h"

static char opc[] = {
	[SQ_OP_DATA] = 'D',
	[SQ_OP_INODE] = 'I',
};

static char nsc[] = {
	[SQ_NS_LITERAL] = 'L',
	[SQ_NS_PROJ] = 'P',
	[SQ_NS_UID] = 'U',
	[SQ_NS_GID] = 'G',
};

static void printf_rule(struct scoutfs_ioctl_quota_rule *irule)
{
	int i;

	/* priority: [0-9]+ */
	printf("%3u ", irule->prio);

	/* totl name: ([0-9]+,[LPUG-]+,[S-]+){3} */
	for (i = 0; i < array_size(irule->name_val); i++) {

		printf("%llu,%c,%c ",
		       irule->name_val[i],
		       nsc[irule->name_source[i]],
		       (irule->name_flags[i] & SQ_NF_SELECT) ? 'S' : '-');
	}

	/* op: [ID], limit: [0-9]+, flags [C-] */
	printf("%c %llu %c\n",
	       opc[irule->op], irule->limit, (irule->rule_flags & SQ_RF_TOTL_COUNT) ? 'C' : '-');
}

static int parse_rule(struct scoutfs_ioctl_quota_rule *irule, char *str)
{
	char ns[3];
	char nf[3];
	char rf;
	char op;
	int ret;
	int i;
	int j;

	memset(irule, 0, sizeof(struct scoutfs_ioctl_quota_rule));

	ret = sscanf(str, " %hhu %llu,%c,%c %llu,%c,%c %llu,%c,%c %c %llu %c",
		     &irule->prio, &irule->name_val[0], &ns[0], &nf[0], &irule->name_val[1],
		     &ns[1], &nf[1], &irule->name_val[2], &ns[2], &nf[2], &op, &irule->limit,
		     &rf);
	if (ret != 13) {
		printf("invalid rule, missing fields: %s\n", str);
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < array_size(irule->name_val); i++) {
		irule->name_source[i] = SQ_NS__NR;

		for (j = 0; j < array_size(nsc); j++) {
			if (ns[i] == nsc[j]) {
				irule->name_source[i] = j;
				break;
			}
		}

		if (irule->name_source[i] == SQ_NS__NR) {
			printf("invalid name source '%c' in name #%u in rule:\n\t%s\n",
			       ns[i], i + 1, str);
			ret = -EINVAL;
			goto out;
		}

		irule->name_flags[i] = nf[i] == '-' ? 0 :
				       nf[i] == 'S' ? SQ_NF_SELECT :
				       SQ_NF__UNKNOWN;
		if (irule->name_flags[i] == SQ_NF__UNKNOWN) {
			printf("invalid name flags '%c' in name #%u in rule:\n\t%s\n",
			       nf[i], i + 1, str);
			ret = -EINVAL;
			goto out;
		}
	}

	irule->op = SQ_NS__NR;
	for (i = 0; i < array_size(opc); i++) {
		if (op == opc[i]) {
			irule->op = i;
			break;
		}
	}

	if (irule->op == SQ_NS__NR) {
		printf("invalid op '%c' in rule:\n\t%s\n", op, str);
		ret = -EINVAL;
		goto out;
	}

	irule->rule_flags = rf == '-' ? 0 : rf == 'C' ? SQ_RF_TOTL_COUNT : SQ_RF__UNKNOWN;
	if (irule->rule_flags == SQ_RF__UNKNOWN) {
		printf("invalid rule flags '%c' in rule:\n\t%s\n", rf, str);
		ret = -EINVAL;
		goto out;
	}

	ret = 0;
out:
	return ret;
}

/* ---------------------------------------------- */

struct mod_args {
	char *path;
	char *rule_str;
	bool is_add;
};

static int do_mod(struct mod_args *args)
{
	struct scoutfs_ioctl_quota_rule irule;
	unsigned int cmd;
	int fd = -1;
	int ret;

	memset(&irule, 0, sizeof(irule));

	ret = parse_rule(&irule, args->rule_str);
	if (ret < 0)
		goto out;

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	cmd = args->is_add ? SCOUTFS_IOC_ADD_QUOTA_RULE : SCOUTFS_IOC_DEL_QUOTA_RULE;
	ret = ioctl(fd, cmd, &irule);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "MOD_QUOTA_RULE ioctl failed: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);

	return ret;
}

static int parse_mod_opt(int key, char *arg, struct argp_state *state)
{
	struct mod_args *args = state->input;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case 'r':
		args->rule_str = strdup_or_error(state, arg);
		break;
	case ARGP_KEY_FINI:
		if (!args->path)
			argp_error(state, "must provide file path");
		if (!args->rule_str)
			argp_error(state, "must provide rule string");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option add_options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "rule", 'r', "RULE_STRING", 0, "Rule string"},
	{ NULL }
};

static struct argp add_argp = {
	add_options,
	parse_mod_opt,
	"",
	"Add quota rule"
};

static int add_cmd(int argc, char **argv)
{
	struct mod_args args = { .is_add = true, };
	int ret;

	ret = argp_parse(&add_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_mod(&args);
}

static void __attribute__((constructor)) add_ctor(void)
{
	cmd_register_argp("quota-add", &add_argp, GROUP_CORE, add_cmd);
}

static struct argp_option del_options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "rule", 'r', "RULE_STRING", 0, "Rule string"},
	{ NULL }
};

static struct argp del_argp = {
	del_options,
	parse_mod_opt,
	"",
	"Delete quota rule"
};

static int del_cmd(int argc, char **argv)
{
	struct mod_args args = { .is_add = false };
	int ret;

	ret = argp_parse(&del_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_mod(&args);
}

static void __attribute__((constructor)) del_ctor(void)
{
	cmd_register_argp("quota-del", &del_argp, GROUP_CORE, del_cmd);
}

/* ---------------------------------------------- */

struct bulk_args {
	char *path;
	bool unsorted;
};

typedef int (*bulk_in_fn)(int fd, struct scoutfs_ioctl_quota_rule *irules, size_t nr,
		          void *in_args);
typedef int (*bulk_out_fn)(int fd, struct scoutfs_ioctl_quota_rule *irule, void *out_args);

static int cmp_irules(const struct scoutfs_ioctl_quota_rule *a,
		      const struct scoutfs_ioctl_quota_rule *b)
{
	return scoutfs_cmp(a->prio, b->prio) ?:
	       scoutfs_cmp(a->name_val[0], b->name_val[0]) ?:
	       scoutfs_cmp(a->name_source[0], b->name_source[0]) ?:
	       scoutfs_cmp(a->name_flags[0], b->name_flags[0]) ?:
	       scoutfs_cmp(a->name_val[1], b->name_val[1]) ?:
	       scoutfs_cmp(a->name_source[1], b->name_source[1]) ?:
	       scoutfs_cmp(a->name_flags[1], b->name_flags[1]) ?:
	       scoutfs_cmp(a->name_val[2], b->name_val[2]) ?:
	       scoutfs_cmp(a->name_source[2], b->name_source[2]) ?:
	       scoutfs_cmp(a->name_flags[2], b->name_flags[2]) ?:
	       scoutfs_cmp(a->op, b->op) ?:
	       scoutfs_cmp(a->limit, b->limit) ?:
	       scoutfs_cmp(a->rule_flags, b->rule_flags);
}

static int compar_irules(const void *a, const void *b)
{
	return -cmp_irules(a, b);
}

static int do_bulk(struct bulk_args *args, bulk_in_fn in_fn, void *in_args,
		   bulk_out_fn out_fn, void *out_args)
{
	struct scoutfs_ioctl_quota_rule *irules = NULL;
	size_t alloced = 0;
	size_t nr = 0;
	size_t batch;
	size_t i;
	int fd = -1;
	int ret;

	fd = get_path(args->path, O_RDONLY);
	if (fd < 0)
		return fd;

	for (;;) {
		if (nr == alloced) {
			alloced += 1024;
			irules = realloc(irules, alloced * sizeof(irules[0]));
			if (!irules) {
				ret = -errno;
				fprintf(stderr, "memory allocation failed: %s (%d)\n",
					strerror(errno), errno);
				goto out;
			}
		}

		ret = in_fn(fd, &irules[nr], alloced - nr, in_args);
		if (ret == 0)
			break;
		if (ret < 0)
			goto out;

		batch = ret;

		if (args->unsorted) {
			for (i = 0; i < batch; i++) {
				ret = out_fn(fd, &irules[nr + i], out_args);
				if (ret < 0)
					goto out;
			}
		} else {
			nr += batch;
		}
	}

	if (!args->unsorted) {
		qsort(irules, nr, sizeof(irules[0]), compar_irules);

		for (i = 0; i < nr; i++) {
			ret = out_fn(fd, &irules[i], out_args);
			if (ret < 0)
				goto out;
		}
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	if (irules)
		free(irules);

	return ret;
}

/* ---------------------------------------------- */

/* maintain iterator in gqr between calls */
static int get_ioctl_in_fn(int fd, struct scoutfs_ioctl_quota_rule *irules, size_t nr,
			   void *in_args)
{
	struct scoutfs_ioctl_get_quota_rules *gqr = in_args;
	int ret;

	gqr->rules_ptr = (intptr_t)irules;
	gqr->rules_nr = nr;

	ret = ioctl(fd, SCOUTFS_IOC_GET_QUOTA_RULES, gqr);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "GET_QUOTA_RULES ioctl failed: %s (%d)\n",
			strerror(errno), errno);
	}

	return ret;
}

static int parse_stdin_in_fn(int fd, struct scoutfs_ioctl_quota_rule *irules, size_t nr,
			     void *in_args)
{
	char *line = NULL;
	size_t size;
	int ret;

	ret = getline(&line, &size, stdin);
	if (ret < 0) {
		if (errno == ENOENT)
			return 0;

		ret = -errno;
		fprintf(stderr, "error reading rules: %s (%d)\n",
			strerror(errno), errno);
		return ret;
	}

	ret = parse_rule(&irules[0], line);
	if (ret == 0)
		ret = 1;

	free(line);

	return ret;
}

struct mod_ioctl_args {
	unsigned int cmd;
	char *which;
};

static int mod_ioctl_out_fn(int fd, struct scoutfs_ioctl_quota_rule *irule, void *out_args)
{
	struct mod_ioctl_args *args = out_args;
	int ret;

	ret = ioctl(fd, args->cmd, irule);
	if (ret < 0) {
		ret = -errno;
		printf("Failed to %s following rule:\n    ", args->which);
		printf_rule(irule);
		fprintf(stderr, "Error: %s (%d)\n", strerror(-ret), -ret);
	}

	return ret;
}

static int print_out_fn(int fd, struct scoutfs_ioctl_quota_rule *irule, void *out_args)
{
	printf_rule(irule);
	return 0;
}

/* ---------------------------------------------- */

static int parse_bulk_opt(int key, char *arg, struct argp_state *state)
{
	struct bulk_args *args = state->input;

	switch (key) {
	case 'p':
		args->path = strdup_or_error(state, arg);
		break;
	case 'U':
		args->unsorted = true;
		break;
	case ARGP_KEY_FINI:
		if (!args->path)
			argp_error(state, "must provide file path");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option bulk_options[] = {
	{ "path", 'p', "PATH", 0, "Path to ScoutFS filesystem"},
	{ "unsorted", 'U', NULL, 0, "Process rules in unsorted filesystem storage order"},
	{ NULL }
};

static struct argp list_argp = {
	bulk_options,
	parse_bulk_opt,
	"",
	"List quota rules"
};

static int list_cmd(int argc, char **argv)
{
	struct scoutfs_ioctl_get_quota_rules gqr = {{0,}};
	struct bulk_args args = {NULL};
	int ret;

	ret = argp_parse(&list_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_bulk(&args, get_ioctl_in_fn, &gqr, print_out_fn, NULL);
}

static void __attribute__((constructor)) list_ctor(void)
{
	cmd_register_argp("quota-list", &list_argp, GROUP_CORE, list_cmd);
}

/* ---------------------------------------------- */

static struct argp wipe_argp = {
	bulk_options,
	parse_bulk_opt,
	"",
	"Delete all quota rules"
};

static int wipe_cmd(int argc, char **argv)
{
	struct bulk_args args = {NULL};
	struct scoutfs_ioctl_get_quota_rules gqr = {{0,}};
	struct mod_ioctl_args out_args = {
		.cmd = SCOUTFS_IOC_DEL_QUOTA_RULE,
		.which = "delete",
	};
	int ret;

	ret = argp_parse(&wipe_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_bulk(&args, get_ioctl_in_fn, &gqr, mod_ioctl_out_fn, &out_args);
}

static void __attribute__((constructor)) wipe_ctor(void)
{
	cmd_register_argp("quota-wipe", &wipe_argp, GROUP_CORE, wipe_cmd);
}

/* ---------------------------------------------- */

static struct argp restore_argp = {
	bulk_options,
	parse_bulk_opt,
	"",
	"Restore quota rules from list output on stdin"
};

static int restore_cmd(int argc, char **argv)
{
	struct bulk_args args = {NULL};
	struct mod_ioctl_args out_args = {
		.cmd = SCOUTFS_IOC_ADD_QUOTA_RULE,
		.which = "add",
	};
	int ret;

	ret = argp_parse(&restore_argp, argc, argv, 0, NULL, &args);
	if (ret)
		return ret;

	return do_bulk(&args, parse_stdin_in_fn, NULL, mod_ioctl_out_fn, &out_args);
}

static void __attribute__((constructor)) restore_ctor(void)
{
	cmd_register_argp("quota-restore", &restore_argp, GROUP_CORE, restore_cmd);
}
