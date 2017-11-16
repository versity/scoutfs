#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/dlmconstants.h>
#include <getopt.h>

#include "sparse.h"
#include "cmd.h"
#include "util.h"
#include "format.h"
#include "list.h"
#include "dlmglue.h"

static int print_lvbs = 0;
static int oneline = 0;

static char *level_str(int level)
{
	char *s;

	switch (level) {
	case DLM_LOCK_IV:
		s = "IV";
		break;
	case DLM_LOCK_NL:
		s = "NL";
		break;
	case DLM_LOCK_CR:
		s = "CR";
		break;
	case DLM_LOCK_CW:
		s = "CW";
		break;
	case DLM_LOCK_PR:
		s = "PR";
		break;
	case DLM_LOCK_PW:
		s = "PW";
		break;
	case DLM_LOCK_EX:
		s = "EX";
		break;
	default:
		s = "Unknown";
	}

	return s;
}

static void print_flags(unsigned long flags, FILE *out)
{
	if (flags & OCFS2_LOCK_INITIALIZED )
		fprintf(out, " Initialized");

	if (flags & OCFS2_LOCK_ATTACHED)
		fprintf(out, " Attached");

	if (flags & OCFS2_LOCK_BUSY)
		fprintf(out, " Busy");

	if (flags & OCFS2_LOCK_BLOCKED)
		fprintf(out, " Blocked");

	if (flags & OCFS2_LOCK_LOCAL)
		fprintf(out, " Local");

	if (flags & OCFS2_LOCK_NEEDS_REFRESH)
		fprintf(out, " Needs Refresh");

	if (flags & OCFS2_LOCK_REFRESHING)
		fprintf(out, " Refreshing");

	if (flags & OCFS2_LOCK_FREEING)
		fprintf(out, " Freeing");

	if (flags & OCFS2_LOCK_QUEUED)
		fprintf(out, " Queued");
}

static char *action_str(unsigned int action)
{
	char *s;

	switch (action) {
	case OCFS2_AST_INVALID:
		s = "None";
		break;
	case OCFS2_AST_ATTACH:
		s = "Attach";
		break;
	case OCFS2_AST_CONVERT:
		s = "Convert";
		break;
	case OCFS2_AST_DOWNCONVERT:
		s = "Downconvert";
		break;
	default:
		s = "Unknown";
	}

	return s;
}

static char *unlock_action_str(unsigned int unlock_action)
{
	char *s;
	switch (unlock_action) {
	case OCFS2_UNLOCK_INVALID:
		s = "None";
		break;
	case OCFS2_UNLOCK_CANCEL_CONVERT:
		s = "Cancel Convert";
		break;
	case OCFS2_UNLOCK_DROP_LOCK:
		s = "Drop Lock";
		break;
	default:
		s = "Unknown";
	}

	return s;
}

static void dump_raw_lvb(const char *lvb, FILE *out)
{
	int i;

	fprintf(out, "Raw LVB:\t");

	for(i = 0; i < DLM_LVB_LEN; i++) {
		fprintf(out, "%02hhx ", lvb[i]);
		if (!((i+1) % 16) && i != (DLM_LVB_LEN-1))
			fprintf(out, "\n\t\t");
	}
	fprintf(out, "\n");
}

static int end_line(FILE *f)
{
	int ret;

	do {
		ret = fgetc(f);
		if (ret == EOF)
			return 1;
	} while (ret != '\n');

	return 0;
}

/* the printing/scanning code here was modified from ocfs2-tools */
static int print_fields(FILE *file, FILE *out)
{
	char id[OCFS2_LOCK_ID_MAX_LEN + 1];	
	char lvb[DLM_LVB_LEN];
	int ret, i, level, requested, blocking;
	unsigned long flags;
	unsigned int action, unlock_action, cw, ro, ex, dummy;
	const char *format;
	unsigned long long num_prmode, num_exmode, num_cwmode;
	unsigned int num_prmode_failed, num_exmode_failed, num_cwmode_failed;
	unsigned long long  total_prmode, total_exmode, total_cwmode;
	unsigned long long  avg_prmode = 0, avg_exmode = 0, avg_cwmode = 0;
	unsigned int max_prmode, max_exmode, max_cwmode, num_refresh;

	ret = fscanf(file, "%s\t"
		     "%d\t"
		     "0x%lx\t"
		     "0x%x\t"
		     "0x%x\t"
		     "%u\t"
		     "%u\t"
		     "%d\t"
		     "%d\t",
		     id,
		     &level,
		     &flags,
		     &action,
		     &unlock_action,
		     &ro,
		     &ex,
		     &requested,
		     &blocking);
	if (ret != 9) {
		ret = -EINVAL;
		goto out;
	}

	format = "0x%x\t";
	for (i = 0; i < DLM_LVB_LEN; i++) {
		ret = fscanf(file, format, &dummy);
		if (ret != 1) {
			ret = -EINVAL;
			goto out;
		}

		lvb[i] = (char) dummy;
	}

	ret = fscanf(file, "%llu\t"
		     "%llu\t"
		     "%u\t"
		     "%u\t"
		     "%llu\t"
		     "%llu\t"
		     "%u\t"
		     "%u\t"
		     "%u\t"
		     "%u\t"
		     "%llu\t"
		     "%u\t"
		     "%llu\t"
		     "%u",
		     &num_prmode,
		     &num_exmode,
		     &num_prmode_failed,
		     &num_exmode_failed,
		     &total_prmode,
		     &total_exmode,
		     &max_prmode,
		     &max_exmode,
		     &num_refresh,
		     &cw,
		     &num_cwmode,
		     &num_cwmode_failed,
		     &total_cwmode,
		     &max_cwmode);
	if (ret != 14) {
		ret = -EINVAL;
		goto out;
	}

	if (oneline) {
		fprintf(out, "%s mode %s flags", id, level_str(level));
		print_flags(flags, out);
		fprintf(out, " cw/ro/ex %u/%u/%u act %s unlock %s req %s "
			"block %s\n", cw, ro, ex, action_str(action),
			unlock_action_str(unlock_action), level_str(requested),
			level_str(blocking));
		ret = 1;
		goto out;
	}

	fprintf(out, "Lockres: %s  Mode: %s\nFlags:", id, level_str(level));
	print_flags(flags, out);
	fprintf(out, "\nCW Holders: %u  RO Holders: %u  EX Holders: %u\n", cw,
		ro, ex);
	fprintf(out, "Pending Action: %s  Pending Unlock Action: %s\n",
		action_str(action), unlock_action_str(unlock_action));
	fprintf(out, "Requested Mode: %s  Blocking Mode: %s\n",
		level_str(requested), level_str(blocking));

	if (print_lvbs)
		dump_raw_lvb(lvb, out);
#define NSEC_PER_USEC   1000

	if (num_prmode)
		avg_prmode = total_prmode/num_prmode;

	if (num_exmode)
		avg_exmode = total_exmode/num_exmode;

	if (num_cwmode)
		avg_cwmode = total_cwmode/num_cwmode;

	fprintf(out, "CW > Gets: %llu  Fails: %u    Waits Total: %lluus  "
		"Max: %uus  Avg: %lluns\n",
		num_cwmode, num_cwmode_failed, total_cwmode/NSEC_PER_USEC,
		max_cwmode, avg_cwmode);
	fprintf(out, "PR > Gets: %llu  Fails: %u    Waits Total: %lluus  "
		"Max: %uus  Avg: %lluns\n",
		num_prmode, num_prmode_failed, total_prmode/NSEC_PER_USEC,
		max_prmode, avg_prmode);
	fprintf(out, "EX > Gets: %llu  Fails: %u    Waits Total: %lluus  "
		"Max: %uus  Avg: %lluns\n",
		num_exmode, num_exmode_failed, total_exmode/NSEC_PER_USEC,
		max_exmode, avg_exmode);
	fprintf(out, "Disk Refreshes: %u\n", num_refresh);

	ret = 1;
out:
	return ret;
}

#define CURRENT_PROTO 4
static void print_locks(int fd)
{
	FILE *file = fdopen(fd, "r");
	unsigned int version;
	int ret;

	if (!file)
		return;

	do {
		/*
		 * Version is printed on every line (silly but easy to
		 * implement)
		 */
		ret = fscanf(file, "%x\t", &version);
		if (ret != 1)
			goto out;

		if (version > CURRENT_PROTO) {
			fprintf(stdout,
				"Lock debug proto is %u, but %u is the "
				"highest I understand.\n", version,
				CURRENT_PROTO);
			goto out;
		}

		ret = print_fields(file, stdout);

		/* Read to the end of the record here. Any new fields tagged
		 * onto the current format will be silently ignored. */
	} while (!end_line(file));

out:
	fclose(file);
}

static int get_fsid(int fd, u64 *fsid)
{
	struct scoutfs_super_block *super;

	super = read_block(fd, SCOUTFS_SUPER_BLKNO);
	if (!super)
		return -ENOMEM;

	*fsid = le64_to_cpu(super->hdr.fsid);

	return 0;
}

static int locks_func(int argc, char *argv[])
{
	char sysfs[PATH_MAX];
	char *path;
	u64 fsid;
	int ret;
	int fd;
	int c = 10000;

	static struct option long_ops[] = {
		{ "oneline", 0, NULL, 'o' },
		{ "lvbs=", 1, NULL, 'L'},
		{ NULL, 0, NULL, 0}
	};

	if (argc < 1) {
		printf("scoutfs: locks: a device argument is required\n");
		return -EINVAL;
	}

	while ((c = getopt_long(argc, argv, "l:", long_ops, NULL))
	       != -1) {
		switch (c) {
		case 'o':
			oneline = 1;
			break;
		case 'l':
		case 'L':
			if (strcasecmp(optarg, "yes") == 0)
				print_lvbs = 1;
			else if (strcasecmp(optarg, "no") == 0)
				print_lvbs = 0;
			break;
		default:
			return -EINVAL;
		}
	}
	path = argv[optind];

	/* XXX: Take mountpoint argument instead and turn that into a
	 * device for below */

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	ret = get_fsid(fd, &fsid);
	close(fd);
	if (ret)
		return ret;

	/* open sysfs file, print now */
	snprintf(sysfs, PATH_MAX,
		 "/sys/kernel/debug/scoutfs/%llx/locking_state", fsid);

	fd = open(sysfs, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n", sysfs,
			strerror(errno), errno);
		return ret;
	}

	print_locks(fd);

	close(fd);

	return 0;
}

static void __attribute__((constructor)) locks_ctor(void)
{
	cmd_register("locks", "--lvbs=[yes|no] --oneline <path>",
		     "show file system locking state", locks_func);
}
