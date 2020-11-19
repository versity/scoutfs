#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <wordexp.h>

#include "util.h"

static int open_path(char *path, int flags)
{
	wordexp_t exp_result;
	int ret;

	ret = wordexp(path, &exp_result, WRDE_NOCMD | WRDE_SHOWERR | WRDE_UNDEF);
	if (ret) {
		fprintf(stderr, "wordexp() failure for \"%s\": %d\n", path, ret);
		ret = -EINVAL;
		goto out;
	}

	ret = open(exp_result.we_wordv[0], flags);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
	}

out:
	wordfree(&exp_result);

	return ret;
}

/*
 * 1. if path option given, use that
 * 2. if env var, use that
 * 3. if cwd is in a scoutfs fs, use that
 * 4. else error
 */
int get_path(char *path, int flags)
{
	char *env_path;
	char *cur_dir_path;
	int ret;

	if (path)
		return open_path(path, flags);

	env_path = getenv("SCOUTFS_PATH");
	if (env_path)
		return open_path(path, flags);

	cur_dir_path = get_current_dir_name();
	if (!cur_dir_path) {
		ret = -errno;
		return ret;
	}

	ret = open_path(cur_dir_path, flags);
	free(cur_dir_path);

	// TODO: check this is within a scoutfs mount?

	return ret;
}
