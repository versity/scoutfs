#define _XOPEN_SOURCE 700 /* openat */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "util.h"
#include "cmd.h"

struct counter {
	char *name;
	char *val;
	unsigned int name_wid;
	unsigned int val_wid;
};

static int dots(char *name)
{
	return name[0] == '.' &&
	       (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static int cmp_counter_names(const void *A, const void *B)
{
	const struct counter *a = A;
	const struct counter *b = B;

	return strcmp(a->name, b->name);
}

static int counters_cmd(int argc, char **argv)
{
	unsigned int *name_wid = NULL;
	unsigned int *val_wid = NULL;
	struct counter *ctrs = NULL;
	struct counter *ctr;
	char path[PATH_MAX + 1];
	unsigned int alloced = 0;
	unsigned int min_rows;
	unsigned int max_rows;
	unsigned int rows = 0;
	unsigned int cols = 0;
	unsigned int nr = 0;
	char *dir_arg = NULL;
	struct dirent *dent;
	bool table = false;
	struct winsize ws;
	DIR *dirp = NULL;
	int dir_fd = -1;
	char buf[25];
	int room;
	int ret;
	int fd;
	int i;
	int r;
	int c;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-t") == 0)
			table = true;
		else
			dir_arg = argv[i];
	}

	ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
	if (ret < 0)
		ret = ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
	if (ret < 0)
		table = false;

	if (dir_arg == NULL) {
		printf("scoutfs counter-table: need mount sysfs dir (i.e. /sys/fs/scoutfs/$fr)\n");
		return -EINVAL;
	}

	ret = snprintf(path, PATH_MAX, "%s/counters", dir_arg);
	if (ret < 1 || ret >= PATH_MAX) {
		ret = -EINVAL;
		fprintf(stderr, "invalid counter dir path '%s'\n", dir_arg);
		goto out;
	}

	dirp = opendir(path);
	if (!dirp) {
		ret = -errno;
		fprintf(stderr, "failed to open sysfs counter dir '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	dir_fd = dup(dirfd(dirp));
	if (dir_fd < 0) {
		ret = -errno;
		fprintf(stderr, "couldn't dup fd for path '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	/* read all the counters */
	while ((dent = readdir(dirp))) {
		if (dots(dent->d_name))
			continue;
		if (nr == alloced) {
			alloced += 100;
			ctrs = realloc(ctrs, alloced * sizeof(*ctrs));
			name_wid = realloc(name_wid, alloced * sizeof(*name_wid));
			val_wid = realloc(val_wid, alloced * sizeof(*val_wid));
			if (!ctrs || !name_wid || !val_wid) {
				fprintf(stderr, "counter array allocation error\n");
				ret = -ENOMEM;
				goto out;
			}
			memset(&ctrs[nr], 0, (alloced - nr) * sizeof(*ctrs));
		}

		ctr = &ctrs[nr];

		ctr->name = strdup(dent->d_name);
		if (ctr->name == NULL) {
			fprintf(stderr, "name string allocation error\n");
			ret = -ENOMEM;
			goto out;
		}

		fd = openat(dir_fd, ctr->name, O_RDONLY);
		if (fd < 0) {
			ret = -errno;
			fprintf(stderr, "failed to open counter file '%s/%s': %s (%d)\n",
				path, ctr->name, strerror(errno), errno);
			goto out;
		}

		ret = pread(fd, buf, sizeof(buf), 0);
		close(fd);

		if (ret <= 1 || ret >= sizeof(buf) || buf[ret - 1] != '\n') {
			fprintf(stderr, "counter file %s/%s read returned %d\n",
				path, ctr->name, ret);
			ret = -EIO;
			goto out;
		}

		buf[ret - 1] = '\0';
		ctr->val = strdup(buf);
		if (ctr->val == NULL) {
			fprintf(stderr, "value string allocation error\n");
			ret = -ENOMEM;
			goto out;
		}

		ctr->name_wid = strlen(ctr->name);
		ctr->val_wid = strlen(ctr->val);

		name_wid[0] = max(ctr->name_wid, name_wid[0]);
		val_wid[0] = max(ctr->val_wid, val_wid[0]);

		nr++;
	}
	closedir(dirp);
	dirp = NULL;
	close(dir_fd);
	dir_fd = -1;

	/* huh, empty counter dir */
	if (nr == 0) {
		ret = 0;
		goto out;
	}

	/* sort counters by name */
	qsort(ctrs, nr, sizeof(ctrs[0]), cmp_counter_names);

	/*
	 * If we're packing the counters into a table that fills the
	 * width of the terminal then there will be a smallest number of
	 * rows in the table that packs counters into columns that fill
	 * the width of the terminal.  We perform a binary search for
	 * that smallest number of rows that doesn't fill too many
	 * columns.
	 *
	 * Unless we're not outputting a table, then we just spit out
	 * one column of counters and use the max field widths from the
	 * initial counter reads.
	 */
	if (table) {
		min_rows = 1;
		cols = ws.ws_col / (name_wid[0] + 1 + val_wid[0] + 2);
		max_rows = nr / cols;
	} else {
		rows = nr;
		cols = 1;
		min_rows = nr + 1;
		max_rows = nr - 1;
	}

	while (min_rows <= max_rows) {
		rows = min_rows + ((max_rows - min_rows) / 2);
		i = 0;
		room = ws.ws_col;

		/*
		 * Iterate over counters, storing the max field widths
		 * of each column, recording the column chars left in
		 * the terminal, stopping if we fill too many columns
		 * for the terminal.
		 */
		for (c = 0; i < nr && room >= 0; c++) {
			name_wid[c] = 0;
			val_wid[c] = 0;

			for (r = 0; r < rows && i < nr; r++, i++) {
				ctr = &ctrs[i];

				name_wid[c] = max(ctr->name_wid, name_wid[c]);
				val_wid[c] = max(ctr->val_wid, val_wid[c]);
			}

			cols = c + 1;
			if (c > 0)
				room -= 2;
			room -= name_wid[c] + 1 + val_wid[c];
		}

		if (room < 0) {
			/* need more rows if we ran out of cols */
			min_rows = rows + 1;
		} else {
			/* see if we can get away with fewer */
			if (max_rows == rows)
				break;
			max_rows = rows;
		}
	}

	/* finally output the columns in each row */ 
	for (r = 0; r < rows; r++) {
		for (c = 0; c < cols; c++) {
			i = (c * rows) + r;
			if (i >= nr)
				break;
			ctr = &ctrs[i];

			printf("%s%-*s %*s",
			       c > 0 ? "  " : "",
			       name_wid[c], ctr->name,
			       val_wid[c], ctr->val);
		}
		printf("\n");
	}

	ret = 0;
out:
	if (dirp)
		closedir(dirp);
	if (dir_fd >= 0)
		close(dir_fd);
	if (ctrs) {
		for (i = 0; i < alloced; i++) {
			free(ctrs[i].name);
			free(ctrs[i].val);
		}
		free(ctrs);
	}
	free(name_wid);
	free(val_wid);

	return ret;
};

static void __attribute__((constructor)) counters_ctor(void)
{
	cmd_register("counters", "[-t] <sysfs dir>",
		     "show [tablular] counters for a given mounted volume",
		     counters_cmd);
}
