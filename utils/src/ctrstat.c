#define _XOPEN_SOURCE 700 /* 600: floorf, strtof, 700: openat */

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
#include <math.h>
#include <time.h>

#include "util.h"
#include "cmd.h"
#include "list.h"

#define SCOUTFS_SYSFS_PATH "/sys/fs/scoutfs"

struct string_item {
	struct list_head head;
	int dir_fd;
	char *str;
	int len;
};

static int add_string(char *str, struct list_head *list)
{
	struct string_item *sitem;
	int ret = -ENOMEM;

	sitem = malloc(sizeof(struct string_item));
	if (sitem) {
		sitem->str = strdup(str);
		if (sitem->str) {
			sitem->dir_fd = -1;
			list_add_tail(&sitem->head, list);
			sitem->len = strlen(str);
			ret = 0;
		}
	}

	if (ret)
		fprintf(stderr, "failed to alloc mem for string '%s'\n", str);

	return ret;
}

/*
 * Iterate over all the mounted ids and use their open dirfds to open
 * and read each counter.  We have to open each time we want updated counters.
 * We reflect the counter length in the column's label length.
 */
static int read_and_print_counters(struct list_head *labels,
				   struct list_head *id_list, int print)
{
	struct string_item *label;
	struct string_item *id;
	char buf[25];
	ssize_t bytes;
	int ret = 0;
	int fd;

	list_for_each_entry(id, id_list, head) {
		list_for_each_entry(label, labels, head) {
			/* id column */
			if (label->str[0] == '\0') {
				label->len = max(label->len, id->len);
				if (print)
					printf("%*s ", label->len, id->str);
				continue;
			}

			/* have to open each time we want current counter :/ */
			fd = openat(id->dir_fd, label->str, O_RDONLY);
			if (fd < 0) {
				ret = -errno;
				goto out;
			}

			bytes = pread(fd, buf, sizeof(buf), 0);
			close(fd);

			if (bytes <= 1 || bytes >= sizeof(buf) ||
			    buf[bytes - 1] != '\n') {
				fprintf(stderr, "counter file %s/%s read returned %zd\n",
					id->str, label->str, bytes);
				ret = -EIO;
				goto out;
			}

			label->len = max(label->len, bytes - 1);

			if (print) {
				buf[bytes - 1] = '\0';
				printf("%*s ", label->len, buf);
			}
		}
		if (print)
			printf("\n");
	}

out:
	return ret;
}

static int dots(char *name)
{
	return name[0] == '.' &&
	       (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

/*
 * XXX deal with unmount ;)
 */
static int ctrstat_cmd(int argc, char **argv)
{
	struct string_item *label;
	struct string_item *id;
	LIST_HEAD(label_list);
	char path[PATH_MAX];
	LIST_HEAD(id_list);
	struct dirent *dent;
	float seconds = 1.0;
	struct timespec ts;
	DIR *dirp;
	int iter;
	int ret;

	if (argc > 2) {
		printf("scoutfs ctrstat: too many arguments\n");
		return -EINVAL;
	}

	/* set the sleep duration */
	if (argc == 2) {
		seconds = strtof(argv[1], NULL);
		if (fpclassify(seconds) != FP_NORMAL || seconds <= 0) {
			printf("invalid sleep duration float: %s\n", argv[1]);
			return -EINVAL;
		}
	}
	ts.tv_sec = (int)floorf(seconds);
	ts.tv_nsec = (seconds - floorf(seconds)) * 1000000000;

	/* find all the mounted ids */
	dirp = opendir(SCOUTFS_SYSFS_PATH);
	if (!dirp) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			SCOUTFS_SYSFS_PATH, strerror(errno), errno);
		goto out;
	}
	while ((dent = readdir(dirp))) {
		if (dots(dent->d_name))
			continue;
		ret = add_string(dent->d_name, &id_list);
		if (ret)
			goto out;

	}
	closedir(dirp);
	dirp = NULL;

	/* add a dummy label for the id column */
	ret = add_string("", &label_list);
	if (ret)
		goto out;

	iter = 1;
	list_for_each_entry(id, &id_list, head) {
		snprintf(path, PATH_MAX, SCOUTFS_SYSFS_PATH"/%s/counters",
			 id->str);

		dirp = opendir(path);
		if (!dirp) {
			ret = -errno;
			fprintf(stderr, "failed to open '%s': %s (%d)\n",
				path, strerror(errno), errno);
			goto out;
		}

		/* hold a dir fd open for each id */
		id->dir_fd = dup(dirfd(dirp));
		if (id->dir_fd < 0) {
			ret = -errno;
			fprintf(stderr, "couldn't dup fd for '%s': %s (%d)\n",
				path, strerror(errno), errno);
			goto out;
		}

		/* find all the counters, assume all ids have same */
		while (iter && (dent = readdir(dirp))) {
			if (dots(dent->d_name))
				continue;

			ret = add_string(dent->d_name, &label_list);
			if (ret)
				goto out;
		}
		closedir(dirp);
		dirp = NULL;
		iter = 0;
	}

	/* initial read pass to find the max lengths */
	ret = read_and_print_counters(&label_list, &id_list, 0);
	if (ret)
		goto out;

	for (iter = 0; ; iter++) {
		/* print row of column labels */
		if (!(iter % 25)) {
			list_for_each_entry(label, &label_list, head)
				printf("%*s ", label->len, label->str);
			printf("\n");
		}

		/* print each id and its stats */
		ret = read_and_print_counters(&label_list, &id_list, 1);
		if (ret)
			goto out;

		nanosleep(&ts, NULL);
	}
	ret = 0;
out:
	if (dirp)
		closedir(dirp);

	/* squish together and free all */
	list_splice(&label_list, &id_list);
	list_for_each_entry_safe(id, label, &id_list, head) {
		list_del_init(&id->head);
		if (id->dir_fd >= 0)
			close(id->dir_fd);
		free(id);
	}
	return ret;
};

static void __attribute__((constructor)) ctrstat_ctor(void)
{
	cmd_register("ctrstat", "<delay secs>", "print counters over time",
		     ctrstat_cmd);
}
