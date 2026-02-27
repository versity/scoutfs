#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define error_exit(cond, fmt, args...)			\
do {							\
	if (cond) {					\
		printf("error: "fmt"\n", ##args);	\
		exit(1);				\
	}						\
} while (0)

#define ERRF " errno %d (%s)"
#define ERRA errno, strerror(errno)

/*
 * Doing setxattr() from a shell a few thousand times takes way too
 * long, hence, this program
 */

static void usage(void)
{
	printf("usage: totl_xattr_fill -d DIR -p PREFIX -n COUNT -v VALUE [-c]\n"
	       " -d DIR     directory containing files\n"
	       " -p PREFIX  file name prefix\n"
	       " -n COUNT   number of files (numbered 1..COUNT)\n"
	       " -v VALUE   xattr value string\n"
	       " -c         create files before setting xattr\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char *dir = NULL;
	char *prefix = NULL;
	char *value = NULL;
	unsigned long count = 0;
	int create = 0;
	char path[4096];
	char name[256];
	unsigned long i;
	int fd;
	int ret;
	int c;

	while ((c = getopt(argc, argv, "d:p:n:v:c")) != -1) {
		switch (c) {
		case 'd':
			dir = optarg;
			break;
		case 'p':
			prefix = optarg;
			break;
		case 'n':
			count = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			value = optarg;
			break;
		case 'c':
			create = 1;
			break;
		case '?':
			usage();
		}
	}

	error_exit(!dir, "must specify directory with -d");
	error_exit(!prefix, "must specify prefix with -p");
	error_exit(!count, "must specify count with -n");
	error_exit(!value, "must specify value with -v");

	for (i = 1; i <= count; i++) {
		ret = snprintf(path, sizeof(path), "%s/%s%lu", dir, prefix, i);
		error_exit(ret >= (int)sizeof(path), "path too long");

		if (create) {
			fd = open(path, O_CREAT | O_WRONLY, 0644);
			error_exit(fd < 0, "open %s failed"ERRF, path, ERRA);
			close(fd);
		}

		ret = snprintf(name, sizeof(name),
			       "scoutfs.totl.test.%lu.0.0", i);
		error_exit(ret >= (int)sizeof(name), "xattr name too long");

		ret = setxattr(path, name, value, strlen(value), 0);
		error_exit(ret, "setxattr %s %s failed"ERRF,
			   path, name, ERRA);
	}

	return 0;
}
