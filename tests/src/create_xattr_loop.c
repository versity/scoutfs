#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static void exit_usage(void)
{
	printf(" -h/-?         output this usage message and exit\n"
	       " -c <count>    number of xattrs to create\n"
	       " -n <string>   xattr name prefix, -NR is appended\n"
	       " -p <path>     string with path to file with xattrs\n" 
	       " -s <size>     xattr value size\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char *pref = NULL;
	char *path = NULL;
	char *val;
	char *name;
	unsigned long long count = 0;
	unsigned long long size = 0;
	unsigned long long i;
	int ret;
	int c;

	while ((c = getopt(argc, argv, "+c:n:p:s:")) != -1) {

		switch (c) {
			case 'c':
				count = strtoull(optarg, NULL, 0);
				break;
			case 'n':
				pref = strdup(optarg);
				break;
			case 'p':
				path = strdup(optarg);
				break;
			case 's':
				size = strtoull(optarg, NULL, 0);
				break;
			case '?':
				printf("unknown argument: %c\n", optind);
			case 'h':
				exit_usage();
		}
	}

	if (count == 0) {
		printf("specify count of xattrs to create with -c\n");
		exit(1);
	}

	if (count == ULLONG_MAX) {
		printf("invalid -c count\n");
		exit(1);
	}

	if (size == 0) {
		printf("specify xattrs value size with -s\n");
		exit(1);
	}

	if (size == ULLONG_MAX || size < 2) {
		printf("invalid -s size\n");
		exit(1);
	}

	if (path == NULL) {
		printf("specify path to file with -p\n");
		exit(1);
	}

	if (pref == NULL) {
		printf("specify xattr name prefix string with -n\n");
		exit(1);
	}

	ret = snprintf(NULL, 0, "%s-%llu", pref, ULLONG_MAX) + 1;
	name = malloc(ret);
	if (!name) {
		printf("couldn't allocate xattr name buffer\n");
		exit(1);
	}

	val = malloc(size);
	if (!val) {
		printf("couldn't allocate xattr value buffer\n");
		exit(1);
	}

	memset(val, 'a', size - 1);
	val[size - 1] = '\0';

	for (i = 0; i < count; i++) {
		sprintf(name, "%s-%llu", pref, i);

		ret = setxattr(path, name, val, size, 0);
		if (ret) {
			printf("returned %d errno %d (%s)\n",
					ret, errno, strerror(errno));
			return 1;
		}
	}

	return 0;
}
