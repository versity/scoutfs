#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

/*
 *     int setxattr(const char *path, const char *name,
 *                   const void *value, size_t size, int flags);
 */

static void exit_usage(void)
{
	printf(" -h/-?         output this usage message and exit\n"
	       " -c            add XATTR_CREATE to flags\n"
	       " -f <num>      add parsed number to flags (defaults to 0)\n"
	       " -n <string>   xattr name string\n"
	       " -N <num>      raw xattr name pointer\n"
	       " -p <string>   file path string\n"
	       " -P <num>      raw file path pointer\n"
	       " -r            add XATTR_REPLACE to flags\n"
	       " -s <num>      xattr value size (defaults to strlen(-v))\n"
	       " -v <string>   xattr value string\n"
	       " -V <num>      raw xattr value pointer\n");
	exit(1);
}

int main(int argc, char **argv)
{
	unsigned char opts[256] = {0,};
	char *path = NULL;
	char *name = NULL;
	char *value = NULL;
	size_t size = 0;
	int flags = 0;
	int ret;
	int c;

	while ((c = getopt(argc, argv, "+cf:n:N:p:P:s:rv:V:")) != -1) {

		switch (c) {
			case 'c':
				flags |= XATTR_CREATE;
				break;
			case 'f':
				flags |= strtol(optarg, NULL, 0);
				break;
			case 'n':
				name = strdup(optarg);
				break;
			case 'N':
				name = (void *)strtol(optarg, NULL, 0);
				break;
			case 'p':
				path = strdup(optarg);
				break;
			case 'P':
				path = (void *)strtol(optarg, NULL, 0);
				break;
			case 'r':
				flags |= XATTR_REPLACE;
				break;
			case 's':
				size = strtoll(optarg, NULL, 0);
				break;
			case 'v':
				value = strdup(optarg);
				break;
			case 'V':
				value = (void *)strtol(optarg, NULL, 0);
				break;
			case '?':
				printf("unknown argument: %c\n", optind);
			case 'h':
				exit_usage();
		}

		opts[c] = 1;
	}

	if (!opts['p'] && !opts['P']) {
		printf("specify path with -p or raw path pointer with -P\n");
		exit(1);
	}

	if (!opts['n'] && !opts['N']) {
		printf("specify name with -n or raw name pointer with -N\n");
		exit(1);
	}

	if (!opts['v'] && !opts['V']) {
		printf("specify value with -v or raw value pointer with -V\n");
		exit(1);
	}

	if (!opts['s']) {
		if (opts['v']) {
			size = strlen(value);
		} else {
			printf("specify size with -s when using -V\n");
			exit(1);
		}
	}

	ret = setxattr(path, name, value, size, flags);
	if (ret)
		printf("returned %d errno %d (%s)\n",
				ret, errno, strerror(errno));
	else
		printf("returned %d\n", ret);

	return 0;
}
