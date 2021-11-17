#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#ifndef RENAMEAT2_EXIST
#include <unistd.h>
#include <sys/syscall.h>

#if !defined(SYS_renameat2) && defined(__x86_64__)
#define SYS_renameat2 316			/* from arch/x86/entry/syscalls/syscall_64.tbl */
#endif

static int renameat2(int olddfd, const char *old_dir,
		     int newdfd, const char *new_dir,
		     unsigned int flags)
{
#ifdef SYS_renameat2
	return syscall(SYS_renameat2, olddfd, old_dir, newdfd, new_dir, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE	(1 << 0)	/* Don't overwrite newpath of rename */
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE		(1 << 1)	/* Exchange oldpath and newpath */
#endif
#ifndef RENAME_WHITEOUT
#define RENAME_WHITEOUT		(1 << 2)	/* Whiteout oldpath */
#endif

static void exit_usage(char **argv)
{
	fprintf(stderr,
		"usage: %s [-n|-x|-w] old_path new_path\n"
		"  -n  noreplace\n"
		"  -x  exchange\n"
		"  -w  whiteout\n", argv[0]);

		exit(1);
}

int main(int argc, char **argv)
{
	const char *old_path = NULL;
	const char *new_path = NULL;
	unsigned int flags = 0;
	int ret;
	int c;

	for (c = 1; c < argc; c++) {
		if (argv[c][0] == '-') {
			switch (argv[c][1]) {
				case 'n':
					flags |= RENAME_NOREPLACE;
					break;
				case 'x':
					flags |= RENAME_EXCHANGE;
					break;
				case 'w':
					flags |= RENAME_WHITEOUT;
					break;
				default:
					exit_usage(argv);
			}
		} else if (!old_path) {
			old_path = argv[c];
		} else if (!new_path) {
			new_path = argv[c];
		} else {
			exit_usage(argv);
		}
	}

	if (!old_path || !new_path) {
		printf("specify the correct directory path\n");
		errno = ENOENT;
		return 1;
	}

	ret = renameat2(AT_FDCWD, old_path, AT_FDCWD, new_path, flags);
	if (ret == -1) {
		perror("Error");
		return 1;
	}

	return 0;
}
