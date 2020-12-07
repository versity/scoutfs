#define _GNU_SOURCE				/* getopt_long_only */
						/* reallocarray */
						/* open_by_handle_at */
#define _ATFILE_SOURCE				/* openat glibc < 2.10 */
#define _POSIX_C_SOURCE		200809L		/* openat glibc >= 2.10 */
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <endian.h>
#include <linux/types.h>

/*
 * We need to test our srch subsystem with a large number of files.  The
 * search_xattrs ioctl prints out a sorted list of inodes which may
 * contain a given xattr.
 *
 * This mimics that behaviour as efficiently as it can.  We walk the
 * name space to find the inode numbers of files to check and then open
 * them in inode number order and print out any that contain the xattr.
 */

#define error_exit(cond, fmt, args...)			\
do {							\
	if (cond) {					\
		printf("error: "fmt"\n", ##args);	\
		exit(1);				\
	}						\
} while (0)

#define ERRF " errno %d (%s)"
#define ERRA errno, strerror(errno)

enum {
	OPT_DIR = 1,
	OPT_MOUNT,
	OPT_NAME,
};

static struct option long_opts[] = {
	{"dir", required_argument, 0,  OPT_DIR},
	{"mount", required_argument, 0,  OPT_MOUNT},
	{"name", required_argument, 0,  OPT_NAME},
};

static void usage(void)
{
	printf("usage:\n"
	       " --dir PATH    | walk files starting with PATH directory\n"
	       " --mount PATH  | open by inode requires fs mount point PATH\n"
	       " --name NAME   | look for xattr named NAME\n");
}

#define GROWTH (4 * 1024 * 1024)
#define NR_LIMIT ((SIZE_MAX - GROWTH) / sizeof(uint64_t))

static void readdir_inos(int dfd, uint64_t **inos, size_t *nr)
{
	struct dirent *dent;
	size_t bytes;
	DIR *dirp;
	int fd;

	dirp = fdopendir(dfd);
	error_exit(dirp == NULL, "fdopendir(%d) failed"ERRF, dfd, ERRA);

	while ((dent = readdir(dirp)) != NULL) {

		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		error_exit(dent->d_type == DT_UNKNOWN,
		           "entry %s has unknown d_type",
			   dent->d_name);

		if (dent->d_type == DT_DIR) {
			/* descend into dir, don't use its ino */
			fd = openat(dfd, dent->d_name, O_RDONLY);
			error_exit(fd < 0,
				   "openat(%d, %s, O_RDONLY) failed"ERRF,
				   dfd, dent->d_name, ERRA);

			readdir_inos(fd, inos, nr);
			close(fd);
		} else {
			/* record ino of all non-directory entries */
			(*inos)[*nr] = dent->d_ino;
			(*nr)++;

			error_exit(*nr == NR_LIMIT,
				   "reached limit of %zu inodes\n",
				   NR_LIMIT);

			if ((*nr % GROWTH) == 0) {
				bytes = (*nr + GROWTH) * sizeof((*inos)[0]);
				*inos = realloc(*inos, bytes);
				error_exit(*inos == NULL,
					   "%zu element ino array failed"ERRF,
					   *nr + GROWTH, ERRA);
			}
		}
	}

	closedir(dirp);
}

#define FILEID_SCOUTFS			0x81
struct our_handle {
	struct file_handle handle;
	__le64 scoutfs_ino;
};

int open_by_ino(int mfd, uint64_t ino)
{
	int fd;
	struct our_handle handle = {
		.handle.handle_bytes = sizeof(struct our_handle),
		.handle.handle_type = FILEID_SCOUTFS,
		.scoutfs_ino = htole64(ino),
	};

	fd = open_by_handle_at(mfd, &handle.handle, O_RDONLY);
	error_exit(fd < 1, "open_by_handle_at(%d, %"PRIu64") failed"ERRF,
		   mfd, ino, ERRA);
	return fd;
}

static int cmp_inos(const void *A, const void *B)
{
	uint64_t a = *(uint64_t *)A;
	uint64_t b = *(uint64_t *)B;

	return a < b ? -1 : b > a ? 1 : 0;
}

int main(int argc, char **argv)
{
	char *dir = NULL;
	char *mount = NULL;
	char *name = NULL;
	uint64_t *inos = NULL;
	size_t nr = 0;
	char junk;
	int dfd;
	int mfd;
	int fd;
	int opt;
	int i;

	while ((opt = getopt_long_only(argc, argv, "", long_opts, NULL)) != -1){
                switch(opt) {
		case OPT_DIR:
                        dir = strdup(optarg);
                        break;
                case OPT_MOUNT:
                        mount = strdup(optarg);
                        break;
                case OPT_NAME:
                        name = strdup(optarg);
                        break;
                case '?':
                        printf("Unknown option '%c'\n", optopt);
                        usage();
			exit(1);
                }
        } 

	error_exit(!dir, "must specify search dir path with -d");
	error_exit(!mount, "must specify mount point path with -m");
	error_exit(!name, "must specify xattr name with -n");

	inos = calloc(GROWTH, sizeof(inos[0]));
	nr = 0;
	error_exit(inos == NULL, "ino array allocation error");

	mfd = open(mount, O_RDONLY);
	error_exit(mfd < 1, "mount open(%s) failed"ERRF, mount, ERRA);

	dfd = open(dir, O_RDONLY);
	error_exit(dfd < 1, "dir open(%s) failed"ERRF, dir, ERRA);

	/* namespace walk to get all the non-dir inode numbers */
	readdir_inos(dfd, &inos, &nr);

	/* sort by inode numbers so accesses are efficient */
	qsort(inos, nr, sizeof(inos[0]), cmp_inos);

	for (i = 0; i < nr; i++) {
		/* hard links can give us duplicate inos */
		if (i > 0 && inos[i - 1] == inos[i])
			continue;

		/* and check each inode for the xattr */
		fd = open_by_ino(mfd, inos[i]);
		if (fgetxattr(fd, name, &junk, 0) >= 0)
			printf("%"PRIu64"\n", inos[i]);
		close(fd);
	}

	close(mfd);
	close(dfd);
	free(dir);
	free(name);

	return 0;
}
