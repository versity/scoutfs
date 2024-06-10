#define _GNU_SOURCE
/*
 * mmap() stress test for scoutfs
 *
 * This test exercises the scoutfs kernel module's locking by
 * repeatedly reading/writing using mmap and pread/write calls
 * across 2 clients (mounts) on the same file.
 *
 * The goal is to assure that locking between _page_mkwrite vfs
 * calls and the normal read/write paths do not cause deadlocks.
 *
 * There is no content validation performed. All that is done is
 * assure that the programs continues without errors.
 */

#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>

int main(int argc, char **argv)
{
	void *buf = NULL;
	int fd_in, fd_out;
	char *addr_in = NULL, *addr_out = NULL;
	int i = 0, c = 0;
	ssize_t read, written, ret;
	int size, count;
	bool nl = false;

	if (argc != 5) {
		fprintf(stderr, "%s requires 4 arguments - size count infile outfile\n", argv[0]);
		exit(-1);
	}

	size = atoi(argv[1]);
	if (size <= 0) {
		fprintf(stderr, "invalid size, must be greater than 0\n");
		exit(-1);
	}

	count = atoi(argv[2]);
	if (count < 0) {
		fprintf(stderr, "invalid count, must be greater than 0\n");
		exit(-1);
	}

	fd_in = open(argv[3], O_RDWR | O_CREAT | O_TRUNC, 00644); /* create and truncate it */
	if (fd_in < 0) {
		perror("open");
		exit(-1);
	}

	/* make it the test size */
	if (posix_fallocate(fd_in, 0, count) != 0) {
		perror("fallocate");
		exit(-1);
	}

	fd_out = open(argv[4], O_RDWR);
	if (fd_out < 0) {
		perror("open");
		exit(-1);
	}

	if (posix_memalign(&buf, 4096, count) != 0) {
		perror("calloc");
		exit(-1);
	}

	/* create mmap()ings to both files */
	addr_in = mmap(NULL, count, PROT_WRITE | PROT_READ, MAP_SHARED, fd_in, 0);
	if (addr_in == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	addr_out = mmap(NULL, count, PROT_WRITE | PROT_READ, MAP_SHARED, fd_out, 0);
	if (addr_out == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	for (;;) {
		if (++c > count)
			break;

		/* simple rotating pattern, otherwise it's too boring */
		memset(buf, (char)(c & 0xff), count);

		i = c % 3; /* 0, 1, or 2 */

		if ((c % 64) == 0) {
			nl = true;
			fprintf(stdout, ".");
			fflush(stdout);
		}
		if ((c % (64 * 80)) == 0) {
			nl = false;
			fprintf(stdout, "\n");
			fflush(stdout);
		}

		/* write */
		if (i == 0) {
			for (written = 0; written < count;) {
				ret = pwrite(fd_in, buf, count - written, written);
				if (ret < 0) {
					perror("pwrite");
					exit(-1);
				}
				written += ret;
			}
		} else /* 1, 2 */
			memcpy(addr_in, buf, count); /* noerr */

		/* read back */
		if (i == 2) {
			for (read = 0; read < count;) {
				ret = pread(fd_in, buf, count - read, read);
				if (ret < 0) {
					perror("pwrite");
					exit(-1);
				}
				read += ret;
			}
		} else /* 0, 1 */
			memcpy(buf, addr_out, count); /* noerr */

	}

	if (nl)
		fprintf(stdout, "\n");

	close(fd_in);
	close(fd_out);

	free(buf);

	exit(0);
}
