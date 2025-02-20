#define _GNU_SOURCE
/*
 * mmap() content consistency checking for scoutfs
 *
 * This test program validates that content from memory mappings
 * are consistent across clients, whether written/read with mmap or
 * normal writes/reads.
 *
 * One side of (read/write) will always be memory mapped. It may
 * be that both sides do memory mapped (33% of the time).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

static int count = 0;
static int size = 0;

static void run_test_func(int fd1, int fd2)
{
	void *buf1 = NULL;
	void *buf2 = NULL;
	char *addr1 = NULL;
	char *addr2 = NULL;
	int c = 0;
	ssize_t read, written, ret;

	/* buffers for both sides to compare */
	if (posix_memalign(&buf1, 4096, size) != 0) {
		perror("calloc1");
		exit(-1);
	}

	if (posix_memalign(&buf2, 4096, size) != 0) {
		perror("calloc1");
		exit(-1);
	}

	/* memory maps for both sides */
	addr1 = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd1, 0);
	if (addr1 == MAP_FAILED) {
		perror("mmap1");
		exit(-1);
	}

	addr2 = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd2, 0);
	if (addr2 == MAP_FAILED) {
		perror("mmap2");
		exit(-1);
	}

	for (;;) {
		if (++c > count) /* 10k iterations */
			break;

		/* put a pattern in buf1 */
		memset(buf1, c & 0xff, size);

		/* pwrite or mmap write from buf1 */
		switch (c % 3) {
		case 0:	/* pwrite */
			for (written = 0; written < size;) {
				ret = pwrite(fd1, buf1, size - written, written);
				if (ret < 0) {
					perror("pwrite");
					exit(-1);
				}
				written += ret;
			}
			break;
		default: /* mmap write */
			memcpy(addr1, buf1, size);
			break;
		}

		/* pread or mmap read to buf2 */
		switch (c % 3) {
		case 2: /* pread */
			for (read = 0; read < size;) {
				ret = pread(fd2, buf2, size - read, read);
				if (ret < 0) {
					perror("pwrite");
					exit(-1);
				}
				read += ret;
			}
			break;
		default: /* mmap read */
			memcpy(buf2, addr2, size);
			break;
		}

		/* compare bufs */
		if (memcmp(buf1, buf2, size) != 0) {
			fprintf(stderr, "memcmp() failed\n");
			exit(-1);
		}
	}

	munmap(addr1, size);
	munmap(addr2, size);

	free(buf1);
	free(buf2);
}

int main(int argc, char **argv)
{
	int fd[1];

	if (argc != 5) {
		fprintf(stderr, "%s requires 4 arguments - size count file1 file2\n", argv[0]);
		exit(-1);
	}

	size = atoi(argv[1]);
	if (size <= 0) {
		fprintf(stderr, "invalid size, must be greater than 0\n");
		exit(-1);
	}

	count = atoi(argv[2]);
	if (count < 3) {
		fprintf(stderr, "invalid count, must be greater than 3\n");
		exit(-1);
	}

	/* create and truncate one fd */
	fd[0] = open(argv[3], O_RDWR | O_CREAT | O_TRUNC, 00644);
	if (fd[0] < 0) {
		perror("open");
		exit(-1);
	}

	fd[1] = open(argv[4], O_RDWR , 00644);
	if (fd[1] < 0) {
		perror("open");
		exit(-1);
	}

	/* make it the test size */
	if (posix_fallocate(fd[0], 0, size) != 0) {
		perror("fallocate");
		exit(-1);
	}

	/* run the test function */
	run_test_func(fd[0], fd[1]);

	close(fd[0]);
	close(fd[1]);

	exit(0);
}
