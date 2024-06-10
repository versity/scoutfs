#define _GNU_SOURCE
/*
 * mmap() stress test for scoutfs
 *
 * This test exercises the scoutfs kernel module's locking by
 * repeatedly reading/writing using mmap and pread/write calls
 * across 5 clients (mounts).
 *
 * Each thread operates on a single thread/client, and performs
 * operations in a random order on the file.
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
#include <pthread.h>
#include <errno.h>

static int size = 0;
static int count = 0; /* XXX make this duration instead */

struct thread_info {
	int nr;
	int fd;
};

static void *run_test_func(void *ptr)
{
	void *buf = NULL;
	char *addr = NULL;
	struct thread_info *tinfo = ptr;
	int c = 0;
	int fd;
	ssize_t read, written, ret;
	int preads = 0, pwrites = 0, mreads = 0, mwrites = 0;

	fd = tinfo->fd;

	if (posix_memalign(&buf, 4096, size) != 0) {
		perror("calloc");
		exit(-1);
	}

	addr = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	usleep(100000); /* 0.1sec to allow all threads to start roughly at the same time */

	for (;;) {
		if (++c > count)
			break;

		switch (rand() % 4) {
		case 0: /* pread */
			preads++;
			for (read = 0; read < size;) {
				ret = pread(fd, buf, size - read, read);
				if (ret < 0) {
					perror("pwrite");
					exit(-1);
				}
				read += ret;
			}
			break;
		case 1: /* pwrite */
			pwrites++;
			memset(buf, (char)(c & 0xff), size);
			for (written = 0; written < size;) {
				ret = pwrite(fd, buf, size - written, written);
				if (ret < 0) {
					perror("pwrite");
					exit(-1);
				}
				written += ret;
			}
			break;
		case 2: /* mmap read */
			mreads++;
			memcpy(buf, addr, size); /* noerr */
			break;
		case 3: /* mmap write */
			mwrites++;
			memset(buf, (char)(c & 0xff), size);
			memcpy(addr, buf, size); /* noerr */
			break;
		}
	}

	munmap(addr, size);

	free(buf);

	printf("thread %u complete: preads %u pwrites %u mreads %u mwrites %u\n", tinfo->nr,
		mreads, mwrites, preads, pwrites);

	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t thread[5];
	struct thread_info tinfo[5];
	int fd[5];
	int ret;
	int i;

	if (argc != 8) {
		fprintf(stderr, "%s requires 7 arguments - size count file1 file2 file3 file4 file5\n", argv[0]);
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

	/* create and truncate one fd */
	fd[0] = open(argv[3], O_RDWR | O_CREAT | O_TRUNC, 00644);
	if (fd[0] < 0) {
		perror("open");
		exit(-1);
	}

	/* make it the test size */
	if (posix_fallocate(fd[0], 0, size) != 0) {
		perror("fallocate");
		exit(-1);
	}

	/* now open the rest of the fds */
	for (i = 1; i < 5; i++) {
		fd[i] = open(argv[3+i], O_RDWR);
		if (fd[i] < 0) {
			perror("open");
			exit(-1);
		}
	}

	/* start threads */
	for (i = 0; i < 5; i++) {
		tinfo[i].fd = fd[i];
		tinfo[i].nr = i;
		ret = pthread_create(&thread[i], NULL, run_test_func, (void*)&tinfo[i]);

		if (ret) {
			perror("pthread_create");
			exit(-1);
		}
	}

	/* wait for complete */
	for (i = 0; i < 5; i++)
		pthread_join(thread[i], NULL);

	for (i = 0; i < 5; i++)
		close(fd[i]);

	exit(0);
}
