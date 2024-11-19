#define _GNU_SOURCE /* O_DIRECT */
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/socket.h>

#include "../../utils/src/sparse.h"
#include "../../utils/src/util.h"
#include "../../utils/src/list.h"
#include "../../utils/src/parse.h"
#include "../../kmod/src/format.h"
#include "../../utils/src/parallel_restore.h"

/*
 * XXX:
 *  - add a nice description of what's going on
 *  - mention allocator contention
 *  - test child process dying handling
 *  - root dir entry name length is wrong
 */

#define ERRF " errno %d (%s)"
#define ERRA errno, strerror(errno)

#define error_exit(cond, fmt, args...)			\
do {							\
	if (cond) {					\
		printf("error: "fmt"\n", ##args);	\
		exit(1);				\
	}						\
} while (0)

#define dprintf(fmt, args...)		\
do {					\
	if (0)				\
		printf(fmt, ##args);	\
} while (0)

#define REG_MODE (S_IFREG | 0644)
#define DIR_MODE (S_IFDIR | 0755)

struct opts {
	unsigned long long buf_size;

	unsigned long long write_batch;
	unsigned long long low_dirs;
	unsigned long long high_dirs;
	unsigned long long low_files;
	unsigned long long high_files;
	char *meta_path;
	unsigned long long total_files;
	bool read_only;
	unsigned long long seed;
	unsigned long long nr_writers;
};

struct scoutfs_parallel_restore_quota_rule template_rule = {
	.limit = 33,
	.prio = 7,
	.op = 0,
	.rule_flags = 0,
	.names[0] = (struct quota_rule_name){ .val = 13, .source = 0, .flags = 0},
	.names[1] = (struct quota_rule_name){ .val = 15, .source = 0, .flags = 0},
	.names[2] = (struct quota_rule_name){ .val = 17, .source = 0, .flags = 0},
	.value = "7 13,L,- 15,L,- 17,L,- I 33 -",
	.value_len = 8,
};

static void usage(void)
{
	printf("usage:\n"
	       " -b NR       | threads write blocks in batches files (100000)\n"
	       " -d LOW:HIGH | range of subdirs per directory (5:10)\n"
	       " -f LOW:HIGH | range of files per directory (10:20)\n"
	       " -m PATH     | path to metadata device\n"
	       " -n NR       | total number of files to create (100)\n"
	       " -r          | read-only, all work except writing, measure cpu cost\n"
	       " -s NR       | randomization seed (random)\n"
	       " -w NR       | number of writing processes to fork (online cpus)\n"
	       );
}

static size_t write_bufs(struct opts *opts, struct scoutfs_parallel_restore_writer *wri,
			 void *buf, size_t buf_size, int dev_fd)
{
	size_t total = 0;
	size_t count;
	off_t off;
	int ret;

	do {
		ret = scoutfs_parallel_restore_write_buf(wri, buf, buf_size, &off, &count);
		error_exit(ret, "write buf %d", ret);

		if (count > 0) {
			if (!opts->read_only)
				ret = pwrite(dev_fd, buf, count, off);
			else
				ret = count;
			error_exit(ret != count, "pwrite count %zu ret %d", count, ret);
			total += ret;
		}
	} while (count > 0);

	return total;
}

struct gen_inode {
	struct scoutfs_parallel_restore_inode inode;
	struct scoutfs_parallel_restore_xattr **xattrs;
	u64 nr_xattrs;
	struct scoutfs_parallel_restore_entry **entries;
	u64 nr_files;
	u64 nr_entries;
};

static void free_gino(struct gen_inode *gino)
{
	u64 i;

	if (gino) {
		if (gino->entries) {
			for (i = 0; i < gino->nr_entries; i++)
				free(gino->entries[i]);
			free(gino->entries);
		}
		if (gino->xattrs) {
			for (i = 0; i < gino->nr_xattrs; i++)
				free(gino->xattrs[i]);
			free(gino->xattrs);
		}
		free(gino);
	}
}

static struct scoutfs_parallel_restore_xattr *
generate_xattr(struct opts *opts, u64 ino, u64 pos, char *name, int name_len, void *value,
		int value_len)
{
	struct scoutfs_parallel_restore_xattr *xattr;

	xattr = malloc(sizeof(struct scoutfs_parallel_restore_xattr) + name_len + value_len);
	error_exit(!xattr, "error allocating generated xattr");

	*xattr = (struct scoutfs_parallel_restore_xattr) {
		.ino = ino,
		.pos = pos,
		.name_len = name_len,
		.value_len = value_len,
	};

	xattr->name = (void *)(xattr + 1);
	xattr->value = (void *)(xattr->name + name_len);

	memcpy(xattr->name, name, name_len);
	if (value_len)
		memcpy(xattr->value, value, value_len);

	return xattr;
}

static struct gen_inode *generate_inode(struct opts *opts, u64 ino, mode_t mode)
{
	struct gen_inode *gino;
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);

	gino = calloc(1, sizeof(struct gen_inode));
	error_exit(!gino, "failure allocating generated inode");

	gino->inode = (struct scoutfs_parallel_restore_inode) {
		.ino = ino,
		.meta_seq = ino,
		.data_seq = 0,
		.mode = mode,
		.atime = now,
		.ctime = now,
		.mtime = now,
		.crtime = now,
	};

	/*
	 * hacky creation of a bunch of xattrs for now.
	 */
	if ((mode & S_IFMT) == S_IFREG) {
		#define NV(n, v) { n, sizeof(n) - 1, v, sizeof(v) - 1, }
		struct name_val {
			char *name;
			int len;
			char *value;
			int value_len;
		} nv[] = {
			NV("scoutfs.hide.totl.acct.8314611887310466424.2.0", "1"),
			NV("scoutfs.hide.srch.sam_vol_E01001L6_4", ""),
			NV("scoutfs.hide.sam_reqcopies", ""),
			NV("scoutfs.hide.sam_copy_2", ""),
			NV("scoutfs.hide.totl.acct.F01030L6.8314611887310466424.7.30", "1"),
			NV("scoutfs.hide.sam_copy_1", ""),
			NV("scoutfs.hide.srch.sam_vol_F01030L6_4", ""),
			NV("scoutfs.hide.srch.sam_release_cand", ""),
			NV("scoutfs.hide.sam_restime", ""),
			NV("scoutfs.hide.sam_uuid", ""),
			NV("scoutfs.hide.totl.acct.8314611887310466424.3.0", "1"),
			NV("scoutfs.hide.srch.sam_vol_F01030L6", ""),
			NV("scoutfs.hide.srch.sam_uuid_865939b7-24d6-472f-b85c-7ce7afeb813a", ""),
			NV("scoutfs.hide.srch.sam_vol_E01001L6", ""),
			NV("scoutfs.hide.totl.acct.E01001L6.8314611887310466424.7.1", "1"),
			NV("scoutfs.hide.totl.acct.8314611887310466424.4.0", "1"),
			NV("scoutfs.hide.totl.acct.8314611887310466424.11.0", "1"),
			NV("scoutfs.hide.totl.acct.8314611887310466424.1.0", "1"),
		};
		unsigned int nr = array_size(nv);
		int i;

		gino->xattrs = calloc(nr, sizeof(struct scoutfs_parallel_restore_xattr *));

		for (i = 0; i < nr; i++)
			gino->xattrs[i] = generate_xattr(opts, ino, i, nv[i].name, nv[i].len,
							 nv[i].value, nv[i].value_len);
		gino->nr_xattrs = nr;
		gino->inode.nr_xattrs = nr;

		gino->inode.size = 4096;
		gino->inode.offline = true;
	}

	return gino;
}

static struct scoutfs_parallel_restore_entry *
generate_entry(struct opts *opts, char *prefix, u64 nr, u64 dir_ino, u64 pos, u64 ino, mode_t mode)
{
	struct scoutfs_parallel_restore_entry *entry;
	char buf[PATH_MAX];
	int bytes;

	bytes = snprintf(buf, sizeof(buf), "%s-%llu", prefix, nr);

	entry = malloc(sizeof(struct scoutfs_parallel_restore_entry) + bytes);
	error_exit(!entry, "error allocating generated entry");

	*entry = (struct scoutfs_parallel_restore_entry) {
		.dir_ino = dir_ino,
		.pos = pos,
		.ino = ino,
		.mode = mode,
		.name = (void *)(entry + 1),
		.name_len = bytes,
	};

	memcpy(entry->name, buf, bytes);

	return entry;
}

static u64 random64(void)
{
	return ((u64)lrand48() << 32) | lrand48();
}

static u64 random_range(u64 low, u64 high)
{
	return low + (random64() % (high - low + 1));
}

static struct gen_inode *generate_dir(struct opts *opts, u64 dir_ino, u64 ino_start, u64 ino_len,
				      bool no_dirs)
{
	struct scoutfs_parallel_restore_entry *entry;
	struct gen_inode *gino;
	u64 nr_entries;
	u64 nr_files;
	u64 nr_dirs;
	u64 ino;
	char *prefix;
	mode_t mode;
	u64 i;

	nr_dirs = no_dirs ? 0 : random_range(opts->low_dirs, opts->high_dirs);
	nr_files = random_range(opts->low_files, opts->high_files);

	if (1 + nr_dirs + nr_files > ino_len) {
		nr_dirs = no_dirs ? 0 : (ino_len - 1) / 2;
		nr_files = (ino_len - 1) - nr_dirs;
	}

	nr_entries = nr_dirs + nr_files;

	gino = generate_inode(opts, dir_ino, DIR_MODE);
	error_exit(!gino, "error allocating generated inode");

	gino->inode.nr_subdirs = nr_dirs;
	gino->nr_files = nr_files;

	if (nr_entries) {
		gino->entries = calloc(nr_entries, sizeof(struct scoutfs_parallel_restore_entry *));
		error_exit(!gino->entries, "error allocating generated inode entries");

		gino->nr_entries = nr_entries;
	}

	mode = DIR_MODE;
	prefix = "dir";
	for (i = 0; i < nr_entries; i++) {
		if (i == nr_dirs) {
			mode = REG_MODE;
			prefix = "file";
		}

		ino = ino_start + i;
		entry = generate_entry(opts, prefix, ino, gino->inode.ino,
				       SCOUTFS_DIRENT_FIRST_POS + i, ino, mode);

		gino->entries[i] = entry;
		gino->inode.total_entry_name_bytes += entry->name_len;
	}

	return gino;
}

/*
 * Restore a generated inode.  If it's a directory then we also restore
 * all its entries.  The caller is going to descend into subdir entries and generate
 * those dir inodes.  We have to generate and restore all non-dir inodes referenced
 * by this inode's entries.
 */
static void restore_inode(struct opts *opts, struct scoutfs_parallel_restore_writer *wri,
			  struct gen_inode *gino)
{
	struct gen_inode *nondir;
	int ret;
	u64 i;

	ret = scoutfs_parallel_restore_add_inode(wri, &gino->inode);
	error_exit(ret, "thread add root inode %d", ret);

	for (i = 0; i < gino->nr_entries; i++) {
		ret = scoutfs_parallel_restore_add_entry(wri, gino->entries[i]);
		error_exit(ret, "thread add entry %d", ret);

		/* caller only needs subdir entries, generate and free others */
		if ((gino->entries[i]->mode & S_IFMT) != S_IFDIR) {

			nondir = generate_inode(opts, gino->entries[i]->ino,
						gino->entries[i]->mode);
			restore_inode(opts, wri, nondir);
			free_gino(nondir);

			free(gino->entries[i]);
			if (i != gino->nr_entries - 1)
				gino->entries[i] = gino->entries[gino->nr_entries - 1];
			gino->nr_entries--;
			gino->nr_files--;
			i--;
		}
	}

	for (i = 0; i < gino->nr_xattrs; i++) {
		ret = scoutfs_parallel_restore_add_xattr(wri, gino->xattrs[i]);
		error_exit(ret, "thread add xattr %d", ret);
	}
}

struct writer_args {
	struct list_head head;

	int dev_fd;
	int pair_fd;

	struct scoutfs_parallel_restore_slice slice;
	u64 writer_nr;
	u64 dir_height;
	u64 ino_start;
	u64 ino_len;
};

struct write_result {
	struct scoutfs_parallel_restore_progress prog;
	struct scoutfs_parallel_restore_slice slice;
	__le64 files_created;
	__le64 bytes_written;
};

static void write_bufs_and_send(struct opts *opts, struct scoutfs_parallel_restore_writer *wri,
				  void *buf, size_t buf_size, int dev_fd,
				  struct write_result *res, bool get_slice, int pair_fd)
{
	size_t total;
	int ret;

	total = write_bufs(opts, wri, buf, buf_size, dev_fd);
	le64_add_cpu(&res->bytes_written, total);

	ret = scoutfs_parallel_restore_get_progress(wri, &res->prog);
	error_exit(ret, "get prog %d", ret);

	if (get_slice) {
		ret = scoutfs_parallel_restore_get_slice(wri, &res->slice);
		error_exit(ret, "thread get slice %d", ret);
	}

	ret = write(pair_fd, res, sizeof(struct write_result));
	error_exit(ret != sizeof(struct write_result), "result send error");

	memset(res, 0, sizeof(struct write_result));
}

/*
 * Calculate the number of bytes in toplevel "dir-%llu" entry names for the given
 * number of writers.
 */
static u64 topdir_entry_bytes(u64 nr_writers)
{
	u64 bytes = (3 + 1) * nr_writers;
	u64 limit;
	u64 done;
	u64 wid;
	u64 nr;

	for (done = 0, wid = 1, limit = 10; done < nr_writers; done += nr, wid++, limit *= 10) {
		nr = min(limit - done, nr_writers - done);
		bytes += nr * wid;
	}

	return bytes;
}

struct dir_pos {
	struct gen_inode *gino;
	u64 pos;
};

static void writer_proc(struct opts *opts, struct writer_args *args)
{
	struct scoutfs_parallel_restore_writer *wri = NULL;
	struct scoutfs_parallel_restore_entry *entry;
	struct dir_pos *dirs = NULL;
	struct write_result res;
	struct gen_inode *gino;
	void *buf = NULL;
	u64 level;
	u64 ino;
	int ret;

	memset(&res, 0, sizeof(res));

	dirs = calloc(args->dir_height, sizeof(struct dir_pos));
	error_exit(errno, "error allocating parent dirs "ERRF, ERRA);

	errno = posix_memalign((void **)&buf, 4096, opts->buf_size);
	error_exit(errno, "error allocating block buf "ERRF, ERRA);

	ret = scoutfs_parallel_restore_create_writer(&wri);
	error_exit(ret, "create writer %d", ret);

	ret = scoutfs_parallel_restore_add_slice(wri, &args->slice);
	error_exit(ret, "add slice %d", ret);

	/* writer 0 creates the root dir */
	if (args->writer_nr == 0) {
		ret = scoutfs_parallel_restore_add_quota_rule(wri, &template_rule);
		error_exit(ret, "add quotas %d", ret);

		gino = generate_inode(opts, SCOUTFS_ROOT_INO, DIR_MODE);
		gino->inode.nr_subdirs = opts->nr_writers;
		gino->inode.total_entry_name_bytes = topdir_entry_bytes(opts->nr_writers);

		ret = scoutfs_parallel_restore_add_inode(wri, &gino->inode);
		error_exit(ret, "thread add root inode %d", ret);
		free_gino(gino);
	}

	/* create root entry for our top level dir */
	ino = args->ino_start++;
	args->ino_len--;

	entry = generate_entry(opts, "top", args->writer_nr,
			       SCOUTFS_ROOT_INO, SCOUTFS_DIRENT_FIRST_POS + args->writer_nr,
			       ino, DIR_MODE);

	ret = scoutfs_parallel_restore_add_entry(wri, entry);
	error_exit(ret, "thread top entry %d", ret);
	free(entry);

	level = args->dir_height - 1;

	while (args->ino_len > 0 && level < args->dir_height) {
		gino = dirs[level].gino;

		/* generate and restore if we follow entries */
		if (!gino) {
			gino = generate_dir(opts, ino, args->ino_start, args->ino_len, level == 0);
			args->ino_start += gino->nr_entries;
			args->ino_len -= gino->nr_entries;
			le64_add_cpu(&res.files_created, gino->nr_files);

			restore_inode(opts, wri, gino);
			dirs[level].gino = gino;
		}

		if (dirs[level].pos == gino->nr_entries) {
			/* ascend if we're done with this dir */
			dirs[level].gino = NULL;
			dirs[level].pos = 0;
			free_gino(gino);
			level++;

		} else {
			/* otherwise descend into subdir entry */
			ino = gino->entries[dirs[level].pos]->ino;
			dirs[level].pos++;
			level--;
		}

		/* do a partial write at batch intervals when there's still more to do */
		if (le64_to_cpu(res.files_created) >= opts->write_batch && args->ino_len > 0)
			write_bufs_and_send(opts, wri, buf, opts->buf_size, args->dev_fd,
					    &res, false, args->pair_fd);
	}

	write_bufs_and_send(opts, wri, buf, opts->buf_size, args->dev_fd,
			    &res, true, args->pair_fd);

	scoutfs_parallel_restore_destroy_writer(&wri);

	free(dirs);
	free(buf);
}

/*
 * If any of our children exited with an error code, we hard exit.
 * The child processes should themselves report out any errors
 * encountered. Any remaining children will receive SIGHUP and
 * terminate.
 */
static void sigchld_handler(int signo, siginfo_t *info, void *context)
{
	if (info->si_status)
		exit(EXIT_FAILURE);
}

static void fork_writer(struct opts *opts, struct writer_args *args)
{
	pid_t parent = getpid();
	pid_t pid;
	int ret;

	pid = fork();
	error_exit(pid == -1, "fork error");

	if (pid != 0)
		return;

	ret = prctl(PR_SET_PDEATHSIG, SIGHUP);
	error_exit(ret < 0, "failed to set parent death sig");

	printf("pid %u getpid() %u parent %u getppid() %u\n",
		pid, getpid(), parent, getppid());
	error_exit(getppid() != parent, "child parent already changed");

	writer_proc(opts, args);
	exit(0);
}

static int do_restore(struct opts *opts)
{
	struct scoutfs_parallel_restore_writer *wri = NULL;
	struct scoutfs_parallel_restore_slice *slices = NULL;
	struct scoutfs_super_block *super = NULL;
	struct write_result res;
	struct writer_args *args;
	struct timespec begin;
	struct timespec end;
	LIST_HEAD(writers);
	u64 next_ino;
	u64 ino_per;
	u64 avg_dirs;
	u64 avg_files;
	u64 dir_height;
	u64 tot_files;
	u64 tot_bytes;
	int pair[2] = {-1, -1};
	float secs;
	void *buf = NULL;
	int dev_fd = -1;
	int ret;
	int i;

	ret = socketpair(PF_LOCAL, SOCK_STREAM, 0, pair);
	error_exit(ret, "socketpair error "ERRF, ERRA);

	dev_fd = open(opts->meta_path, O_DIRECT | (opts->read_only ? O_RDONLY : (O_RDWR|O_EXCL)));
	error_exit(dev_fd < 0, "error opening '%s': "ERRF, opts->meta_path, ERRA);

	errno = posix_memalign((void **)&super, 4096, SCOUTFS_BLOCK_SM_SIZE) ?:
		posix_memalign((void **)&buf, 4096, opts->buf_size);
	error_exit(errno, "error allocating block bufs "ERRF, ERRA);

	ret = pread(dev_fd, super, SCOUTFS_BLOCK_SM_SIZE,
		    SCOUTFS_SUPER_BLKNO << SCOUTFS_BLOCK_SM_SHIFT);
	error_exit(ret != SCOUTFS_BLOCK_SM_SIZE, "error reading super, ret %d", ret);

	ret = scoutfs_parallel_restore_create_writer(&wri);
	error_exit(ret, "create writer %d", ret);

	ret = scoutfs_parallel_restore_import_super(wri, super, dev_fd);
	error_exit(ret, "import super %d", ret);

	slices = calloc(1 + opts->nr_writers, sizeof(struct scoutfs_parallel_restore_slice));
	error_exit(!slices, "alloc slices");

	scoutfs_parallel_restore_init_slices(wri, slices, 1 + opts->nr_writers);

	ret = scoutfs_parallel_restore_add_slice(wri, &slices[0]);
	error_exit(ret, "add slices[0] %d", ret);

	next_ino = (SCOUTFS_ROOT_INO | SCOUTFS_LOCK_INODE_GROUP_MASK) + 1;
	ino_per = opts->total_files / opts->nr_writers;
	avg_dirs = (opts->low_dirs + opts->high_dirs) / 2;
	avg_files = (opts->low_files + opts->high_files) / 2;

	dir_height = 1;
	tot_files = avg_files * opts->nr_writers;

	while (tot_files < opts->total_files) {
		dir_height++;
		tot_files *= avg_dirs;
	}

	dprintf("height %llu tot %llu total %llu\n", dir_height, tot_files, opts->total_files);

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	/* start each writing process */
	for (i = 0; i < opts->nr_writers; i++) {
		args = calloc(1, sizeof(struct writer_args));
		error_exit(!args, "alloc writer args");

		args->dev_fd = dev_fd;
		args->pair_fd = pair[1];
		args->slice = slices[1 + i];
		args->writer_nr = i;
		args->dir_height = dir_height;
		args->ino_start = next_ino;
		args->ino_len = ino_per;

		list_add_tail(&args->head, &writers);
		next_ino += ino_per;

		fork_writer(opts, args);
	}

	/* read results and watch for writers to finish */
	tot_files = 0;
	tot_bytes = 0;
	i = 0;
	while (i < opts->nr_writers) {
		ret = read(pair[0], &res, sizeof(struct write_result));
		error_exit(ret != sizeof(struct write_result), "result read error %d", ret);

		ret = scoutfs_parallel_restore_add_progress(wri, &res.prog);
		error_exit(ret, "add thr prog %d", ret);

		if (res.slice.meta_len != 0) {
			ret = scoutfs_parallel_restore_add_slice(wri, &res.slice);
			error_exit(ret, "add thr slice %d", ret);
			i++;
		}

		tot_files += le64_to_cpu(res.files_created);
		tot_bytes += le64_to_cpu(res.bytes_written);
	}

	tot_bytes += write_bufs(opts, wri, buf, opts->buf_size, dev_fd);

	ret = scoutfs_parallel_restore_export_super(wri, super);
	error_exit(ret, "update super %d", ret);

	if (!opts->read_only) {
		ret = pwrite(dev_fd, super, SCOUTFS_BLOCK_SM_SIZE,
			     SCOUTFS_SUPER_BLKNO << SCOUTFS_BLOCK_SM_SHIFT);
		error_exit(ret != SCOUTFS_BLOCK_SM_SIZE, "error writing super, ret %d", ret);
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);

	scoutfs_parallel_restore_destroy_writer(&wri);

	secs = ((float)end.tv_sec + ((float)end.tv_nsec/NSEC_PER_SEC)) -
	       ((float)begin.tv_sec + ((float)begin.tv_nsec/NSEC_PER_SEC));
	printf("created %llu files in %llu bytes and %f secs => %f bytes/file, %f files/sec\n",
		tot_files, tot_bytes, secs,
		(float)tot_bytes / tot_files, (float)tot_files / secs);

	if (dev_fd >= 0)
		close(dev_fd);
	if (pair[0] >= 0)
		close(pair[0]);
	if (pair[1] >= 0)
		close(pair[1]);
	free(super);
	free(slices);
	free(buf);

	return 0;
}

static int parse_low_high(char *str, u64 *low_ret, u64 *high_ret)
{
	char *sep;
	int ret = 0;

	sep = index(str, ':');
	if (sep) {
		*sep = '\0';
		ret = parse_u64(sep + 1, high_ret);
	}

	if (ret == 0)
		ret = parse_u64(str, low_ret);

	if (sep)
		*sep = ':';

	return ret;
}

int main(int argc, char **argv)
{
	struct opts opts = {
		.buf_size = (32 * 1024 * 1024),

		.write_batch = 1000000,
		.low_dirs = 5,
		.high_dirs = 10,
		.low_files = 10,
		.high_files = 20,
		.total_files = 100,
	};
	struct sigaction act = { 0 };
	int ret;
	int c;

	opts.seed = random64();
	opts.nr_writers = sysconf(_SC_NPROCESSORS_ONLN);

        while ((c = getopt(argc, argv, "b:d:f:m:n:rs:w:")) != -1) {
                switch(c) {
                case 'b':
			ret = parse_u64(optarg, &opts.write_batch);
			error_exit(ret, "error parsing -b '%s'\n", optarg);
			error_exit(opts.write_batch == 0, "-b can't be 0");
                        break;
                case 'd':
			ret = parse_low_high(optarg, &opts.low_dirs, &opts.high_dirs);
			error_exit(ret, "error parsing -d '%s'\n", optarg);
                        break;
                case 'f':
			ret = parse_low_high(optarg, &opts.low_files, &opts.high_files);
			error_exit(ret, "error parsing -f '%s'\n", optarg);
                        break;
                case 'm':
                        opts.meta_path = strdup(optarg);
                        break;
                case 'n':
			ret = parse_u64(optarg, &opts.total_files);
			error_exit(ret, "error parsing -n '%s'\n", optarg);
                        break;
                case 'r':
			opts.read_only = true;
			break;
                case 's':
			ret = parse_u64(optarg, &opts.seed);
			error_exit(ret, "error parsing -s '%s'\n", optarg);
                        break;
                case 'w':
			ret = parse_u64(optarg, &opts.nr_writers);
			error_exit(ret, "error parsing -w '%s'\n", optarg);
                        break;
                case '?':
                        printf("Unknown option '%c'\n", optopt);
                        usage();
			exit(1);
                }
        }

	error_exit(opts.low_dirs > opts.high_dirs, "LOW > HIGH in -d %llu:%llu",
		   opts.low_dirs, opts.high_dirs);
	error_exit(opts.low_files > opts.high_files, "LOW > HIGH in -f %llu:%llu",
		   opts.low_files, opts.high_files);
	error_exit(!opts.meta_path, "must specify metadata device path with -m");

	printf("recreate with: -d %llu:%llu -f %llu:%llu -n %llu -s %llu -w %llu\n",
		opts.low_dirs, opts.high_dirs, opts.low_files, opts.high_files,
		opts.total_files, opts.seed, opts.nr_writers);

	act.sa_flags = SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = &sigchld_handler;
	if (sigaction(SIGCHLD, &act, NULL) == -1)
		error_exit(ret, "error setting up signal handler\n");

	ret = do_restore(&opts);

	free(opts.meta_path);

	return ret == 0 ? 0 : 1;
}
