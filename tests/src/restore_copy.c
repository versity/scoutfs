#define _GNU_SOURCE /* O_DIRECT */
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <dirent.h>

#include "../../utils/src/sparse.h"
#include "../../utils/src/util.h"
#include "../../utils/src/list.h"
#include "../../utils/src/parse.h"
#include "../../kmod/src/format.h"
#include "../../kmod/src/ioctl.h"
#include "../../utils/src/parallel_restore.h"

/*
 * XXX:
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

#define REG_MODE (S_IFREG | 0644)
#define DIR_MODE (S_IFDIR | 0755)

#define BUF_SIZ 256 * 4096

static struct list_head hardlinks;
struct hardlink_head {
	struct list_head head;
	u64 ino;
};

static int nr_files;
static int nr_dirs;
static int nr_symlinks;
static int nr_hardlinks;
static int nr_xattrs;

struct opts {
	char *meta_path;
	char *source_dir;
};

static void usage(void)
{
	printf("usage:\n"
	       " -m PATH     | path to metadata device\n"
	       " -s PATH     | path to source directory\n"
	       );
}

static size_t write_bufs(struct scoutfs_parallel_restore_writer *wri,
			 void *buf, int dev_fd)
{
	size_t total = 0;
	size_t count;
	off_t off;
	int ret;

	do {
		ret = scoutfs_parallel_restore_write_buf(wri, buf, BUF_SIZ, &off, &count);
		error_exit(ret, "write buf %d", ret);

		if (count > 0) {
			fprintf(stderr, "pwrite %ld %ld\n", count, off);
			ret = pwrite(dev_fd, buf, count, off);
			error_exit(ret != count, "pwrite count %zu ret %d", count, ret);
			total += ret;
		}
	} while (count > 0);

	return total;
}

static void add_xattrs(struct scoutfs_parallel_restore_writer *wri, char *path, u64 ino)
{
	struct scoutfs_ioctl_listxattr_hidden lxh;
	struct scoutfs_parallel_restore_xattr xattr;
	char *buf = NULL;
	char *value = NULL;
	char *name = NULL;
	int fd = -1;
	int bytes;
	int len;
	int value_len;
	int ret;
	int pos = 0;

	memset(&lxh, 0, sizeof(lxh));
	lxh.id_pos = 0;
	lxh.hash_pos = 0;
	lxh.buf_bytes = 256 * 1024;

	buf = malloc(lxh.buf_bytes);
	error_exit(!buf, "alloc xattr_hidden buf");
	lxh.buf_ptr = (unsigned long)buf;

	fd = open(path, O_RDONLY);
	error_exit(fd < 0, "open"ERRF, ERRA);

	/* hidden */
	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_LISTXATTR_HIDDEN, &lxh);
		if (ret == 0) /* done */
			break;
		if ((ret == -1) && (errno == ENOTTY)) /* not scoutfs */
			break;
		error_exit(ret < 0, "listxattr_hidden"ERRF, ERRA);
		bytes = ret;
		error_exit(ret > lxh.buf_bytes, "listxattr_hidden overflow");
		error_exit(buf[bytes - 1] != '\0', "listxattr_hidden didn't term");

		name = buf;

		do {
			len = strlen(name);
			error_exit(len == 0, "listxattr_hidden empty name");
			error_exit(len > SCOUTFS_XATTR_MAX_NAME_LEN, "listxattr_hidden long name");

			/* get value */
			value_len = fgetxattr(fd, name, NULL, 0);
			value = calloc(1, value_len);
			error_exit(!value, "malloc value hidden"ERRF, ERRA);
			value_len = fgetxattr(fd, name, &value, value_len); 

			xattr = (struct scoutfs_parallel_restore_xattr) {
				.ino = ino,
				.pos = pos,
				.name = name,
				.name_len = len,
				.value = value,
				.value_len = value_len,
			};

			ret = scoutfs_parallel_restore_add_xattr(wri, &xattr);
			nr_xattrs++;
			error_exit(ret, "add hidden xattr %d", ret);

			free(value);

			pos++;

			name += len + 1;
			bytes -= len + 1;
		} while (bytes > 0);
	}

	free(buf);

	/* normal */
	value_len = flistxattr(fd, NULL, 0);
	error_exit(value_len < 0, "flistxattr %d", ret);
	if (value_len == 0) {
		close(fd);
		return;
	}
	buf = calloc(1, value_len);
	error_exit(!buf, "malloc value"ERRF, ERRA);

	ret = flistxattr(fd, buf, value_len);
	error_exit(ret < 0, "flistxattr %d", ret);

	name = buf;
	bytes = ret;
	do {
		len = strlen(name);
		value_len = fgetxattr(fd, name, NULL, 0);
		value = calloc(1, value_len);
		error_exit(!value, "calloc value"ERRF, ERRA);
		value_len = fgetxattr(fd, name, value, value_len);

		xattr = (struct scoutfs_parallel_restore_xattr) {
			.ino = ino,
			.pos = pos,
			.name = name,
			.name_len = len,
			.value = value,
			.value_len = value_len,
		};

		ret = scoutfs_parallel_restore_add_xattr(wri, &xattr);
		nr_xattrs++;
		error_exit(ret, "add xattr %d", ret);

		free(value);

		name += len + 1;
		bytes -= len + 1;
		pos++;
	} while (bytes > 0);

	free(buf);

	close(fd);
}

static bool is_new_inode_item(bool nlink, u64 ino)
{
	struct hardlink_head *hh_tmp;
	struct hardlink_head *hh;

	if (!nlink)
		return true;

	/* lineair search, pretty awful, should be a binary tree */
	list_for_each_entry_safe(hh, hh_tmp, &hardlinks, head) {
		if (hh->ino == ino)
			return false;
	}

	/* insert item */
	hh = malloc(sizeof(struct hardlink_head));
	error_exit(!hh, "malloc");
	hh->ino = ino;
	list_add_tail(&hh->head, &hardlinks);

	nr_hardlinks++;

	return true;
}

static struct scoutfs_parallel_restore_inode *read_inode_data(char *path, u64 ino, bool *nlink)
{
	struct scoutfs_parallel_restore_inode *inode = NULL;
	struct scoutfs_ioctl_stat_more stm;
	struct stat st;
	int ret;
	int fd;

	inode = calloc(1, sizeof(struct scoutfs_parallel_restore_inode));
	error_exit(!inode, "failure allocating inode");

	/* normal stat */
	ret = stat(path, &st);
	error_exit(ret, "failure stat inode");

	inode->ino = st.st_ino;
	inode->mode = st.st_mode;
	inode->uid = st.st_uid;
	inode->gid = st.st_gid;
	inode->atime = st.st_atim;
	inode->ctime = st.st_ctim;
	inode->mtime = st.st_mtim;
	inode->size = st.st_size;

	/* scoutfs specific */
	inode->meta_seq = 0;
	inode->data_seq = 0;
	inode->crtime = st.st_ctim;

	fd = get_path(path, O_RDONLY);
	error_exit(!fd, "failure get_path inode");

	if ((inode->mode & S_IFMT) == S_IFREG) {
		if (inode->size > 0)
			inode->offline = true;

		ret = ioctl(fd, SCOUTFS_IOC_STAT_MORE, &stm);
		/* might not be scoutfs source */
		if (!((ret == -1) && (errno == 25))) {
			error_exit(ret, "failure SCOUTFS_IOC_STAT_MORE inode");

			inode->meta_seq = stm.meta_seq;
			inode->data_seq = stm.data_seq;
			inode->crtime = (struct timespec){.tv_sec = stm.crtime_sec, .tv_nsec = stm.crtime_nsec};
		}
	}
	close(fd);

	/* pass whether item is hardlinked or not */
	*nlink = (st.st_nlink > 1);

	return inode;
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

static void restore_path(struct scoutfs_parallel_restore_writer *wri, struct writer_args *args, char *path, u64 ino)
{
	struct scoutfs_parallel_restore_inode *inode;
	struct scoutfs_parallel_restore_entry entry;
	DIR *dirp = NULL;
	void *buf = NULL;
	char *subdir = NULL;
	char link[PATH_MAX];
	struct dirent *ent;
	size_t total;
	int ret = 0;
	int subdir_count = 0, file_count = 0;
	size_t ent_len = 0;
	size_t pos = 0;
	bool nlink = false;

	errno = posix_memalign((void **)&buf, 4096, BUF_SIZ);
	error_exit(errno, "error allocating block buf "ERRF, ERRA);

	/* restore all subdirs */
	dirp = opendir(path);
	errno = 0;
	while ((ent = readdir(dirp))) {
		if (ent->d_type != DT_DIR)
			continue;

		if ((strcmp(ent->d_name, ".") == 0) ||
		    (strcmp(ent->d_name, "..") == 0))
				continue;

		fprintf(stdout, "d %s/%s\n", path, ent->d_name);

		ret = asprintf(&subdir, "%s/%s", path, ent->d_name);
		error_exit(ret == -1, "asprintf subdir"ERRF, ERRA);
		restore_path(wri, args, subdir, ent->d_ino);
		nr_dirs++;
		free(subdir);
	}
	closedir(dirp);

	/* traverse the entire tree */
	dirp = opendir(path);
	errno = 0;
	while ((ent = readdir(dirp))) {
		if (ent->d_type == DT_DIR) {
			if ((strcmp(ent->d_name, ".") == 0) ||
			    (strcmp(ent->d_name, "..") == 0))
				continue;

			fprintf(stdout, "d %s/%s\n", path, ent->d_name);

			subdir_count++;

			ent_len += strlen(ent->d_name);

			entry = (struct scoutfs_parallel_restore_entry) {
				.dir_ino = ino,
				.pos = pos,
				.ino = ent->d_ino,
				.mode = DIR_MODE,
				.name = ent->d_name,
				.name_len = strlen(ent->d_name),
			};
			ret = scoutfs_parallel_restore_add_entry(wri, &entry);
			ent_len += strlen(ent->d_name);
			error_exit(ret, "add entry %d", ret);
		} else if (ent->d_type == DT_REG) {
			fprintf(stdout, "f %s/%s\n", path, ent->d_name);
			file_count++;

			ent_len += strlen(ent->d_name);

			/* entry */
			entry = (struct scoutfs_parallel_restore_entry) {
				.dir_ino = ino,
				.pos = pos,
				.ino = ent->d_ino,
				.mode = REG_MODE,
				.name = ent->d_name,
				.name_len = strlen(ent->d_name),
			};
			ret = scoutfs_parallel_restore_add_entry(wri, &entry);
			error_exit(ret, "add entry %d", ret);
			ent_len += strlen(ent->d_name);

			ret = asprintf(&subdir, "%s/%s", path, ent->d_name);
			error_exit(ret == -1, "asprintf subdir"ERRF, ERRA);

			/* file inode */
			inode = read_inode_data(subdir, ent->d_ino, &nlink);
			if (is_new_inode_item(nlink, ent->d_ino)) {
				ret = scoutfs_parallel_restore_add_inode(wri, inode);
				nr_files++;
				error_exit(ret, "add reg file inode %d", ret);

				/* xattrs */
				add_xattrs(wri, subdir, ent->d_ino);
			}
			free(inode);

			free(subdir);

		} else if (ent->d_type == DT_LNK) {
			/* readlink */
			fprintf(stdout, "l %s/%s\n", path, ent->d_name);

			/* insert inode item */
			ret = asprintf(&subdir, "%s/%s", path, ent->d_name);
			error_exit(ret == -1, "asprintf subdir"ERRF, ERRA);

			ret = readlink(subdir, link, PATH_MAX);
			error_exit(ret < 0, "readlink %d", ret);

			free(subdir);

			entry = (struct scoutfs_parallel_restore_entry) {
				.dir_ino = ino,
				.pos = pos,
				.ino = ent->d_ino,
				.mode = S_IFLNK,
				.name = link,
				.name_len = ret,
			};
			ret = scoutfs_parallel_restore_add_entry(wri, &entry);
			error_exit(ret, "add symlink entry %d", ret);
			ent_len += strlen(ent->d_name);
			nr_symlinks++;

		} else {
			/* don't bother */
			fprintf(stderr, "Unsupported file type: \"%s/%s\"\n", path, ent->d_name);
			//ent_len += strlen(ent->d_name);
		}

		pos++;

	}
	if (ent != NULL)
		error_exit(errno, "readdir"ERRF, ERRA);
	closedir(dirp);

	/* create the dir itself */
	inode = read_inode_data(path, ino, &nlink);
	inode->nr_subdirs = subdir_count;
	inode->total_entry_name_bytes = ent_len;

	ret = scoutfs_parallel_restore_add_inode(wri, inode);
	error_exit(ret, "add dir inode %d", ret);

	free(inode);

	total = write_bufs(wri, buf, args->dev_fd);
	fprintf(stderr, "++ %ld\n", total);

	free(buf);

}

static int do_restore(struct opts *opts)
{
	struct scoutfs_parallel_restore_writer *pwri, *wri = NULL;
	struct scoutfs_parallel_restore_slice *slices = NULL;
	struct scoutfs_super_block *super = NULL;
	struct writer_args *args;
	LIST_HEAD(writers);
	void *buf = NULL;
	int dev_fd = -1;
	int ret;
	size_t total;

	dev_fd = open(opts->meta_path, O_DIRECT | (O_RDWR|O_EXCL));
	error_exit(dev_fd < 0, "error opening '%s': "ERRF, opts->meta_path, ERRA);

	errno = posix_memalign((void **)&super, 4096, SCOUTFS_BLOCK_SM_SIZE) ?:
		posix_memalign((void **)&buf, 4096, BUF_SIZ);
	error_exit(errno, "error allocating block bufs "ERRF, ERRA);

	ret = pread(dev_fd, super, SCOUTFS_BLOCK_SM_SIZE,
		    SCOUTFS_SUPER_BLKNO << SCOUTFS_BLOCK_SM_SHIFT);
	error_exit(ret != SCOUTFS_BLOCK_SM_SIZE, "error reading super, ret %d", ret);

	ret = scoutfs_parallel_restore_create_writer(&wri);
	error_exit(ret, "create writer %d", ret);

	ret = scoutfs_parallel_restore_import_super(wri, super);
	error_exit(ret, "import super %d", ret);

	slices = calloc(2, sizeof(struct scoutfs_parallel_restore_slice));
	error_exit(!slices, "alloc slices");

	scoutfs_parallel_restore_init_slices(wri, slices, 2);

	ret = scoutfs_parallel_restore_add_slice(wri, &slices[0]);
	error_exit(ret, "add slices[0] %d", ret);

	args = calloc(1, sizeof(struct writer_args));
	error_exit(!args, "alloc writer args");

	args->dev_fd = dev_fd;
	args->slice = slices[0];
	list_add_tail(&args->head, &writers);

	/* create 2nd writer with own slice*/
	ret = scoutfs_parallel_restore_create_writer(&pwri);
	error_exit(ret, "create pwriter %d", ret);

	ret = scoutfs_parallel_restore_add_slice(pwri, &slices[1]);
	error_exit(ret, "add pslice %d", ret);

	// fill all the content recursively
	restore_path(pwri, args, opts->source_dir, SCOUTFS_ROOT_INO);

	total = write_bufs(wri, buf, args->dev_fd);
	fprintf(stderr, "++ %ld\n", total);

	// write super to finalize
	ret = scoutfs_parallel_restore_export_super(wri, super);
	error_exit(ret, "update super %d", ret);

	ret = pwrite(dev_fd, super, SCOUTFS_BLOCK_SM_SIZE,
		     SCOUTFS_SUPER_BLKNO << SCOUTFS_BLOCK_SM_SHIFT);
	error_exit(ret != SCOUTFS_BLOCK_SM_SIZE, "error writing super, ret %d", ret);

	scoutfs_parallel_restore_destroy_writer(&pwri);
	scoutfs_parallel_restore_destroy_writer(&wri);

	if (dev_fd >= 0)
		close(dev_fd);
	free(super);
	free(args);
	free(slices);
	free(buf);

	return 0;
}

int main(int argc, char **argv)
{
	struct opts opts = (struct opts){ 0 };
	struct hardlink_head *hh_tmp;
	struct hardlink_head *hh;
	int ret;
	int c;

	INIT_LIST_HEAD(&hardlinks);

	nr_files = 0;
	nr_dirs = 0;
	nr_symlinks = 0;
	nr_hardlinks = 0;
	nr_xattrs = 0;

        while ((c = getopt(argc, argv, "b:m:s:")) != -1) {
                switch(c) {
                case 'm':
                        opts.meta_path = strdup(optarg);
                        break;
		case 's':
			opts.source_dir = strdup(optarg);
			break;
                case '?':
                        printf("Unknown option '%c'\n", optopt);
                        usage();
			exit(1);
                }
        }

	error_exit(!opts.meta_path, "must specify metadata device path with -m");
	error_exit(!opts.source_dir, "must specify source directory path with -s");

	ret = do_restore(&opts);

	fprintf(stdout, "Restored %d files, %d directories, %d symlinks, %d hardlinks, %d xattrs.\n",
		nr_files, nr_dirs, nr_symlinks, nr_hardlinks, nr_xattrs);

	free(opts.meta_path);
	free(opts.source_dir);

	list_for_each_entry_safe(hh, hh_tmp, &hardlinks, head) {
		list_del_init(&hh->head);
		free(hh);
	}

	return ret == 0 ? 0 : 1;
}
