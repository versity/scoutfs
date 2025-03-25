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
#include <sys/signal.h>
#include <sys/statfs.h>
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
#define LNK_MODE (S_IFLNK | 0777)

/*
 * At about 1k files we seem to be writing about 1MB of data, so
 * set buffer sizes adequately above that.
 */
#define BATCH_FILES 1024
#define BUF_SIZ 2 * 1024 * 1024

/*
 * We can't make duplicate inodes for hardlinked files, so we
 * will need to track these as we generate them. Not too costly
 * to do, since it's just an integer, and sorting shouldn't matter
 * until we get into the millions of entries, hopefully.
 */
static struct list_head hardlinks;
struct hardlink_head {
	struct list_head head;
	u64 ino;
};

struct opts {
	char *meta_path;
	char *source_dir;
};

static bool warn_scoutfs = false;

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
			ret = pwrite(dev_fd, buf, count, off);
			error_exit(ret != count, "pwrite count %zu ret %d", count, ret);
			total += ret;
		}
	} while (count > 0);

	return total;
}

struct write_result {
	struct scoutfs_parallel_restore_progress prog;
	struct scoutfs_parallel_restore_slice slice;
	__le64 files_created;
	__le64 dirs_created;
	__le64 bytes_written;
	bool complete;
};

static void write_bufs_and_send(struct scoutfs_parallel_restore_writer *wri,
				void *buf, int dev_fd,
				struct write_result *res, bool get_slice, int pair_fd)
{
	size_t total;
	int ret;

	total = write_bufs(wri, buf, dev_fd);
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
 * Adding xattrs is supported for files and directories only.
 *
 * If the filesystem on which the path resides isn't scoutfs, we omit the
 * scoutfs specific ioctl to fetch hidden xattrs.
 *
 * Untested if the hidden xattr ioctl works on directories or symlinks.
 */
static void add_xattrs(struct scoutfs_parallel_restore_writer *wri, char *path, u64 ino, bool is_scoutfs)
{
	struct scoutfs_ioctl_listxattr_hidden lxh;
	struct scoutfs_parallel_restore_xattr *xattr;
	char *buf = NULL;
	char *name = NULL;
	int fd = -1;
	int bytes;
	int len;
	int value_len;
	int ret;
	int pos = 0;

	if (!is_scoutfs)
		goto normal_xattrs;

	fd = open(path, O_RDONLY);
	error_exit(fd < 0, "open"ERRF, ERRA);

	memset(&lxh, 0, sizeof(lxh));
	lxh.id_pos = 0;
	lxh.hash_pos = 0;
	lxh.buf_bytes = 256 * 1024;

	buf = malloc(lxh.buf_bytes);
	error_exit(!buf, "alloc xattr_hidden buf");
	lxh.buf_ptr = (unsigned long)buf;

	/* hidden */
	for (;;) {
		ret = ioctl(fd, SCOUTFS_IOC_LISTXATTR_HIDDEN, &lxh);
		if (ret == 0) /* done */
			break;
		error_exit(ret < 0, "listxattr_hidden"ERRF, ERRA);
		bytes = ret;
		error_exit(bytes > lxh.buf_bytes, "listxattr_hidden overflow");
		error_exit(buf[bytes - 1] != '\0', "listxattr_hidden didn't term");

		name = buf;

		do {
			len = strlen(name);
			error_exit(len == 0, "listxattr_hidden empty name");
			error_exit(len > SCOUTFS_XATTR_MAX_NAME_LEN, "listxattr_hidden long name");

			/* get value len */
			value_len = fgetxattr(fd, name, NULL, 0);
			error_exit(value_len < 0, "malloc value hidden"ERRF, ERRA);

			/* allocate everything at once */
			xattr = malloc(sizeof(struct scoutfs_parallel_restore_xattr) + len + value_len);
			error_exit(!xattr, "error allocating generated xattr");

			*xattr = (struct scoutfs_parallel_restore_xattr) {
				.ino = ino,
				.pos = pos++,
				.name_len = len,
				.value_len = value_len,
			};
			xattr->name = (void *)(xattr + 1);
			xattr->value = (void *)(xattr->name + len);

			/* get value into xattr directly */
			ret = fgetxattr(fd, name, (void *)(xattr->name + len), value_len);
			error_exit(ret != value_len, "fgetxattr value"ERRF, ERRA);

			memcpy(xattr->name, name, len);

			ret = scoutfs_parallel_restore_add_xattr(wri, xattr);
			error_exit(ret, "add hidden xattr %d", ret);

			free(xattr);

			name += len + 1;
			bytes -= len + 1;
		} while (bytes > 0);
	}

	free(buf);
	close(fd);

normal_xattrs:
	value_len = listxattr(path, NULL, 0);
	error_exit(value_len < 0, "hidden listxattr "ERRF, ERRA);
	if (value_len == 0)
		return;

	buf = calloc(1, value_len);
	error_exit(!buf, "malloc value"ERRF, ERRA);

	ret = listxattr(path, buf, value_len);
	error_exit(ret < 0, "hidden listxattr %d", ret);

	name = buf;
	bytes = ret;
	do {
		len = strlen(name);

		error_exit(len == 0, "listxattr_hidden empty name");
		error_exit(len > SCOUTFS_XATTR_MAX_NAME_LEN, "listxattr_hidden long name");

		value_len = getxattr(path, name, NULL, 0);
		error_exit(value_len < 0, "value "ERRF, ERRA);

		xattr = malloc(sizeof(struct scoutfs_parallel_restore_xattr) + len + value_len);
		error_exit(!xattr, "error allocating generated xattr");

		*xattr = (struct scoutfs_parallel_restore_xattr) {
			.ino = ino,
			.pos = pos++,
			.name_len = len,
			.value_len = value_len,
		};
		xattr->name = (void *)(xattr + 1);
		xattr->value = (void *)(xattr->name + len);

		ret = getxattr(path, name, (void *)(xattr->name + len), value_len);
		error_exit(ret != value_len, "fgetxattr value"ERRF, ERRA);

		memcpy(xattr->name, name, len);

		ret = scoutfs_parallel_restore_add_xattr(wri, xattr);
		error_exit(ret, "add xattr %d", ret);

		free(xattr);

		name += len + 1;
		bytes -= len + 1;
	} while (bytes > 0);

	free(buf);
}

/*
 * We can't store the same inode multiple times, so we need to make
 * sure to account for hardlinks. Maintain a LL that stores the first
 * hardlink inode we encounter, and every subsequent hardlink to this
 * inode will omit inserting an inode, and just adds another entry
 */
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

	/*
	 *  XXX
	 *
	 * We can be confident that if we don't traverse filesystems
	 * that once we've created N entries of an N-linked inode, that
	 * it can be removed from the LL. This would significantly
	 * improve the manageability of the list.
	 *
	 * All we'd need to do is add a counter and compare it to the nr_links
	 * field of the inode.
	 */

	return true;
}

/*
 * create the inode data for a given path as best as possible
 * duplicating the exact data from the source path
 */
static struct scoutfs_parallel_restore_inode *read_inode_data(char *path, u64 ino, bool *nlink, bool is_scoutfs)
{
	struct scoutfs_parallel_restore_inode *inode = NULL;
	struct scoutfs_ioctl_stat_more stm;
	struct scoutfs_ioctl_inode_attr_x iax;
	struct stat st;
	int ret;
	int fd;

	inode = calloc(1, sizeof(struct scoutfs_parallel_restore_inode));
	error_exit(!inode, "failure allocating inode");

	ret = lstat(path, &st);
	error_exit(ret, "failure stat inode");

	/* use exact inode numbers from path, except for root ino */
	if (ino != SCOUTFS_ROOT_INO)
		inode->ino = st.st_ino;
	else
		inode->ino = SCOUTFS_ROOT_INO;

	inode->mode = st.st_mode;
	inode->uid = st.st_uid;
	inode->gid = st.st_gid;
	inode->atime = st.st_atim;
	inode->ctime = st.st_ctim;
	inode->mtime = st.st_mtim;
	inode->size = st.st_size;
	inode->nlink = st.st_nlink;

	inode->rdev = st.st_rdev;

	/* scoutfs specific */
	inode->meta_seq = 0;
	inode->data_seq = 0;
	inode->crtime = st.st_ctim;

	/* we don't restore data */
	if (S_ISREG(inode->mode) && (inode->size > 0))
		inode->offline = true;

	if (S_ISREG(inode->mode) || S_ISDIR(inode->mode)) {
		if (is_scoutfs) {
			fd = open(path, O_RDONLY);
			error_exit(!fd, "open failure"ERRF, ERRA);

			ret = ioctl(fd, SCOUTFS_IOC_STAT_MORE, &stm);
			error_exit(ret, "failure SCOUTFS_IOC_STAT_MORE inode");

			inode->meta_seq = stm.meta_seq;
			inode->data_seq = stm.data_seq;
			inode->crtime = (struct timespec){.tv_sec = stm.crtime_sec, .tv_nsec = stm.crtime_nsec};

			/* project ID, retention bit */
			memset(&iax, 0, sizeof(iax));

			iax.x_flags = 0;
			iax.x_mask = SCOUTFS_IOC_IAX_PROJECT_ID | SCOUTFS_IOC_IAX__BITS;
			iax.bits = SCOUTFS_IOC_IAX_B_RETENTION;

			ret = ioctl(fd, SCOUTFS_IOC_GET_ATTR_X, &iax);
			error_exit(ret, "failure SCOUTFS_IOC_GET_ATTR_X inode");

			inode->proj = iax.project_id;
			inode->flags |= (iax.bits & SCOUTFS_IOC_IAX_B_RETENTION) ? SCOUTFS_INO_FLAG_RETENTION : 0;

			close(fd);
		}

	}

	/* pass whether item is hardlinked or not */
	*nlink = (st.st_nlink > 1);

	return inode;
}

typedef int (*quota_ioctl_in)(struct scoutfs_ioctl_quota_rule *irules,
							  struct scoutfs_ioctl_get_quota_rules *gqr,
							  size_t nr, int fd);

static int get_quota_ioctl(struct scoutfs_ioctl_quota_rule *irules,
						   struct scoutfs_ioctl_get_quota_rules *rules_in,
						   size_t nr, int fd)
{
	struct scoutfs_ioctl_get_quota_rules *gqr = rules_in;
	int ret;

	gqr->rules_ptr = (intptr_t)irules;
	gqr->rules_nr = nr;

	ret = ioctl(fd, SCOUTFS_IOC_GET_QUOTA_RULES, gqr);
	error_exit(ret < 0, "quota ioctl error");

	return ret;
}

static char opc[] = {
        [SQ_OP_DATA] = 'D',
        [SQ_OP_INODE] = 'I',
};

static char nsc[] = {
        [SQ_NS_LITERAL] = 'L',
        [SQ_NS_PROJ] = 'P',
        [SQ_NS_UID] = 'U',
        [SQ_NS_GID] = 'G',
};

static int insert_quota_rule(struct scoutfs_parallel_restore_writer *wri,
					   struct scoutfs_ioctl_quota_rule *irule)
{
	struct scoutfs_parallel_restore_quota_rule *prule = NULL;
	int ret;
	int i;

	prule = calloc(1, sizeof(struct scoutfs_parallel_restore_quota_rule));
	error_exit(!prule, "quota rule alloc failed");
	prule->limit = irule->limit;
	prule->prio = irule->prio;
	prule->op = irule->op;
	prule->rule_flags = irule->rule_flags;
	prule->names[0].val = irule->name_val[0];
	prule->names[0].source = irule->name_source[0];
	prule->names[0].flags = irule->name_flags[0];
	prule->names[1].val = irule->name_val[1];
	prule->names[1].source = irule->name_source[1];
	prule->names[1].flags = irule->name_flags[1];
	prule->names[2].val = irule->name_val[2];
	prule->names[2].source = irule->name_source[2];
	prule->names[2].flags = irule->name_flags[2];

	/* print out the rule */
        printf("Quota rule: %3u ", irule->prio);
        for (i = 0; i < array_size(irule->name_val); i++) {
                printf("%llu,%c,%c ",
                       irule->name_val[i],
                       nsc[irule->name_source[i]],
                       (irule->name_flags[i] & SQ_NF_SELECT) ? 'S' : '-');
        }
        printf("%c %llu %c\n",
               opc[irule->op], irule->limit, (irule->rule_flags & SQ_RF_TOTL_COUNT) ? 'C' : '-');

	ret = scoutfs_parallel_restore_add_quota_rule(wri, prule);
	error_exit(ret, "quota add rule %d", ret);
	free(prule);
	return ret;
}

static int restore_quotas(struct scoutfs_parallel_restore_writer *wri,
			  quota_ioctl_in quota_in, char *path)
{
	struct scoutfs_ioctl_get_quota_rules gqr = {{0,}};
	struct scoutfs_ioctl_quota_rule *irules = NULL;
	size_t rule_alloc = 0;
	size_t rule_nr = 0;
	size_t rule_count;
	size_t i;
	int fd = -1;
	int ret;

	fd = open(path, O_RDONLY);
	error_exit(fd < 0, "open"ERRF, ERRA);

	for (;;) {
		if (rule_nr == rule_alloc) {
			rule_alloc += 1024;
			irules = realloc(irules, rule_alloc * sizeof(irules[0]));
			error_exit(!irules, "irule realloc failed rule_nr:%zu alloced:%zu", rule_nr, rule_alloc);
			if (!irules) {
				ret = -errno;
				fprintf(stderr, "memory allocation failed: %s (%d)\n",
					strerror(errno), errno);
				goto out;
			}
		}

		ret = quota_in(&irules[rule_nr], &gqr, rule_alloc - rule_nr, fd);
		if (ret == 0)
			break;
		if (ret < 0)
			goto out;

		rule_count = ret;

		for (i = 0; i < rule_count; i++) {
			ret = insert_quota_rule(wri, &irules[i]);
			if (ret < 0)
				goto out;
		}
	}

	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	if (irules)
		free(irules);
	return ret;
}

struct writer_args {
	struct list_head head;

	int dev_fd;
	int pair_fd;

	struct scoutfs_parallel_restore_slice slice;
};

static void restore_path(struct scoutfs_parallel_restore_writer *wri, struct writer_args *args, struct write_result *res, void *buf, char *path, u64 ino)
{
	struct scoutfs_parallel_restore_inode *inode;
	struct scoutfs_parallel_restore_entry *entry;
	DIR *dirp = NULL;
	char *subdir = NULL;
	char link[PATH_MAX + 1];
	struct dirent *ent;
	struct statfs stf;
	int ret = 0;
	int subdir_count = 0, file_count = 0;
	size_t ent_len = 0;
	size_t pos = 0;
	bool nlink = false;
	char ind = '?';
	u64 mode;
	bool is_scoutfs = false;

	/* get fs info once per path */
	ret = statfs(path, &stf);
	error_exit(ret != 0, "statfs"ERRF, ERRA);
	is_scoutfs = (stf.f_type == 0x554f4353);

	if (!is_scoutfs && !warn_scoutfs) {
		warn_scoutfs = true;
		fprintf(stderr, "Non-scoutfs source path detected: scoutfs specific features disabled\n");
	}


	/* traverse the entire tree */
	dirp = opendir(path);
	errno = 0;
	while ((ent = readdir(dirp))) {
		if (ent->d_type == DT_DIR) {
			if ((strcmp(ent->d_name, ".") == 0) ||
			    (strcmp(ent->d_name, "..") == 0)) {
				/* position still matters */
				pos++;
				continue;
			}

			/* recurse into subdir */
			ret = asprintf(&subdir, "%s/%s", path, ent->d_name);
			error_exit(ret == -1, "asprintf subdir"ERRF, ERRA);
			restore_path(wri, args, res, buf, subdir, ent->d_ino);

			subdir_count++;

			ent_len += strlen(ent->d_name);

			entry = malloc(sizeof(struct scoutfs_parallel_restore_entry) + strlen(ent->d_name));
			error_exit(!entry, "error allocating generated entry");

			*entry = (struct scoutfs_parallel_restore_entry) {
				.dir_ino = ino,
				.pos = pos++,
				.ino = ent->d_ino,
				.mode = DIR_MODE,
				.name = (void *)(entry + 1),
				.name_len = strlen(ent->d_name),
			};

			memcpy(entry->name, ent->d_name, strlen(ent->d_name));
			ret = scoutfs_parallel_restore_add_entry(wri, entry);
			error_exit(ret, "add entry %d", ret);
			free(entry);

			add_xattrs(wri, subdir, ent->d_ino, is_scoutfs);

			free(subdir);

			le64_add_cpu(&res->dirs_created, 1);
		} else if (ent->d_type == DT_REG) {

			file_count++;

			ent_len += strlen(ent->d_name);

			entry = malloc(sizeof(struct scoutfs_parallel_restore_entry) + strlen(ent->d_name));
			error_exit(!entry, "error allocating generated entry");

			*entry = (struct scoutfs_parallel_restore_entry) {
				.dir_ino = ino,
				.pos = pos++,
				.ino = ent->d_ino,
				.mode = REG_MODE,
				.name = (void *)(entry + 1),
				.name_len = strlen(ent->d_name),
			};

			memcpy(entry->name, ent->d_name, strlen(ent->d_name));
			ret = scoutfs_parallel_restore_add_entry(wri, entry);
			error_exit(ret, "add entry %d", ret);
			free(entry);

			ret = asprintf(&subdir, "%s/%s", path, ent->d_name);
			error_exit(ret == -1, "asprintf subdir"ERRF, ERRA);

			/* file inode */
			inode = read_inode_data(subdir, ent->d_ino, &nlink, is_scoutfs);
			fprintf(stdout, "f %s/%s\n", path, ent->d_name);
			if (is_new_inode_item(nlink, ent->d_ino)) {
				ret = scoutfs_parallel_restore_add_inode(wri, inode);
				error_exit(ret, "add reg file inode %d", ret);

				/* xattrs */
				add_xattrs(wri, subdir, ent->d_ino, is_scoutfs);
			}
			free(inode);

			free(subdir);

			le64_add_cpu(&res->files_created, 1);
		} else if (ent->d_type == DT_LNK) {
			/* readlink */

			ret = asprintf(&subdir, "%s/%s", path, ent->d_name);
			error_exit(ret == -1, "asprintf subdir"ERRF, ERRA);

			ent_len += strlen(ent->d_name);

			ret = readlink(subdir, link, PATH_MAX);
			error_exit(ret < 0, "readlink %d", ret);
			/* must 0-terminate if we want to print it */
			link[ret] = 0;

			entry = malloc(sizeof(struct scoutfs_parallel_restore_entry) + strlen(ent->d_name));
			error_exit(!entry, "error allocating generated entry");

			*entry = (struct scoutfs_parallel_restore_entry) {
				.dir_ino = ino,
				.pos = pos++,
				.ino = ent->d_ino,
				.mode = LNK_MODE,
				.name = (void *)(entry + 1),
				.name_len = strlen(ent->d_name),
			};

			memcpy(entry->name, ent->d_name, strlen(ent->d_name));
			ret = scoutfs_parallel_restore_add_entry(wri, entry);
			error_exit(ret, "add symlink entry %d", ret);

			/* link inode */
			inode = read_inode_data(subdir, ent->d_ino, &nlink, is_scoutfs);

			fprintf(stdout, "l %s/%s -> %s\n", path, ent->d_name, link);

			inode->mode = LNK_MODE;
			inode->target = link;
			inode->target_len = strlen(link) + 1; /* scoutfs null terminates symlinks */

			ret = scoutfs_parallel_restore_add_inode(wri, inode);
			error_exit(ret, "add syml inode %d", ret);

			free(inode);
			free(subdir);

			le64_add_cpu(&res->files_created, 1);
		} else {
			/* odd stuff */
			switch(ent->d_type) {
			case DT_CHR:
				ind = 'c';
				mode = S_IFCHR;
				break;
			case DT_BLK:
				ind = 'b';
				mode = S_IFBLK;
				break;
			case DT_FIFO:
				ind = 'p';
				mode = S_IFIFO;
				break;
			case DT_SOCK:
				ind = 's';
				mode = S_IFSOCK;
				break;
			default:
				error_exit(true, "Unknown readdir entry type");
				;;
			}

			file_count++;

			ent_len += strlen(ent->d_name);

			entry = malloc(sizeof(struct scoutfs_parallel_restore_entry) + strlen(ent->d_name));
			error_exit(!entry, "error allocating generated entry");

			*entry = (struct scoutfs_parallel_restore_entry) {
				.dir_ino = ino,
				.pos = pos++,
				.ino = ent->d_ino,
				.mode = mode,
				.name = (void *)(entry + 1),
				.name_len = strlen(ent->d_name),
			};

			memcpy(entry->name, ent->d_name, strlen(ent->d_name));
			ret = scoutfs_parallel_restore_add_entry(wri, entry);
			error_exit(ret, "add entry %d", ret);

			free(entry);

			ret = asprintf(&subdir, "%s/%s", path, ent->d_name);
			error_exit(ret == -1, "asprintf subdir"ERRF, ERRA);

			/* file inode */
			inode = read_inode_data(subdir, ent->d_ino, &nlink, is_scoutfs);
			fprintf(stdout, "%c %s/%s\n", ind, path, ent->d_name);
			if (is_new_inode_item(nlink, ent->d_ino)) {
				ret = scoutfs_parallel_restore_add_inode(wri, inode);
				error_exit(ret, "add reg file inode %d", ret);
			}
			free(inode);

			free(subdir);

			le64_add_cpu(&res->files_created, 1);
		}

		/* batch out changes, will be about 1M */
		if (le64_to_cpu(res->files_created) > BATCH_FILES) {
			write_bufs_and_send(wri, buf, args->dev_fd, res, false, args->pair_fd);
		}

	}
	if (ent != NULL)
		error_exit(errno, "readdir"ERRF, ERRA);
	closedir(dirp);

	/* create the dir itself */
	inode = read_inode_data(path, ino, &nlink, is_scoutfs);
	inode->nr_subdirs = subdir_count;
	inode->total_entry_name_bytes = ent_len;
	fprintf(stdout, "d %s\n", path);

	ret = scoutfs_parallel_restore_add_inode(wri, inode);
	error_exit(ret, "add dir inode %d", ret);

	free(inode);

	/* No need to send, we'll send final after last directory is complete */
}

static int do_restore(struct opts *opts)
{
	struct scoutfs_parallel_restore_writer *pwri, *wri = NULL;
	struct scoutfs_parallel_restore_slice *slices = NULL;
	struct scoutfs_super_block *super = NULL;
	struct writer_args *args;
	struct write_result res;
	int pair[2] = {-1, -1};
	LIST_HEAD(writers);
	void *buf = NULL;
	void *bufp = NULL;
	int dev_fd = -1;
	pid_t pid;
	int ret;
	u64 tot_bytes;
	u64 tot_dirs;
	u64 tot_files;

	ret = socketpair(PF_LOCAL, SOCK_STREAM, 0, pair);
	error_exit(ret, "socketpair error "ERRF, ERRA);

	dev_fd = open(opts->meta_path, O_DIRECT | (O_RDWR|O_EXCL));
	error_exit(dev_fd < 0, "error opening '%s': "ERRF, opts->meta_path, ERRA);

	errno = posix_memalign((void **)&super, 4096, SCOUTFS_BLOCK_SM_SIZE) ?:
		posix_memalign((void **)&buf, 4096, BUF_SIZ);
	error_exit(errno, "error allocating block bufs "ERRF, ERRA);

	ret = pread(dev_fd, super, SCOUTFS_BLOCK_SM_SIZE,
		    SCOUTFS_SUPER_BLKNO << SCOUTFS_BLOCK_SM_SHIFT);
	error_exit(ret != SCOUTFS_BLOCK_SM_SIZE, "error reading super, ret %d", ret);

	error_exit((super->flags & SCOUTFS_FLAG_IS_META_BDEV) == 0, "super block is not meta dev");

	ret = scoutfs_parallel_restore_create_writer(&wri);
	error_exit(ret, "create writer %d", ret);

	ret = scoutfs_parallel_restore_import_super(wri, super, dev_fd);
	error_exit(ret, "import super %d", ret);

	slices = calloc(2, sizeof(struct scoutfs_parallel_restore_slice));
	error_exit(!slices, "alloc slices");

	scoutfs_parallel_restore_init_slices(wri, slices, 2);

	ret = scoutfs_parallel_restore_add_slice(wri, &slices[0]);
	error_exit(ret, "add slices[0] %d", ret);

	args = calloc(1, sizeof(struct writer_args));
	error_exit(!args, "alloc writer args");

	args->dev_fd = dev_fd;
	args->slice = slices[1];
	args->pair_fd = pair[1];
	list_add_tail(&args->head, &writers);

	/* fork writer process */
	pid = fork();
	error_exit(pid == -1, "fork error");

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGHUP);
		error_exit(ret < 0, "failed to set parent death sig");

		errno = posix_memalign((void **)&bufp, 4096, BUF_SIZ);
		error_exit(errno, "error allocating block bufp "ERRF, ERRA);

		ret = scoutfs_parallel_restore_create_writer(&pwri);
		error_exit(ret, "create pwriter %d", ret);

		ret = scoutfs_parallel_restore_add_slice(pwri, &args->slice);
		error_exit(ret, "add pslice %d", ret);

		memset(&res, 0, sizeof(res));

		restore_path(pwri, args, &res, bufp, opts->source_dir, SCOUTFS_ROOT_INO);

		ret = restore_quotas(pwri, get_quota_ioctl, opts->source_dir);
		error_exit(ret, "quota add %d", ret);

		res.complete = true;

		write_bufs_and_send(pwri, buf, args->dev_fd, &res, true, args->pair_fd);

		scoutfs_parallel_restore_destroy_writer(&pwri);
		free(bufp);

		exit(0);
	};

	/* read results and wait for writer to finish */
	tot_bytes = 0;
	tot_dirs = 1;
	tot_files = 0;
	for (;;) {
		ret = read(pair[0], &res, sizeof(struct write_result));
		error_exit(ret != sizeof(struct write_result), "result read error %d", ret);

		ret = scoutfs_parallel_restore_add_progress(wri, &res.prog);
		error_exit(ret, "add thr prog %d", ret);

		if (res.slice.meta_len != 0) {
			ret = scoutfs_parallel_restore_add_slice(wri, &res.slice);
			error_exit(ret, "add thr slice %d", ret);

			if (res.complete)
				break;
		}

		tot_bytes += le64_to_cpu(res.bytes_written);
		tot_files += le64_to_cpu(res.files_created);
		tot_dirs += le64_to_cpu(res.dirs_created);
	}

	tot_bytes += write_bufs(wri, buf, args->dev_fd);

	fprintf(stdout, "Wrote %lld directories, %lld files, %lld bytes total\n",
		tot_dirs, tot_files, tot_bytes);

	/* write super to finalize */
	ret = scoutfs_parallel_restore_export_super(wri, super);
	error_exit(ret, "update super %d", ret);

	ret = pwrite(dev_fd, super, SCOUTFS_BLOCK_SM_SIZE,
		     SCOUTFS_SUPER_BLKNO << SCOUTFS_BLOCK_SM_SHIFT);
	error_exit(ret != SCOUTFS_BLOCK_SM_SIZE, "error writing super, ret %d", ret);

	scoutfs_parallel_restore_destroy_writer(&wri);

	if (dev_fd >= 0)
		close(dev_fd);
	if (pair[0] > 0)
		close(pair[0]);
	if (pair[1] > 0)
		close(pair[1]);
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

	free(opts.meta_path);
	free(opts.source_dir);

	list_for_each_entry_safe(hh, hh_tmp, &hardlinks, head) {
		list_del_init(&hh->head);
		free(hh);
	}

	return ret == 0 ? 0 : 1;
}
