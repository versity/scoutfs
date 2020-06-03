#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>

/*
 * Read lines of paths from stdin and use them as relative paths to
 * files created under a top level directory.  The final components in
 * all the paths are the files to create.  Directories are only
 * specified indirectly as leading components in the read paths.
 *
 * Files in the same directory are recognized by having the same parent
 * directories in the paths that are read.  All the files in a given
 * directory are read before being created.  The file creation process
 * first creates all the directories and then changes into the directory
 * to create all the file components.  This is to minimize the overhead
 * of each create.  (And to give us the infrastructure to distribute
 * concurrent create work across tasks/processes by groups.)
 *
 * A `-L` flag indicates that the lines read aren't full paths, but are
 * ls output that starts with textual metadata that would otherwise be
 * parsed as very nutty path components.  The metadata is only used to
 * parse paths for regular files, then the paths begin after the
 * metadata.
 */

struct opts {
	unsigned int dry_run:1,
		     ls_output:1,
		     quiet:1,
		     user_xattr:1,
		     same_srch_xattr:1,
		     group_srch_xattr:1,
		     unique_srch_xattr:1;
};

struct str_list {
	struct str_list *next;
	char str[0];
};

struct dir {
	struct str_list *parents;
	struct str_list *files;
	unsigned long nr_files;
};

#define error_exit(cond, fmt, args...)			\
do {							\
	if (cond) {					\
		printf("error: "fmt"\n", ##args);	\
		exit(1);				\
	}						\
} while (0)

#define ERRF " errno %d (%s)"
#define ERRA errno, strerror(errno)

#define USEC_PER_SEC 1000000

static double tv_secf(struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / USEC_PER_SEC);
}

/* return a - b in usecs */
static double tv_sub_secf(struct timeval *a, struct timeval *b)
{
	return tv_secf(a) - tv_secf(b);
}

static char dashes[] = "---------------------------------------------";

static void rate_banner(struct timeval *tot_start, unsigned long tot_dirs,
			unsigned long tot_files, struct timeval *start,
			unsigned long dirs, unsigned long files,
			unsigned long lines)
{
	struct timeval now;
	double secs;

	gettimeofday(&now, NULL);

	if (lines % 25 == 0) {
		printf("%.15s%9s%.14s | %.10s%10s%.10s\n",
		       dashes, " overall ", dashes,
		       dashes, " previous ", dashes);
		printf("%7s %9s %7s %5s %6s | "
		       "%4s %6s %5s %5s %6s\n",
		       "dirs", "files", "secs", "d/s", "f/s",
		       "dirs", "files", "secs", "d/s", "f/s");
	}

	secs = tv_sub_secf(&now, tot_start);
	printf("%7lu %9lu %7.2f %5.0f %6.0f | ",
	       tot_dirs, tot_files, secs, (double)tot_dirs / secs,
	       (double)tot_files / secs);

	secs = tv_sub_secf(&now, start);
	printf("%4lu %6lu %5.2f %5.0f %6.0f\n",
	       dirs, files, secs, (double)dirs / secs,
	       (double)files / secs);
}

static void free_str_list(struct str_list *s)
{
	struct str_list *next;

	while (s) {
		next = s->next;
		free(s);
		s = next;
	}
}

static void free_dir(struct dir *dir)
{
	free_str_list(dir->parents);
	free_str_list(dir->files);
	free(dir);
}

static void create_dir(struct dir *dir, struct opts *opts,
		       unsigned long long counter)
{
	struct str_list *s;
	char name[100];
	char val[] = "v";
	size_t vs = sizeof(val);
	int rc;
	int i;

	for (s = dir->parents; s; s = s->next) {
		rc = access(s->str, R_OK|W_OK|X_OK);
		error_exit(rc && errno != ENOENT, "stat %s failed"ERRF,
			   s->str, ERRA);
		if (rc == -1 && errno == ENOENT) {
			rc = mkdir(s->str, 0755);
			error_exit(rc, "mkdir %s failed"ERRF, s->str, ERRA);
		}
		rc = chdir(s->str);
		error_exit(rc, "chdir %s failed"ERRF, s->str, ERRA);
	}

	for (s = dir->files, i = 0; s; s = s->next, i++) {
		rc = mknod(s->str, S_IFREG | 0644, 0);
		error_exit(rc, "mknod %s failed"ERRF, s->str, ERRA);

		rc = 0;
		if (rc == 0 && opts->user_xattr) {
			strcpy(name, "user.scoutfs_bcp");
			rc = setxattr(s->str, name, val, vs, 0);
		}
		if (rc == 0 && opts->same_srch_xattr) {
			strcpy(name, "scoutfs.srch.scoutfs_bcp");
			rc = setxattr(s->str, name, val, vs, 0);
		}
		if (rc == 0 && opts->group_srch_xattr) {
			snprintf(name, sizeof(name),
				 "scoutfs.srch.scoutfs_bcp.group.%llu",
				 (counter + i) / 10000);
			rc = setxattr(s->str, name, val, vs, 0);
		}
		if (rc == 0 && opts->unique_srch_xattr) {
			snprintf(name, sizeof(name),
				 "scoutfs.srch.scoutfs_bcp.unique.%llu",
				 counter + i);
			rc = setxattr(s->str, name, val, vs, 0);
		}

		error_exit(rc, "setxattr %s %s failed"ERRF, s->str, name, ERRA);
	}
}

#define BUF_SIZE	(2 * 1024 * 1024)
#define BUF_READ_SIZE	(BUF_SIZE / 2)

static struct str_list *alloc_str(struct str_list *prev, char *str, int len)
{
	struct str_list *s = malloc(sizeof(struct str_list) + len + 1);

	error_exit(!s, "allocating path memory failed"ERRF, ERRA);

	s->next = NULL;
	memcpy(s->str, str, len);
	s->str[len] = '\0';
	return s;
}

static int equal_lists(struct str_list *a, struct str_list *b)
{
	while(a && b && !strcmp(a->str, b->str)) {
		a = a->next;
		b = b->next;
	}

	return a == NULL && b == NULL;
}

static void parse_path(char *str, int len, struct str_list **parents,
		       struct str_list **file)
{
	struct str_list **prev;
	struct str_list *s;
	char *sl;
	char *c;

	*parents = NULL;
	prev = parents;

	c = str;
	while ((sl = index(c, '/'))) {
		s = alloc_str(s, c, sl - c);
		*prev = s;
		prev = &s->next;
		c = sl + 1;
	}

	*file = alloc_str(s, c, len - (c - str));
}

static struct dir *parse_dir(int fd, char *buf, unsigned int *_buf_off,
			     unsigned int *_buf_len, int ls_output)
{
	unsigned int buf_off = *_buf_off;
	unsigned int buf_len = *_buf_len;
	struct str_list *last_file = NULL;
	struct str_list *parents;
	struct str_list *file;
	struct dir *dir = NULL;
	ssize_t ret;
	char *nl;
	char *c;
	int len;

	for (;;) {
		/* move to the front and read if we might truncate a path */
		if (buf_off > 0 && buf_len < PATH_MAX) {
			memmove(buf, buf + buf_off, buf_len);
			buf_off = 0;
		}

		/* read another chunk into the end of the buf */
		if (BUF_SIZE - (buf_off + buf_len) > BUF_READ_SIZE) {
			ret = read(fd, buf + buf_off + buf_len, BUF_READ_SIZE);
			error_exit(ret < 0, "stdin read returned %zd"ERRF,
				   ret, ERRA);
			buf_len += ret;
		}

		/* done if nothing left to do */
		if (buf_len == 0)
			break;

		/* find and null the next path delmiter */
		nl = index(buf + buf_off, '\n');
		if (!nl) {
			/* assume bytes till eof are last path */
			error_exit(buf_len >= PATH_MAX,
				   "%u tail bytes without \\n", buf_len);
			nl = buf + buf_off + buf_len;
			buf_len++; /* read never fills the buf */
		}
		*nl = '\0';
		c = buf + buf_off;

		/* drop this line from the front of the buf */
		len = (nl + 1) - (buf + buf_off);
		buf_off += len;
		buf_len -= len;

		/* only parse regular files in ls output */
		if (ls_output && *c != '-')
			continue;

		/* skip to relative path in ls output */
		if (ls_output) {
			while(*c != '.' && *(c+1) != '/')
				c = index(c + 1, '.');
			/* no relative path */
			if (*c == '\0')
				continue;
		}

		/* trim leading slashes or ./ */
		while (*c == '/')
			c++;
		while (*c == '.' && *(c+1) == '/')
			c += 2;

		/* skip . and .. in case they snuck in */
		if ((*c == '.' && *(c+1) == '\0') ||
		    (*c == '.' && *(c+1) == '.' && *(c+2) == '\0'))
			continue;

		parse_path(c, nl - c, &parents, &file);

		/* add our file if we're in the same dir */
		if (dir && equal_lists(dir->parents, parents)) {
			last_file->next = file;
			last_file = file;
			dir->nr_files++;
			free_str_list(parents);
			continue;
		}

		/* return a dir once we have all its files */
		if (dir) {
			/* .. and reparse this path again :/ */
			*nl = '\n';
			buf_off -= len;
			buf_len += len;
			break;
		}

		/* start a new dir */
		dir = malloc(sizeof(struct dir));
		error_exit(!dir, "dir memory allocation failure"ERRF, ERRA);
		dir->parents = parents;
		dir->files = file;
		dir->nr_files = 1;
		last_file = file;
	}

	*_buf_off = buf_off;
	*_buf_len = buf_len;
	return dir;
}

static void usage(void)
{
	printf("usage:\n"
	       " -d DIR | create all files in DIR top level directory\n"
	       " -n     | dry run, only parse, don't create any files\n"
	       " -q     | quiet, don't regularly print rates\n"
	       " -L     | parse ls output; only reg, skip meta, paths at ./\n"
	       " -X     | set the same user. xattr name in all files\n"
	       " -S     | set the same .srch. xattr name in all files\n"
	       " -G     | set a .srch. xattr name shared by groups of files\n"
	       " -U     | set a unique .srch. xattr name in all files\n");
}

int main(int argc, char **argv)
{
	unsigned int buf_off = 0;
	unsigned int buf_len = 0;
	unsigned long done_dirs = 0;
	unsigned long done_files = 0;
	unsigned long last_dirs = 0;
	unsigned long last_files = 0;
	unsigned long banner_lines = 0;
	char *top_dir = NULL;
	struct timeval last_start;
	struct timeval start;
	struct opts opts;
	struct dir *dir;
	char *buf;
	int rc;
	int c;

	memset(&opts, 0, sizeof(opts));

        while ((c = getopt(argc, argv, "d:nqLXSGU")) != -1) {
                switch(c) {
                case 'd':
                        top_dir = strdup(optarg);
                        break;
                case 'n':
                        opts.dry_run = 1;
                        break;
                case 'q':
                        opts.quiet = 1;
                        break;
                case 'L':
                        opts.ls_output = 1;
                        break;
                case 'X':
                        opts.user_xattr = 1;
                        break;
                case 'S':
                        opts.same_srch_xattr = 1;
                        break;
                case 'G':
                        opts.group_srch_xattr = 1;
                        break;
                case 'U':
                        opts.unique_srch_xattr = 1;
                        break;
                case '?':
                        printf("Unknown option '%c'\n", optopt);
                        usage();
			exit(1);
                }
        }

	if (!opts.dry_run) {
		error_exit(!top_dir,
			   "must specify top level directory with -d");

		error_exit(access(top_dir, R_OK|W_OK|X_OK),
			"top level dir %s isn't accessible for read/write"ERRF,
			top_dir, ERRA);
	}

	buf = malloc(BUF_SIZE);
	error_exit(!buf, "%u buf alloc failed"ERRF, BUF_SIZE, ERRA);

	if (!opts.dry_run) {
		rc = chdir(top_dir);
		error_exit(rc, "chdir %s failed"ERRF, top_dir, ERRA);
	} else {
		printf("(dry run: printing final path reading rate)\n");
	}

	gettimeofday(&start, NULL);
	last_start = start;

	for (;;) {

		dir = parse_dir(STDIN_FILENO, buf, &buf_off, &buf_len,
				opts.ls_output);
		if (dir == NULL)
			break;
		if (!opts.dry_run)
			create_dir(dir, &opts, done_files);
		done_files += dir->nr_files;
		done_dirs++;
		free_dir(dir);

		if (!opts.dry_run && !opts.quiet &&
		    (done_files - last_files) >= 10000) {
			rate_banner(&start, done_dirs, done_files, &last_start,
				    done_dirs - last_dirs,
				    done_files - last_files, banner_lines++);
			last_dirs = done_dirs;
			last_files = done_files;
			gettimeofday(&last_start, NULL);
		}

		if (!opts.dry_run) {
			rc = chdir(top_dir);
			error_exit(rc, "chdir %s failed"ERRF, top_dir, ERRA);
		}
	}

	rate_banner(&start, done_dirs, done_files, &last_start,
		    done_dirs - last_dirs, done_files - last_files, 1);

	free(buf);

	return 0;
}
