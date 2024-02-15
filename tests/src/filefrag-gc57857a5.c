/*
 * filefrag.c -- report if a particular file is fragmented
 *
 * Copyright 2003 by Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

/*
 * This copy of filefrag.c was created from e2fsprogs-v1.45.6-26-gc57857a5
 * in order to work around changes in the UNKNOWN flag causing the output to
 * not display phys_offset properly for scoutfs offline extents.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
extern char *optarg;
extern int optind;
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#ifdef HAVE_LINUX_FD_H
#include <linux/fd.h>
#endif

#include <linux/types.h>

#ifndef _LINUX_FIEMAP_H
#define _LINUX_FIEMAP_H

struct fiemap_extent {
	__u64 fe_logical;  /* logical offset in bytes for the start of
			    * the extent from the beginning of the file */
	__u64 fe_physical; /* physical offset in bytes for the start
			    * of the extent from the beginning of the disk */
	__u64 fe_length;   /* length in bytes for this extent */
	__u64 fe_reserved64[2];
	__u32 fe_flags;    /* FIEMAP_EXTENT_* flags for this extent */
	__u32 fe_reserved[3];
};

struct fiemap {
	__u64 fm_start;		/* logical offset (inclusive) at
				 * which to start mapping (in) */
	__u64 fm_length;	/* logical length of mapping which
				 * userspace wants (in) */
	__u32 fm_flags;		/* FIEMAP_FLAG_* flags for request (in/out) */
	__u32 fm_mapped_extents;/* number of extents that were mapped (out) */
	__u32 fm_extent_count;  /* size of fm_extents array (in) */
	__u32 fm_reserved;
#if __GNUC_PREREQ (4, 8)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
	struct fiemap_extent fm_extents[0]; /* array of mapped extents (out) */
#if __GNUC_PREREQ (4, 8)
#pragma GCC diagnostic pop
#endif
};

#if defined(__linux__) && !defined(FS_IOC_FIEMAP)
#define FS_IOC_FIEMAP	_IOWR('f', 11, struct fiemap)
#endif

#define FIEMAP_MAX_OFFSET	(~0ULL)

#define FIEMAP_FLAG_SYNC	0x00000001 /* sync file data before map */
#define FIEMAP_FLAG_XATTR	0x00000002 /* map extended attribute tree */

#define FIEMAP_FLAGS_COMPAT	(FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR)

#define FIEMAP_EXTENT_LAST		0x00000001 /* Last extent in file. */
#define FIEMAP_EXTENT_UNKNOWN		0x00000002 /* Data location unknown. */
#define FIEMAP_EXTENT_DELALLOC		0x00000004 /* Location still pending.
						    * Sets EXTENT_UNKNOWN. */
#define FIEMAP_EXTENT_ENCODED		0x00000008 /* Data can not be read
						    * while fs is unmounted */
#define FIEMAP_EXTENT_DATA_ENCRYPTED	0x00000080 /* Data is encrypted by fs.
						    * Sets EXTENT_NO_BYPASS. */
#define FIEMAP_EXTENT_NOT_ALIGNED	0x00000100 /* Extent offsets may not be
						    * block aligned. */
#define FIEMAP_EXTENT_DATA_INLINE	0x00000200 /* Data mixed with metadata.
						    * Sets EXTENT_NOT_ALIGNED.*/
#define FIEMAP_EXTENT_DATA_TAIL		0x00000400 /* Multiple files in block.
						    * Sets EXTENT_NOT_ALIGNED.*/
#define FIEMAP_EXTENT_UNWRITTEN		0x00000800 /* Space allocated, but
						    * no data (i.e. zero). */
#define FIEMAP_EXTENT_MERGED		0x00001000 /* File does not natively
						    * support extents. Result
						    * merged for efficiency. */
#define FIEMAP_EXTENT_SHARED		0x00002000 /* Space shared with other
						    * files. */

#endif /* _LINUX_FIEMAP_H */

int verbose = 0;
unsigned int blocksize;	/* Use specified blocksize (default 1kB) */
int sync_file = 0;	/* fsync file before getting the mapping */
int xattr_map = 0;	/* get xattr mapping */
int force_bmap;	/* force use of FIBMAP instead of FIEMAP */
int force_extent;	/* print output in extent format always */
int logical_width = 8;
int physical_width = 10;
const char *ext_fmt = "%4d: %*llu..%*llu: %*llu..%*llu: %6llu: %s\n";
const char *hex_fmt = "%4d: %*llx..%*llx: %*llx..%*llx: %6llx: %s\n";

#define FILEFRAG_FIEMAP_FLAGS_COMPAT (FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR)

#define FIBMAP		_IO(0x00, 1)	/* bmap access */
#define FIGETBSZ	_IO(0x00, 2)	/* get the block size used for bmap */

#define LUSTRE_SUPER_MAGIC 0x0BD00BD0

#define	EXT4_EXTENTS_FL			0x00080000 /* Inode uses extents */
#define	EXT3_IOC_GETFLAGS		_IOR('f', 1, long)

static int ulong_log2(unsigned long arg)
{
	int     l = 0;

	arg >>= 1;
	while (arg) {
		l++;
		arg >>= 1;
	}
	return l;
}

static int ulong_log10(unsigned long long arg)
{
	int     l = 0;

	arg = arg / 10;
	while (arg) {
		l++;
		arg = arg / 10;
	}
	return l;
}

static void print_extent_header(void)
{
	printf(" ext: %*s %*s length: %*s flags:\n",
	       logical_width * 2 + 3,
	       "logical_offset:",
	       physical_width * 2 + 3, "physical_offset:",
	       physical_width + 1,
	       "expected:");
}

static void print_flag(__u32 *flags, __u32 mask, char *buf, const char *name)
{
	if ((*flags & mask) == 0)
		return;

	strcat(buf, name);
	*flags &= ~mask;
}

static void print_extent_info(struct fiemap_extent *fm_extent, int cur_ex,
			      unsigned long long expected, int blk_shift,
			      struct stat *st)
{
	unsigned long long physical_blk;
	unsigned long long logical_blk;
	unsigned long long ext_len;
	unsigned long long ext_blks;
	__u32 fe_flags, mask;
	char flags[256] = "";

	/* For inline data all offsets should be in bytes, not blocks */
	if (fm_extent->fe_flags & FIEMAP_EXTENT_DATA_INLINE)
		blk_shift = 0;

	ext_len = fm_extent->fe_length >> blk_shift;
	ext_blks = (fm_extent->fe_length - 1) >> blk_shift;
	logical_blk = fm_extent->fe_logical >> blk_shift;
	if (fm_extent->fe_flags & FIEMAP_EXTENT_UNKNOWN) {
		physical_blk = 0;
	} else {
		physical_blk = fm_extent->fe_physical >> blk_shift;
	}

	if (expected)
		sprintf(flags, ext_fmt == hex_fmt ? "%*llx: " : "%*llu: ",
			physical_width, expected >> blk_shift);
	else
		sprintf(flags, "%.*s  ", physical_width, "                   ");

	fe_flags = fm_extent->fe_flags;
	print_flag(&fe_flags, FIEMAP_EXTENT_LAST, flags, "last,");
	print_flag(&fe_flags, FIEMAP_EXTENT_UNKNOWN, flags, "unknown_loc,");
	print_flag(&fe_flags, FIEMAP_EXTENT_DELALLOC, flags, "delalloc,");
	print_flag(&fe_flags, FIEMAP_EXTENT_ENCODED, flags, "encoded,");
	print_flag(&fe_flags, FIEMAP_EXTENT_DATA_ENCRYPTED, flags,"encrypted,");
	print_flag(&fe_flags, FIEMAP_EXTENT_NOT_ALIGNED, flags, "not_aligned,");
	print_flag(&fe_flags, FIEMAP_EXTENT_DATA_INLINE, flags, "inline,");
	print_flag(&fe_flags, FIEMAP_EXTENT_DATA_TAIL, flags, "tail_packed,");
	print_flag(&fe_flags, FIEMAP_EXTENT_UNWRITTEN, flags, "unwritten,");
	print_flag(&fe_flags, FIEMAP_EXTENT_MERGED, flags, "merged,");
	print_flag(&fe_flags, FIEMAP_EXTENT_SHARED, flags, "shared,");
	/* print any unknown flags as hex values */
	for (mask = 1; fe_flags != 0 && mask != 0; mask <<= 1) {
		char hex[sizeof(mask) * 2 + 4]; /* 2 chars/byte + 0x, + NUL */

		if ((fe_flags & mask) == 0)
			continue;
		sprintf(hex, "%#04x,", mask);
		print_flag(&fe_flags, mask, flags, hex);
	}

	if (fm_extent->fe_logical + fm_extent->fe_length >=
	    (unsigned long long) st->st_size)
		strcat(flags, "eof,");

	/* Remove trailing comma, if any */
	if (flags[0] != '\0')
		flags[strnlen(flags, sizeof(flags)) - 1] = '\0';

	printf(ext_fmt, cur_ex, logical_width, logical_blk,
	       logical_width, logical_blk + ext_blks,
	       physical_width, physical_blk,
	       physical_width, physical_blk + ext_blks,
	       ext_len, flags);
}

static int filefrag_fiemap(int fd, int blk_shift, int *num_extents,
			   struct stat *st)
{
	__u64 buf[2048];	/* __u64 for proper field alignment */
	struct fiemap *fiemap = (struct fiemap *)buf;
	struct fiemap_extent *fm_ext = &fiemap->fm_extents[0];
	struct fiemap_extent fm_last;
	int count = (sizeof(buf) - sizeof(*fiemap)) /
			sizeof(struct fiemap_extent);
	unsigned long long expected = 0;
	unsigned long long expected_dense = 0;
	unsigned long flags = 0;
	unsigned int i;
	int fiemap_header_printed = 0;
	int tot_extents = 0, n = 0;
	int last = 0;
	int rc;

	memset(fiemap, 0, sizeof(struct fiemap));
	memset(&fm_last, 0, sizeof(fm_last));

	if (sync_file)
		flags |= FIEMAP_FLAG_SYNC;

	if (xattr_map)
		flags |= FIEMAP_FLAG_XATTR;

	do {
		fiemap->fm_length = ~0ULL;
		fiemap->fm_flags = flags;
		fiemap->fm_extent_count = count;
		rc = ioctl(fd, FS_IOC_FIEMAP, (unsigned long) fiemap);
		if (rc < 0) {
			static int fiemap_incompat_printed;

			rc = -errno;
			if (rc == -EBADR && !fiemap_incompat_printed) {
				fprintf(stderr, "FIEMAP failed with unknown "
						"flags %x\n",
				       fiemap->fm_flags);
				fiemap_incompat_printed = 1;
			}
			return rc;
		}

		/* If 0 extents are returned, then more ioctls are not needed */
		if (fiemap->fm_mapped_extents == 0)
			break;

		if (verbose && !fiemap_header_printed) {
			print_extent_header();
			fiemap_header_printed = 1;
		}

		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			expected_dense = fm_last.fe_physical +
					 fm_last.fe_length;
			expected = fm_last.fe_physical +
				   fm_ext[i].fe_logical - fm_last.fe_logical;
			if (fm_ext[i].fe_logical != 0 &&
			    fm_ext[i].fe_physical != expected &&
			    fm_ext[i].fe_physical != expected_dense) {
				tot_extents++;
			} else {
				expected = 0;
				if (!tot_extents)
					tot_extents = 1;
			}
			if (verbose)
				print_extent_info(&fm_ext[i], n, expected,
						  blk_shift, st);
			if (fm_ext[i].fe_flags & FIEMAP_EXTENT_LAST)
				last = 1;
			fm_last = fm_ext[i];
			n++;
		}

		fiemap->fm_start = (fm_ext[i - 1].fe_logical +
				    fm_ext[i - 1].fe_length);
	} while (last == 0);

	*num_extents = tot_extents;

	return 0;
}

#define EXT2_DIRECT	12


static int frag_report(const char *filename)
{
	static struct statfs fsinfo;
	static unsigned int blksize;
	struct stat	st;
	int		blk_shift;
	long		fd;
	unsigned long long	numblocks;
	int		num_extents = 1;
	static dev_t	last_device;
	int		width;
	int		rc = 0;

#if defined(HAVE_OPEN64) && !defined(__OSX_AVAILABLE_BUT_DEPRECATED)
	fd = open64(filename, O_RDONLY);
#else
	fd = open(filename, O_RDONLY);
#endif
	if (fd < 0) {
		rc = -errno;
		perror("open");
		return rc;
	}

#if defined(HAVE_FSTAT64) && !defined(__OSX_AVAILABLE_BUT_DEPRECATED)
	if (fstat64(fd, &st) < 0) {
#else
	if (fstat(fd, &st) < 0) {
#endif
		rc = -errno;
		perror("stat");
		goto out_close;
	}

	if ((last_device != st.st_dev) || !st.st_dev) {
		if (fstatfs(fd, &fsinfo) < 0) {
			rc = -errno;
			perror("fstatfs");
			goto out_close;
		}
		if ((ioctl(fd, FIGETBSZ, &blksize) < 0) || !blksize)
			blksize = fsinfo.f_bsize;
		if (verbose)
			printf("Filesystem type is: %lx\n",
			       (unsigned long)fsinfo.f_type);
	}
	st.st_blksize = blksize;

	last_device = st.st_dev;

	width = ulong_log10(fsinfo.f_blocks);
	if (width > physical_width)
		physical_width = width;

	numblocks = (st.st_size + blksize - 1) / blksize;
	if (blocksize != 0)
		blk_shift = ulong_log2(blocksize);
	else
		blk_shift = ulong_log2(blksize);

	width = ulong_log10(numblocks);
	if (width > logical_width)
		logical_width = width;
	if (verbose)
		printf("File size of %s is %llu (%llu block%s of %d bytes)\n",
		       filename, (unsigned long long)st.st_size,
		       numblocks * blksize >> blk_shift,
		       numblocks == 1 ? "" : "s", 1 << blk_shift);

	rc = filefrag_fiemap(fd, blk_shift, &num_extents, &st);

	if (num_extents == 1)
		printf("%s: 1 extent found", filename);
	else
		printf("%s: %d extents found", filename, num_extents);
	fputc('\n', stdout);
out_close:
	close(fd);

	return rc;
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [-b{blocksize}[KMG]] [-BeksvxX] file ...\n",
		progname);
	exit(1);
}

int main(int argc, char**argv)
{
	char **cpp;
	int rc = 0, c;

	while ((c = getopt(argc, argv, "Bb::eksvxX")) != EOF) {
		switch (c) {
		case 'B':
			force_bmap++;
			break;
		case 'b':
			if (optarg) {
				char *end;
				unsigned long val;

				val = strtoul(optarg, &end, 0);
				if (end) {
#if __GNUC_PREREQ (7, 0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#endif
					switch (end[0]) {
					case 'g':
					case 'G':
						val *= 1024;
						/* fall through */
					case 'm':
					case 'M':
						val *= 1024;
						/* fall through */
					case 'k':
					case 'K':
						val *= 1024;
						break;
					default:
						break;
					}
#if __GNUC_PREREQ (7, 0)
#pragma GCC diagnostic pop
#endif
				}
				/* Specifying too large a blocksize will just
				 * shift all extents down to zero length. Even
				 * 1GB is questionable, but caveat emptor. */
				if (val > 1024 * 1024 * 1024) {
					fprintf(stderr,
						"%s: blocksize %lu over 1GB\n",
						argv[0], val);
					usage(argv[0]);
				}
				blocksize = val;
			} else { /* Allow -b without argument for compat. Remove
				  * this eventually so "-b {blocksize}" works */
				fprintf(stderr, "%s: -b needs a blocksize "
					"option, assuming 1024-byte blocks.\n",
					argv[0]);
				blocksize = 1024;
			}
			break;
		case 'e':
			force_extent++;
			if (!verbose)
				verbose++;
			break;
		case 'k':
			blocksize = 1024;
			break;
		case 's':
			sync_file++;
			break;
		case 'v':
			verbose++;
			break;
		case 'x':
			xattr_map++;
			break;
		case 'X':
			ext_fmt = hex_fmt;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (optind == argc)
		usage(argv[0]);

	for (cpp = argv + optind; *cpp != NULL; cpp++) {
		int rc2 = frag_report(*cpp);

		if (rc2 < 0 && rc == 0)
			rc = rc2;
	}

	return -rc;
}
