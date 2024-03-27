#define _GNU_SOURCE /* O_DIRECT */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <argp.h>

#include "sparse.h"
#include "bitmap.h"
#include "parse.h"
#include "util.h"
#include "format.h"
#include "crc.h"
#include "cmd.h"
#include "dev.h"

#include "alloc.h"
#include "block.h"
#include "btree.h"
#include "log_trees.h"
#include "super.h"

/* huh. */
#define OFF_MAX (off_t)((u64)((off_t)~0ULL) >> 1)

#define SCOUTFS_META_IMAGE_HEADER_MAGIC		0x8aee00d098fa60c5ULL
#define SCOUTFS_META_IMAGE_BLOCK_HEADER_MAGIC	0x70bd5e9269effd86ULL

struct scoutfs_meta_image_header {
	__le64 magic;
	__le64 total_bytes;
	__le32 version;
} __packed;

struct scoutfs_meta_image_block_header {
	__le64 magic;
	__le64 offset;
	__le32 size;
	__le32 crc;
} __packed;

struct image_args {
	char *meta_device;
	bool is_read;
	bool show_header;
	u64 ra_window;
};

struct block_bitmaps {
	unsigned long *bits;
	u64 size;
	u64 count;
};

#define errf(fmt, args...) \
	dprintf(STDERR_FILENO, fmt, ##args)

static int set_meta_bit(u64 start, u64 len, void *arg)
{
	struct block_bitmaps *bm = arg;
	int ret;

	if (len != 1) {
		ret = -EINVAL;
	} else {
		if (!test_bit(bm->bits, start)) {
			set_bit(bm->bits, start);
			bm->count++;
		}
		ret = 0;
	}

	return ret;
}

static int get_ref_bits(struct block_bitmaps *bm)
{
	struct scoutfs_super_block *super = global_super;
	int ret;
	u64 i;

	/*
	 * There are almost no small blocks we need to read, so we read
	 * them as the large blocks that contain them to simplify the
	 * block reading process.
	 */
	set_meta_bit(SCOUTFS_SUPER_BLKNO >> SCOUTFS_BLOCK_SM_LG_SHIFT, 1, bm);

	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++)
		set_meta_bit((SCOUTFS_QUORUM_BLKNO + i) >> SCOUTFS_BLOCK_SM_LG_SHIFT, 1, bm);

	ret = alloc_root_meta_iter(&super->meta_alloc[0], set_meta_bit, bm) ?:
	      alloc_root_meta_iter(&super->meta_alloc[1], set_meta_bit, bm) ?:
	      alloc_root_meta_iter(&super->data_alloc, set_meta_bit, bm) ?:
	      alloc_list_meta_iter(&super->server_meta_avail[0], set_meta_bit, bm) ?:
	      alloc_list_meta_iter(&super->server_meta_avail[1], set_meta_bit, bm) ?:
	      alloc_list_meta_iter(&super->server_meta_freed[0], set_meta_bit, bm) ?:
	      alloc_list_meta_iter(&super->server_meta_freed[1], set_meta_bit, bm) ?:
	      btree_meta_iter(&super->fs_root, set_meta_bit, bm) ?:
	      btree_meta_iter(&super->logs_root, set_meta_bit, bm) ?:
	      btree_meta_iter(&super->log_merge, set_meta_bit, bm) ?:
	      btree_meta_iter(&super->mounted_clients, set_meta_bit, bm) ?:
	      btree_meta_iter(&super->srch_root, set_meta_bit, bm) ?:
	      log_trees_meta_iter(set_meta_bit, bm);

	return ret;
}

/*
 * Note that this temporarily modifies the header that it's given.
 */
static __le32 calc_crc(struct scoutfs_meta_image_block_header *bh, void *buf, size_t size)
{
	__le32 saved = bh->crc;
	u32 crc = ~0;

	bh->crc = 0;
	crc = crc32c(crc, bh, sizeof(*bh));
	crc = crc32c(crc, buf, size);
	bh->crc = saved;

	return cpu_to_le32(crc);
}

static void printf_header(struct scoutfs_meta_image_header *hdr)
{
	errf("magic: 0x%016llx\n"
	     "total_bytes: %llu\n"
	     "version: %u\n",
	       le64_to_cpu(hdr->magic),
	       le64_to_cpu(hdr->total_bytes),
	       le32_to_cpu(hdr->version));
}

typedef ssize_t (*rw_func_t)(int fd, void *buf, size_t count, off_t offset);

static inline ssize_t rw_read(int fd, void *buf, size_t count, off_t offset)
{
	return read(fd, buf, count);
}

static inline ssize_t rw_pread(int fd, void *buf, size_t count, off_t offset)
{
	return pread(fd, buf, count, offset);
}

static inline ssize_t rw_write(int fd, void *buf, size_t count, off_t offset)
{
	return write(fd, buf, count);
}

static inline ssize_t rw_pwrite(int fd, void *buf, size_t count, off_t offset)
{
	return pwrite(fd, buf, count, offset);
}

static int rw_full_count(rw_func_t func, u64 *tot, int fd, void *buf, size_t count, off_t offset)
{
	ssize_t sret;

	while (count > 0) {
		sret = func(fd, buf, count, offset);
		if (sret <= 0 || sret > count) {
			if (sret < 0)
				return -errno;
			else
				return -EIO;
		}

		if (tot)
			*tot += sret;
		buf += sret;
		count -= sret;
	}

	return 0;
}

static int read_image(struct image_args *args, int fd, struct block_bitmaps *bm)
{
	struct scoutfs_meta_image_block_header bh;
	struct scoutfs_meta_image_header hdr;
	u64 opening;
	void *buf;
	off_t off;
	u64 bit;
	u64 ra;
	int ret;

	buf = malloc(SCOUTFS_BLOCK_LG_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}

	hdr.magic = cpu_to_le64(SCOUTFS_META_IMAGE_HEADER_MAGIC);
	hdr.total_bytes = cpu_to_le64(sizeof(hdr) +
				      (bm->count * (SCOUTFS_BLOCK_LG_SIZE + sizeof(bh))));
	hdr.version = cpu_to_le32(1);

	if (args->show_header) {
		printf_header(&hdr);
		ret = 0;
		goto out;
	}

	ret = rw_full_count(rw_write, NULL, STDOUT_FILENO, &hdr, sizeof(hdr), 0);
	if (ret < 0)
		goto out;

	opening = args->ra_window;
	ra = 0;
	bit = 0;

	for (bit = 0; (bit = find_next_set_bit(bm->bits, bit, bm->size)) < bm->size; bit++) {

		/* readahead to open the full window, then a block at a time */
		do {
			ra = find_next_set_bit(bm->bits, ra, bm->size);
			if (ra < bm->size) {
				off = ra << SCOUTFS_BLOCK_LG_SHIFT;
				posix_fadvise(fd, off, SCOUTFS_BLOCK_LG_SIZE, POSIX_FADV_WILLNEED);
				ra++;
				if (opening)
					opening -= min(opening, SCOUTFS_BLOCK_LG_SIZE);
			}
		} while (opening > 0);

		off = bit << SCOUTFS_BLOCK_LG_SHIFT;
		ret = rw_full_count(rw_pread, NULL, fd, buf, SCOUTFS_BLOCK_LG_SIZE, off);
		if (ret < 0)
			goto out;

		/*
		 * Might as well try to drop the pages we've used to
		 * reduce memory pressure on our read-ahead pages that
		 * are waiting.
		 */
		posix_fadvise(fd, off, SCOUTFS_BLOCK_LG_SIZE, POSIX_FADV_DONTNEED);

		bh.magic = SCOUTFS_META_IMAGE_BLOCK_HEADER_MAGIC;
		bh.offset = cpu_to_le64(off);
		bh.size = cpu_to_le32(SCOUTFS_BLOCK_LG_SIZE);
		bh.crc = calc_crc(&bh, buf, SCOUTFS_BLOCK_LG_SIZE);

		ret = rw_full_count(rw_write, NULL, STDOUT_FILENO, &bh, sizeof(bh), 0) ?:
		      rw_full_count(rw_write, NULL, STDOUT_FILENO, buf, SCOUTFS_BLOCK_LG_SIZE, 0);
		if (ret < 0)
			goto out;
	}

out:
	free(buf);

	return ret;
}

static int invalid_header(struct scoutfs_meta_image_header *hdr)
{
	if (le64_to_cpu(hdr->magic) != SCOUTFS_META_IMAGE_HEADER_MAGIC) {
		errf("bad image header magic 0x%016llx (!= expected %016llx)\n",
		       le64_to_cpu(hdr->magic), SCOUTFS_META_IMAGE_HEADER_MAGIC);

	} else if (le32_to_cpu(hdr->version) != 1) {
		errf("unknown image header version %u\n", le32_to_cpu(hdr->version));

	} else {
		return 0;
	}

	return -EIO;
}

/*
 * Doesn't catch offset+size overflowing, presumes pwrite() will return
 * an error.
 */
static int invalid_block_header(struct scoutfs_meta_image_block_header *bh)
{
	if (le64_to_cpu(bh->magic) != SCOUTFS_META_IMAGE_BLOCK_HEADER_MAGIC) {
		errf("bad block header magic 0x%016llx (!= expected %016llx)\n",
		       le64_to_cpu(bh->magic), SCOUTFS_META_IMAGE_BLOCK_HEADER_MAGIC);

	} else if (le32_to_cpu(bh->size) == 0) {
		errf("invalid block header size %u\n", le32_to_cpu(bh->size));

	} else if (le32_to_cpu(bh->size) > SIZE_MAX) {
		errf("block header size %u too large for size_t (> %zu)\n",
		       le32_to_cpu(bh->size), (size_t)SIZE_MAX);

	} else if (le64_to_cpu(bh->offset) > OFF_MAX) {
		errf("block header offset %llu too large for off_t (> %llu)\n",
		       le64_to_cpu(bh->offset), (u64)OFF_MAX);

	} else {
		return 0;
	}

	return -EIO;
}

static int write_image(struct image_args *args, int fd, struct block_bitmaps *bm)
{
	struct scoutfs_meta_image_block_header bh;
	struct scoutfs_meta_image_header hdr;
	size_t writeback_batch = (2 * 1024 * 1024);
	size_t buf_size;
	size_t dirty;
	size_t size;
	off_t first;
	off_t last;
	off_t off;
	__le32 calc;
	void *buf;
	u64 tot;
	int ret;

	tot = 0;

	ret = rw_full_count(rw_read, &tot, STDIN_FILENO, &hdr, sizeof(hdr), 0);
	if (ret < 0)
		goto out;

	if (args->show_header) {
		printf_header(&hdr);
		ret = 0;
		goto out;
	}

	ret = invalid_header(&hdr);
	if (ret < 0)
		goto out;

	dirty = 0;
	first = OFF_MAX;
	last = 0;
	buf = NULL;
	buf_size = 0;

	while (tot < le64_to_cpu(hdr.total_bytes)) {

		ret = rw_full_count(rw_read, &tot, STDIN_FILENO, &bh, sizeof(bh), 0);
		if (ret < 0)
			goto out;

		ret = invalid_block_header(&bh);
		if (ret < 0)
			goto out;

		size = le32_to_cpu(bh.size);
		if (buf_size < size) {
			buf = realloc(buf, size);
			if (!buf) {
				ret = -ENOMEM;
				goto out;
			}

			buf_size = size;
		}

		ret = rw_full_count(rw_read, &tot, STDIN_FILENO, buf, size, 0);
		if (ret < 0)
			goto out;

		calc = calc_crc(&bh, buf, size);
		if (calc != bh.crc) {
			errf("crc err");
			ret = -EIO;
			goto out;
		}

		off = le64_to_cpu(bh.offset);

		ret = rw_full_count(rw_pwrite, NULL, fd, buf, size, off);
		if (ret < 0)
			goto out;

		dirty += size;
		first = min(first, off);
		last = max(last, off);
		if (dirty >= writeback_batch) {
			posix_fadvise(fd, first, last, POSIX_FADV_DONTNEED);
			dirty = 0;
			first = OFF_MAX;
			last = 0;
		}
	}

	ret = fsync(fd);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}

out:
	return ret;
}

static int do_image(struct image_args *args)
{
	struct block_bitmaps bm = { .bits = NULL };
	int meta_fd = -1;
	u64 dev_size;
	mode_t mode;
	int ret;

	mode = args->is_read ? O_RDONLY : O_RDWR;

	meta_fd = open(args->meta_device, mode);
	if (meta_fd < 0) {
		ret = -errno;
		errf("failed to open meta device '%s': %s (%d)\n",
		     args->meta_device, strerror(errno), errno);
		goto out;
	}

	if (args->is_read) {
		ret = flush_device(meta_fd);
		if (ret < 0)
			goto out;

		ret = get_device_size(args->meta_device, meta_fd, &dev_size);
		if (ret < 0)
			goto out;

		bm.size = DIV_ROUND_UP(dev_size, SCOUTFS_BLOCK_LG_SIZE);
		bm.bits = calloc(1, round_up(bm.size, BITS_PER_LONG) / 8);
		if (!bm.bits) {
			ret = -ENOMEM;
			goto out;
		}

		ret = block_setup(meta_fd, 128 * 1024 * 1024, 32 * 1024 * 1024) ?:
		      check_supers(-1, false) ?:
		      get_ref_bits(&bm) ?:
		      read_image(args, meta_fd, &bm);
		block_shutdown();
	} else {
		ret = write_image(args, meta_fd, &bm);
	}
out:
	free(bm.bits);

	if (meta_fd >= 0)
		close(meta_fd);

	return ret;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct image_args *args = state->input;
	int ret;

	switch (key) {
	case 'h':
		args->show_header = true;
		break;
	case 'r':
		ret = parse_u64(arg, &args->ra_window);
		if (ret)
			argp_error(state, "readahead winddoe parse error");
		break;
	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than two device arguments given");
		break;
	case ARGP_KEY_FINI:
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");
		break;
	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "show-header", 'h', NULL, 0, "Print image header and exit without processing stream" },
	{ "readahead", 'r', "NR", 0, "Maintain read-ahead window of NR blocks" },
	{ NULL }
};

static struct argp read_image_argp = {
	options,
	parse_opt,
	"META-DEVICE",
	"Read metadata image stream from metadata device file"
};

#define DEFAULT_RA_WINDOW (512 * 1024)

static int read_image_cmd(int argc, char **argv)
{
	struct image_args image_args = {
		.is_read = true,
		.ra_window = DEFAULT_RA_WINDOW,
	};
	int ret;

	ret = argp_parse(&read_image_argp, argc, argv, 0, NULL, &image_args);
	if (ret)
		return ret;

	return do_image(&image_args);
}

static struct argp write_image_argp = {
	options,
	parse_opt,
	"META-DEVICE",
	"Write metadata image stream to metadata device file"
};

static int write_image_cmd(int argc, char **argv)
{
	struct image_args image_args = {
		.is_read = false,
		.ra_window = DEFAULT_RA_WINDOW,
	};
	int ret;

	ret = argp_parse(&write_image_argp, argc, argv, 0, NULL, &image_args);
	if (ret)
		return ret;

	return do_image(&image_args);
}

static void __attribute__((constructor)) image_ctor(void)
{
	cmd_register_argp("read-metadata-image", &read_image_argp, GROUP_CORE, read_image_cmd);
	cmd_register_argp("write-metadata-image", &write_image_argp, GROUP_CORE, write_image_cmd);
}
