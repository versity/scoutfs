#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "key.h"

/*
 * To print keys we wrap the key snprintf code from the kernel with a
 * few support functions.  We need a few functions that the kernel has
 * that we don't provide, then we implement our printing function by
 * allocating a buffer for the formatted output then just printing it.
 *
 * To update the key printing code from the kernel we just need to make
 * scoutfs_key_str_size() static and replace the snprintf call with the
 * kernel's "%phN" format with the call to our replacement.
 *
 * This is not efficient but this isn't a performant path.
 */

#define min_t(t, a, b) min(a, b)

struct scoutfs_key_buf {
	void *data;
	unsigned key_len;
};

/*
 * like snprintf(buf, size, "%*phN", nr, bytes) in the kernel, but this
 * is only called when there's room for the formatted output because
 * we've already been through once with a 0 buffer to allocate a buffer
 * for the output.
 */
static int snprintf_phN(char *buf, size_t size, unsigned nr, char *bytes)
{
	int ret = 0;
	int i;

	for (i = 0; i < nr; i++)
		ret += sprintf(buf + ret, "%02x", bytes[i]);

	return ret;
}

static char *memchr_inv(char *str, int c, size_t len)
{
	while (len--) {
		if (*(str++) != c)
			return str - 1;
	}

	return NULL;
}

static int scoutfs_key_str_size(char *buf, struct scoutfs_key_buf *key,
				size_t size);

void print_key(void *key_data, unsigned key_len)
{
	struct scoutfs_key_buf key = {.data = key_data, .key_len = key_len};
	char *buf;
	int size;

	size = scoutfs_key_str_size(NULL, &key, 0);
	if (size > 0) {
		buf = malloc(size);
		if (buf) {
			size = scoutfs_key_str_size(buf, &key, size);
			if (size > 0)
				printf("%s", buf);
			free(buf);
		}
	}
}

/* ------ copied code follows --------- */

#define snprintf_null(buf, size, fmt, args...) \
	(snprintf((buf), (size), fmt, ##args) + 1)

/*
 * Store a formatted string representing the key in the buffer.  The key
 * must be at least min_len to store the data needed by the format at
 * all.  fmt_len is the length of data that's used by the format.  These
 * are different because we have badly designed keys with variable
 * length data that isn't described by the key.  It's assumed from the
 * length of the key.  Take dirents -- they need to at least have a
 * dirent struct, but the name length is the rest of the key.
 *
 * (XXX And this goes horribly wrong when we pad out dirent keys to max
 * len to increment at high precision.  We'll never see these items used
 * by real fs code, but temporary keys and range endpoints can be full
 * precision and we can try and print them and get very confused.  We
 * need to rev the format to include explicit lengths.)
 *
 * If the format doesn't cover the entire key then we append more
 * formatting to represent the trailing bytes: runs of zeros compresesd
 * to _ and then hex output of non-zero bytes.
 */
static int snprintf_key(char *buf, size_t size, struct scoutfs_key_buf *key,
			unsigned min_len, unsigned fmt_len,
			const char *fmt, ...)

{
	va_list args;
	char *data;
	char *end;
	int left;
	int part;
	int ret;
	int nr;

	if (key->key_len < min_len)
		return snprintf_null(buf, size, "[trunc len %u < min %u]",
				     key->key_len, min_len);

	if (fmt_len == 0)
		fmt_len = min_len;

	va_start(args, fmt);
	ret = vsnprintf(buf, size, fmt, args);
	va_end(args);
	/* next formatting overwrites null */
	if (buf) {
		buf += ret;
		size -= min_t(int, size, ret);
	}

	data = key->data + fmt_len;
	left = key->key_len - fmt_len;

	while (left && (!buf || size > 1)) {
		/* compress runs of zero bytes to _ */
		end = memchr_inv(data, 0, left);
		nr = end ? end - data : left;
		if (nr) {
			if (buf) {
				*(buf++) = '_';
				size--;
			}
			ret++;
			data += nr;
			left -= nr;
			continue;
		}

		/*
		 * hex print non-zero bytes.  %ph is limited to 64 bytes
		 * and is buggy in that it still tries to print to buf
		 * past size.  (so buf = null, size = 0 crashes instead
		 * of printing the length of the formatted string.)
		 */
		end = memchr(data, 0, left);
		nr = end ? end - data : left;
		nr = min(nr, 64);

		if (buf)
			part = snprintf_phN(buf, size, nr, data);
		else
			part = nr * 2;
		if (buf) {
			buf += part;
			size -= min_t(int, size, part);
		}
		ret += part;

		data += nr;
		left -= nr;
	}

	/* always store and include null */
	if (buf)
		*buf = '\0';
	return ret + 1;
}

typedef int (*key_printer_t)(char *buf, struct scoutfs_key_buf *key,
			     size_t size);

static int pr_ino_idx(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	static char *type_strings[] = {
		[SCOUTFS_INODE_INDEX_SIZE_TYPE]		= "siz",
		[SCOUTFS_INODE_INDEX_META_SEQ_TYPE]	= "msq",
		[SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE]	= "dsq",
	};
	struct scoutfs_inode_index_key *ikey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_inode_index_key), 0,
			    "iin.%s.%llu.%u.%llu",
			    type_strings[ikey->type], be64_to_cpu(ikey->major),
			    be32_to_cpu(ikey->minor), be64_to_cpu(ikey->ino));
}

static int pr_free_ext(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_free_extent_blkno_key *fkey = key->data;

	static char *type_strings[] = {
		[SCOUTFS_FREE_EXTENT_BLKNO_TYPE]	= "fno",
		[SCOUTFS_FREE_EXTENT_BLOCKS_TYPE]	= "fks",
	};

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_free_extent_blkno_key), 0,
			    "nod.%llu.%s.%llu.%llu",
			    be64_to_cpu(fkey->node_id),
			    type_strings[fkey->type],
			    be64_to_cpu(fkey->last_blkno),
			    be64_to_cpu(fkey->blocks));
}

static int pr_orphan(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_orphan_key *okey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_orphan_key), 0,
			    "nod.%llu.orp.%llu",
			    be64_to_cpu(okey->node_id),
			    be64_to_cpu(okey->ino));
}

static int pr_inode(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_inode_key *ikey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_inode_key), 0,
			    "fs.%llu.ino",
			    be64_to_cpu(ikey->ino));
}

static int pr_xattr(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_xattr_key *xkey = key->data;
	int len = (int)key->key_len -
		  offsetof(struct scoutfs_xattr_key, name[1]);

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_xattr_key), key->key_len,
			    "fs.%llu.xat.%.*s",
			    be64_to_cpu(xkey->ino), len, xkey->name);
}

static int pr_dirent(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_dirent_key *dkey = key->data;
	int len = (int)key->key_len - sizeof(struct scoutfs_dirent_key);

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_dirent_key), key->key_len,
			    "fs.%llu.dnt.%.*s",
			    be64_to_cpu(dkey->ino), len, dkey->name);
}

static int pr_readdir(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_readdir_key *rkey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_readdir_key), 0,
			    "fs.%llu.rdr.%llu",
			    be64_to_cpu(rkey->ino), be64_to_cpu(rkey->pos));
}

static int pr_link_backref(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_link_backref_key *lkey = key->data;
	int len = (int)key->key_len - sizeof(*lkey);

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_link_backref_key),
			    key->key_len,
			    "fs.%llu.lbr.%llu.%.*s",
			    be64_to_cpu(lkey->ino), be64_to_cpu(lkey->dir_ino),
			    len, lkey->name);
}

static int pr_symlink(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_symlink_key *skey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_symlink_key), 0,
			    "fs.%llu.sym",
			    be64_to_cpu(skey->ino));
}

static int pr_file_ext(char *buf, struct scoutfs_key_buf *key, size_t size)
{
	struct scoutfs_file_extent_key *ekey = key->data;

	return snprintf_key(buf, size, key,
			    sizeof(struct scoutfs_file_extent_key), 0,
			    "fs.%llu.ext.%llu.%llu.%llu.%x",
			    be64_to_cpu(ekey->ino),
			    be64_to_cpu(ekey->last_blk_off),
			    be64_to_cpu(ekey->last_blkno),
			    be64_to_cpu(ekey->blocks),
			    ekey->flags);
}

const static key_printer_t key_printers[SCOUTFS_MAX_ZONE][SCOUTFS_MAX_TYPE] = {
	[SCOUTFS_INODE_INDEX_ZONE][SCOUTFS_INODE_INDEX_SIZE_TYPE] =
		pr_ino_idx,
	[SCOUTFS_INODE_INDEX_ZONE][SCOUTFS_INODE_INDEX_META_SEQ_TYPE] =
		pr_ino_idx,
	[SCOUTFS_INODE_INDEX_ZONE][SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE] =
		pr_ino_idx,
	[SCOUTFS_NODE_ZONE][SCOUTFS_FREE_EXTENT_BLKNO_TYPE] = pr_free_ext,
	[SCOUTFS_NODE_ZONE][SCOUTFS_FREE_EXTENT_BLOCKS_TYPE] = pr_free_ext,
	[SCOUTFS_NODE_ZONE][SCOUTFS_ORPHAN_TYPE] = pr_orphan,
	[SCOUTFS_FS_ZONE][SCOUTFS_INODE_TYPE] = pr_inode,
	[SCOUTFS_FS_ZONE][SCOUTFS_XATTR_TYPE] = pr_xattr,
	[SCOUTFS_FS_ZONE][SCOUTFS_DIRENT_TYPE] = pr_dirent,
	[SCOUTFS_FS_ZONE][SCOUTFS_READDIR_TYPE] = pr_readdir,
	[SCOUTFS_FS_ZONE][SCOUTFS_LINK_BACKREF_TYPE] = pr_link_backref,
	[SCOUTFS_FS_ZONE][SCOUTFS_SYMLINK_TYPE] = pr_symlink,
	[SCOUTFS_FS_ZONE][SCOUTFS_FILE_EXTENT_TYPE] = pr_file_ext,
};

/*
 * Write the null-terminated string that describes the key to the
 * buffer.  The bytes copied (including the null) is returned.  A null
 * buffer can be used to find the string size without writing anything.
 *
 * XXX nonprintable characters in the trace?
 */
static int scoutfs_key_str_size(char *buf, struct scoutfs_key_buf *key,
				size_t size)
{
	u8 zone;
	u8 type;

	if (key == NULL || key->data == NULL)
		return snprintf_null(buf, size, "[NULL]");

	/* always at least zone, some id, and type */
	if (key->key_len < (1 + 8 + 1))
		return snprintf_null(buf, size, "[trunc len %u]", key->key_len);

	zone = *(u8 *)key->data;

	/*
	 * each zone's keys always start with the same fields that let
	 * us deref any key to get the type.  We chose a few representative
	 * keys from each zone to get the type.
	 */
	if (zone == SCOUTFS_INODE_INDEX_ZONE) {
		struct scoutfs_inode_index_key *ikey = key->data;
		type = ikey->type;
	} else if (zone == SCOUTFS_NODE_ZONE) {
		struct scoutfs_free_extent_blkno_key *fkey = key->data;
		type = fkey->type;
	} else if (zone == SCOUTFS_FS_ZONE) {
		struct scoutfs_inode_key *ikey = key->data;
		type = ikey->type;
	} else {
		type = 255;
	}

	if (zone > SCOUTFS_MAX_ZONE || type > SCOUTFS_MAX_TYPE ||
	    key_printers[zone][type] == NULL) {
		return snprintf_null(buf, size, "[unk zone %u type %u]",
				     zone, type);
	}

	return key_printers[zone][type](buf, key, size);
}
