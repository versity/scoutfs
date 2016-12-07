#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <uuid/uuid.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "cmd.h"
#include "crc.h"
#include "buddy.h"
#include "bitops.h"
#include "item.h"

/* XXX maybe these go somewhere */
#define SKF "%llu.%u.%llu"
#define SKA(k) le64_to_cpu((k)->inode), (k)->type, \
		le64_to_cpu((k)->offset)

static void *read_block(int fd, u64 blkno)
{
	ssize_t ret;
	void *buf;

	buf = malloc(SCOUTFS_BLOCK_SIZE);
	if (!buf)
		return NULL;

	ret = pread(fd, buf, SCOUTFS_BLOCK_SIZE, blkno << SCOUTFS_BLOCK_SHIFT);
	if (ret != SCOUTFS_BLOCK_SIZE) {
		fprintf(stderr, "read blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		free(buf);
		buf = NULL;
	}

	return buf;
}

static void *read_segment(int fd, u64 segno)
{
	ssize_t ret;
	void *buf;

	buf = malloc(SCOUTFS_SEGMENT_SIZE);
	if (!buf)
		return NULL;

	ret = pread(fd, buf, SCOUTFS_SEGMENT_SIZE,
		    segno << SCOUTFS_SEGMENT_SHIFT);
	if (ret != SCOUTFS_SEGMENT_SIZE) {
		fprintf(stderr, "read segno %llu returned %zd: %s (%d)\n",
			segno, ret, strerror(errno), errno);
		free(buf);
		buf = NULL;
	}

	return buf;
}

static void print_block_header(struct scoutfs_block_header *hdr)
{
	u32 crc = crc_block(hdr);
	char valid_str[40];

	if (crc != le32_to_cpu(hdr->crc))
		sprintf(valid_str, "(!= %08x) ", crc);
	else
		valid_str[0] = '\0';

	printf("  hdr: crc %08x %sfsid %llx seq %llu blkno %llu\n",
		le32_to_cpu(hdr->crc), valid_str, le64_to_cpu(hdr->fsid),
		le64_to_cpu(hdr->seq), le64_to_cpu(hdr->blkno));
}

static void print_inode(void *key, void *val)
{
	struct scoutfs_inode_key *ikey = key;
	struct scoutfs_inode *inode = val;

	printf("    inode: ino %llu size %llu blocks %llu lctr %llu nlink %u\n"
	       "      uid %u gid %u mode 0%o rdev 0x%x\n"
	       "      salt 0x%x data_version %llu\n"
	       "      atime %llu.%08u ctime %llu.%08u\n"
	       "      mtime %llu.%08u\n",
	       be64_to_cpu(ikey->ino),
	       le64_to_cpu(inode->size), le64_to_cpu(inode->blocks),
	       le64_to_cpu(inode->link_counter),
	       le32_to_cpu(inode->nlink), le32_to_cpu(inode->uid),
	       le32_to_cpu(inode->gid), le32_to_cpu(inode->mode),
	       le32_to_cpu(inode->rdev), le32_to_cpu(inode->salt),
	       le64_to_cpu(inode->data_version),
	       le64_to_cpu(inode->atime.sec),
	       le32_to_cpu(inode->atime.nsec),
	       le64_to_cpu(inode->ctime.sec),
	       le32_to_cpu(inode->ctime.nsec),
	       le64_to_cpu(inode->mtime.sec),
	       le32_to_cpu(inode->mtime.nsec));
}

#if 0

static void print_xattr(struct scoutfs_xattr *xat)
{
	/* XXX check lengths */

	printf("      xattr: name %.*s val_len %u\n",
	       xat->name_len, xat->name, xat->value_len);
}

static void print_xattr_val_hash(__le64 *refcount)
{
	/* XXX check lengths */

	printf("      xattr_val_hash: refcount %llu\n",
	       le64_to_cpu(*refcount));
}

static void print_dirent(struct scoutfs_dirent *dent, unsigned int val_len)
{
	unsigned int name_len = val_len - sizeof(*dent);
	char name[SCOUTFS_NAME_LEN + 1];
	int i;

	for (i = 0; i < min(SCOUTFS_NAME_LEN, name_len); i++)
		name[i] = isprint(dent->name[i]) ?  dent->name[i] : '.';
	name[i] = '\0';

	printf("      dirent: ino: %llu ctr: %llu type: %u name: \"%.*s\"\n",
	       le64_to_cpu(dent->ino), le64_to_cpu(dent->counter),
	       dent->type, i, name);
}

static void print_link_backref(struct scoutfs_link_backref *lref,
			       unsigned int val_len)
{
	printf("      lref: ino: %llu offset: %llu\n",
	       le64_to_cpu(lref->ino), le64_to_cpu(lref->offset));
}

/* for now show the raw component items not the whole path */
static void print_symlink(char *str, unsigned int val_len)
{
	printf("      symlink: %.*s\n", val_len, str);
}

#define EXT_FLAG(f, flags, str) \
	(flags & f) ? str : "", (flags & (f - 1)) ? "|" : ""

static void print_extent(struct scoutfs_key *key,
			 struct scoutfs_extent *ext)
{
	printf("      extent: (offest %llu) blkno %llu, len %llu flags %s%s\n",
	       le64_to_cpu(key->offset), le64_to_cpu(ext->blkno),
	       le64_to_cpu(ext->len),
	       EXT_FLAG(SCOUTFS_EXTENT_FLAG_OFFLINE, ext->flags, "OFF"));
}
#endif

typedef void (*print_func_t)(void *key, void *val);

static print_func_t printers[] = {
	[SCOUTFS_INODE_KEY] = print_inode,
};

static void print_item(struct scoutfs_segment_block *sblk, u32 pos)
{
	struct native_item item;
	void *key;
	void *val;
	__u8 type;

	load_item(sblk, pos, &item);

	key = (char *)sblk + item.key_off;
	val = (char *)sblk + item.val_off;
	type = *(__u8 *)key;

	printf("  [%u]: seq %llu key_off %u val_off %u key_len %u "
	       "val_len %u\n",
		pos, item.seq, item.key_off, item.val_off, item.key_len,
		item.val_len);

	if (type < array_size(printers) && printers[type])
		printers[type](key, val);
	else
		printf(" unknown!\n");
}

static int print_segment(int fd, u64 segno)
{
	struct scoutfs_segment_block *sblk;
	int i;

	sblk = read_segment(fd, segno);
	if (!sblk)
		return -ENOMEM;

	printf("segment segno %llu\n", segno);
//	print_block_header(&sblk->hdr);

	for (i = 0; i < le32_to_cpu(sblk->nr_items); i++)
		print_item(sblk, i);

	free(sblk);

	return 0;
}

static int print_segments(int fd, unsigned long *seg_map, u64 total_segs)
{
	int ret = 0;
	int i = 0;
	int err;

	for (i = 0; 
	     (i = find_next_bit_le(seg_map, total_segs, i)) < total_segs;
	     i++) {

		err = print_segment(fd, i);
		if (err && !ret)
			ret = err;
		i++;
	}

	return ret;
}

static int print_ring_block(int fd, unsigned long *seg_map, u64 blkno)
{
	struct scoutfs_ring_alloc_region *reg;
	struct scoutfs_ring_entry_header *eh;
	struct scoutfs_ring_add_manifest *am;
	struct scoutfs_ring_block *ring;
	u32 off;
	int i;

	ring = read_block(fd, blkno);
	if (!ring)
		return -ENOMEM;

	printf("ring blkno %llu\n", blkno);
	print_block_header(&ring->hdr);

	eh = ring->entries;
	while (eh->len) {
		off = (char *)eh - (char *)ring;
		printf("  [%u]: type %u len %u\n",
			off, eh->type, le16_to_cpu(eh->len));

		switch(eh->type) {

		case SCOUTFS_RING_ADD_MANIFEST:
			am = (void *)eh;
			printf("    add ment: segno %llu seq %llu "
			       "first_len %u last_len %u level %u\n",
			       le64_to_cpu(am->segno),
			       le64_to_cpu(am->seq),
			       le16_to_cpu(am->first_key_len),
			       le16_to_cpu(am->last_key_len),
			       am->level);

			/* XXX verify, 'int nr' limits segno precision */
			set_bit_le(le64_to_cpu(am->segno), seg_map);
			break;

		case SCOUTFS_RING_ADD_ALLOC:
			reg = (void *)eh;
			printf("    add alloc: index %llu bits",
			       le64_to_cpu(reg->index));
			for (i = 0; i < array_size(reg->bits); i++)
				printf(" %016llx", le64_to_cpu(reg->bits[i]));
			printf("\n");
			break;
		}

		eh = (void *)eh + le16_to_cpu(eh->len);
	}

	free(ring);

	return 0;
}

static int print_ring_blocks(int fd, struct scoutfs_super_block *super,
			     unsigned long *seg_map)
{
	int ret = 0;
	u64 blkno;
	u16 index;
	u16 tail;
	int err;

	index = le64_to_cpu(super->ring_head_index);
	tail = le64_to_cpu(super->ring_tail_index);

	for(;;) {
		blkno = le64_to_cpu(super->ring_blkno) + index;

		err = print_ring_block(fd, seg_map, blkno);
		if (err && !ret)
			ret = err;

		if (index == tail)
			break;

		if (++index == le64_to_cpu(super->ring_blocks))
			index = 0;
	};

	return ret;
}

static int print_super_blocks(int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_super_block recent = { .hdr.seq = 0 };
	unsigned long *seg_map;
	char uuid_str[37];
	u64 total_segs;
	u64 longs;
	int ret = 0;
	int i;

	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {
		super = read_block(fd, SCOUTFS_SUPER_BLKNO + i);
		if (!super)
			return -ENOMEM;

		uuid_unparse(super->uuid, uuid_str);

		printf("super blkno %llu\n", (u64)SCOUTFS_SUPER_BLKNO + i);
		print_block_header(&super->hdr);
		printf("  id %llx uuid %s\n",
		       le64_to_cpu(super->id), uuid_str);
		/* XXX these are all in a crazy order */
		printf("  next_ino %llu total_blocks %llu free_blocks %llu\n"
		       "  ring_blkno %llu ring_blocks %llu ring_head %llu\n"
		       "  ring_tail %llu alloc_uninit %llu total_segs %llu\n",
			le64_to_cpu(super->next_ino),
			le64_to_cpu(super->total_blocks),
			le64_to_cpu(super->free_blocks),
			le64_to_cpu(super->ring_blkno),
			le64_to_cpu(super->ring_blocks),
			le64_to_cpu(super->ring_head_index),
			le64_to_cpu(super->ring_tail_index),
			le64_to_cpu(super->alloc_uninit),
			le64_to_cpu(super->total_segs));

		if (le64_to_cpu(super->hdr.seq) > le64_to_cpu(recent.hdr.seq))
			memcpy(&recent, super, sizeof(recent));

		free(super);
	}

	super = &recent;

	/* XXX :P */
	total_segs = le64_to_cpu(super->total_blocks) / SCOUTFS_SEGMENT_BLOCKS;
	longs = DIV_ROUND_UP(total_segs, BITS_PER_LONG);
	seg_map = calloc(longs, sizeof(unsigned long));
	if (!seg_map)
		return -ENOMEM;

	ret = print_ring_blocks(fd, super, seg_map) ?:
	      print_segments(fd, seg_map, total_segs);

	free(seg_map);

	return ret;
}

static int print_cmd(int argc, char **argv)
{
	char *path;
	int ret;
	int fd;

	if (argc != 1) {
		printf("scoutfs print: a single path argument is required\n");
		return -EINVAL;
	}
	path = argv[0];

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	ret = print_super_blocks(fd);
	close(fd);
	return ret;
};

static void __attribute__((constructor)) print_ctor(void)
{
	cmd_register("print", "<device>", "print metadata structures",
			print_cmd);
}
