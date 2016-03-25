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
#include "lebitmap.h"

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

static void *read_chunk(int fd, u64 blkno)
{
	ssize_t ret;
	void *buf;

	buf = malloc(SCOUTFS_CHUNK_SIZE);
	if (!buf)
		return NULL;

	ret = pread(fd, buf, SCOUTFS_CHUNK_SIZE, blkno << SCOUTFS_BLOCK_SHIFT);
	if (ret != SCOUTFS_CHUNK_SIZE) {
		fprintf(stderr, "read blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		free(buf);
		buf = NULL;
	}

	return buf;
}

static void print_le32_list(int indent, __le32 *data, int nr)
{
	char *fmt;
	int pos;
	int len;
	int i;
	u32 d;

	printf("[");

	pos = indent;
	for (i = 0; i < nr; i++) {
		if (i + 1 < nr)
			fmt = "%u, ";
		else
			fmt = "%u";

		d = le32_to_cpu(data[i]);
		len = snprintf(NULL, 0, fmt, d);
		if (pos + len > 78) {
			printf("\n%*c", indent, ' ');
			pos = indent;
		}

		printf(fmt, d);
		pos += len;
	}

	printf("]\n");
}

static void print_block_header(struct scoutfs_block_header *hdr)
{
	u32 crc = crc_block(hdr);
	char valid_str[40];

	if (crc != le32_to_cpu(hdr->crc))
		sprintf(valid_str, "# != %08x", crc);
	else
		valid_str[0] = '\0';

	printf("    header:\n"
	       "        crc: %08x %s\n"
	       "        fsid: %llx\n"
	       "        seq: %llu\n"
	       "        blkno: %llu\n",
		le32_to_cpu(hdr->crc), valid_str, le64_to_cpu(hdr->fsid),
		le64_to_cpu(hdr->seq), le64_to_cpu(hdr->blkno));
}

static void print_inode(struct scoutfs_inode *inode)
{
	printf("        inode:\n"
	       "                size: %llu\n"
	       "                blocks: %llu\n"
	       "                nlink: %u\n"
	       "                uid: %u\n"
	       "                gid: %u\n"
	       "                mode: 0%o\n"
	       "                rdev: 0x%x\n"
	       "                salt: 0x%x\n"
	       "                max_dirent_hash_nr: %u\n"
	       "                atime: %llu.%08u\n"
	       "                ctime: %llu.%08u\n"
	       "                mtime: %llu.%08u\n",
	       le64_to_cpu(inode->size), le64_to_cpu(inode->blocks),
	       le32_to_cpu(inode->nlink), le32_to_cpu(inode->uid),
	       le32_to_cpu(inode->gid), le32_to_cpu(inode->mode),
	       le32_to_cpu(inode->rdev), le32_to_cpu(inode->salt),
	       inode->max_dirent_hash_nr,
	       le64_to_cpu(inode->atime.sec),
	       le32_to_cpu(inode->atime.nsec),
	       le64_to_cpu(inode->ctime.sec),
	       le32_to_cpu(inode->ctime.nsec),
	       le64_to_cpu(inode->mtime.sec),
	       le32_to_cpu(inode->mtime.nsec));
}

static void print_dirent(struct scoutfs_dirent *dent, unsigned int val_len)
{
	unsigned int name_len = val_len - sizeof(*dent);
	char name[SCOUTFS_NAME_LEN + 1];
	int i;

	for (i = 0; i < min(SCOUTFS_NAME_LEN, name_len); i++)
		name[i] = isprint(dent->name[i]) ?  dent->name[i] : '.';
	name[i] = '\0';

	printf("        dirent:\n"
	       "                ino: %llu\n"
	       "                type: %u\n"
	       "                name: \"%.*s\"\n",
	       le64_to_cpu(dent->ino), dent->type, i, name);
}

static void print_item(struct scoutfs_item *item, void *val)
{
	printf("    item:\n"
	       "        key: "SKF"\n"
	       "        offset: %u\n"
	       "        len: %u\n"
	       "        skip_height: %u\n"
	       "        skip_next[]: ",
	       SKA(&item->key),
	       le32_to_cpu(item->offset),
	       le16_to_cpu(item->len),
	       item->skip_height);

	print_le32_list(22, item->skip_next, item->skip_height);

	switch(item->key.type) {
	case SCOUTFS_INODE_KEY:
		print_inode(val);
		break;
	case SCOUTFS_DIRENT_KEY:
		print_dirent(val, le16_to_cpu(item->len));
		break;
	}
}

static int print_log_segment(int fd, u64 nr)
{
	struct scoutfs_item_block *iblk;
	struct scoutfs_bloom_block *blm;
	struct scoutfs_item *item;
	char *buf;
	char *val;
	__le32 next;
	int i;

	buf = read_chunk(fd, nr);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < SCOUTFS_BLOOM_BLOCKS; i++) {

		blm = (void *)(buf + (i << SCOUTFS_BLOCK_SHIFT));

		printf("bloom block:\n");
		print_block_header(&blm->hdr);
	}

	iblk = (void *)(buf + (SCOUTFS_BLOOM_BLOCKS << SCOUTFS_BLOCK_SHIFT));

	printf("item block:\n");
	print_block_header(&iblk->hdr);
	printf("    first: "SKF"\n"
	       "    last: "SKF"\n"
	       "    skip_root.next[]: ",
	       SKA(&iblk->first), SKA(&iblk->last));
	print_le32_list(23, iblk->skip_root.next, SCOUTFS_SKIP_HEIGHT);

	next = iblk->skip_root.next[0];
	while (next) {
		item = (void *)(buf + le32_to_cpu(next));
		val = (void *)(buf + le32_to_cpu(item->offset));
		print_item(item, val);
		next = item->skip_next[0];
	}

	free(buf);

	return 0;
}

static int print_log_segments(int fd, __le64 *log_segs, u64 total_chunks)
{
	int ret = 0;
	int err;
	s64 nr;

	while ((nr = find_first_le_bit(log_segs, total_chunks)) >= 0) {
		clear_le_bit(log_segs, nr);

		err = print_log_segment(fd, nr << SCOUTFS_CHUNK_BLOCK_SHIFT);
		if (!ret && err)
			ret = err;
	}
	
	return ret;
}

static char *ent_type_str(u8 type)
{
	switch (type) {
		case SCOUTFS_RING_ADD_MANIFEST:
			return "ADD_MANIFEST";
		case SCOUTFS_RING_DEL_MANIFEST:
			return "DEL_MANIFEST";
		case SCOUTFS_RING_BITMAP:
			return "BITMAP";
		default:
			return "(unknown)";
	}
}

static void print_ring_entry(int fd, struct scoutfs_ring_entry *ent)
{
	struct scoutfs_ring_manifest_entry *ment;
	struct scoutfs_ring_del_manifest *del;
	struct scoutfs_ring_bitmap *bm;

	printf("    entry:\n"
	       "        type: %u # %s\n"
	       "        len: %u\n",
	       ent->type, ent_type_str(ent->type), le16_to_cpu(ent->len));

	switch(ent->type) {
	case SCOUTFS_RING_ADD_MANIFEST:
		ment = (void *)(ent + 1);
		printf("            blkno: %llu\n"
		       "            seq: %llu\n"
		       "            level: %u\n"
		       "            first: "SKF"\n"
		       "            last: "SKF"\n",
		       le64_to_cpu(ment->blkno), le64_to_cpu(ment->seq),
		       ment->level, SKA(&ment->first), SKA(&ment->last));
		break;
	case SCOUTFS_RING_DEL_MANIFEST:
		del = (void *)(ent + 1);
		printf("            blkno: %llu\n",
		       le64_to_cpu(del->blkno));
		break;
	case SCOUTFS_RING_BITMAP:
		bm = (void *)(ent + 1);
		printf("            offset: %u\n"
		       "            bits: 0x%llx%llx\n",
		       le32_to_cpu(bm->offset),
		       le64_to_cpu(bm->bits[1]), le64_to_cpu(bm->bits[0]));
		break;
	}
}

static void update_log_segs(struct scoutfs_ring_entry *ent,
			       __le64 *log_segs)
{
	struct scoutfs_ring_manifest_entry *add;
	struct scoutfs_ring_del_manifest *del;
	u64 bit;

	switch(ent->type) {
	case SCOUTFS_RING_ADD_MANIFEST:
		add = (void *)(ent + 1);
		bit = le64_to_cpu(add->blkno) >> SCOUTFS_CHUNK_BLOCK_SHIFT;
		set_le_bit(log_segs, bit);
		break;
	case SCOUTFS_RING_DEL_MANIFEST:
		del = (void *)(ent + 1);
		bit = le64_to_cpu(del->blkno) >> SCOUTFS_CHUNK_BLOCK_SHIFT;
		clear_le_bit(log_segs, bit);
		break;
	}
}

static int print_ring_block(int fd, u64 blkno, __le64 *log_segs)
{
	struct scoutfs_ring_block *ring;
	struct scoutfs_ring_entry *ent;
	size_t off;
	int ret = 0;
	int i;

	/* XXX just printing the first block for now */

	ring = read_block(fd, blkno);
	if (!ring)
		return -ENOMEM;

	printf("ring block:\n");
	print_block_header(&ring->hdr);
	printf("    nr_entries: %u\n", le16_to_cpu(ring->nr_entries));

	off = sizeof(struct scoutfs_ring_block);
	for (i = 0; i < le16_to_cpu(ring->nr_entries); i++) {
		ent = (void *)((char *)ring + off);

		update_log_segs(ent, log_segs);
		print_ring_entry(fd, ent);

		off += sizeof(struct scoutfs_ring_entry) + 
		       le16_to_cpu(ent->len);
	}

	free(ring);
	return ret;
}

/*
 * Print all the active ring blocks that are referenced by the super
 * and which were mapped by the map blocks that we printed.
 */
static int print_ring_blocks(int fd, struct scoutfs_super_block *super,
			     u64 *ring_blknos, __le64 *log_segs)
{
	u64 block;
	u64 blkno;
	u64 i;
	int ret = 0;
	int err;

	block = le64_to_cpu(super->ring_first_block);

	for (i = 0; i < le64_to_cpu(super->ring_active_blocks); i++) {
		blkno = ring_blknos[block >> SCOUTFS_CHUNK_BLOCK_SHIFT] +
			(block & SCOUTFS_CHUNK_BLOCK_MASK);

		err = print_ring_block(fd, blkno, log_segs);
		if (err && !ret)
			ret = err;

		if (++block == le64_to_cpu(super->ring_total_blocks))
			block = 0;
	}

	return ret;
}

/*
 * print a chunk's worth of map blocks and stop if we hit a partial
 * block.
 */
static int print_map_blocks(int fd, u64 blkno, u64 *ring_blknos)
{
	struct scoutfs_ring_map_block *map;
	int r = 0;
	int b;
	int i;

	for (b = 0; SCOUTFS_BLOCKS_PER_CHUNK; b++) {
		map = read_block(fd, blkno + b);
		if (!map)
			return -ENOMEM;

		printf("map block:\n");
		print_block_header(&map->hdr);
		printf("    nr_chunks: %u\n", le32_to_cpu(map->nr_chunks));

		printf("    blknos: ");
		for (i = 0; i < le32_to_cpu(map->nr_chunks); i++, r++) {
			printf("    %llu\n", le64_to_cpu(map->blknos[i]));
			ring_blknos[r] = le64_to_cpu(map->blknos[i]);
		}

		free(map);

		if (i != SCOUTFS_RING_MAP_BLOCKS)
			break;
	}

	return 0;
}

static int print_super_brick(int fd)
{
	struct scoutfs_super_block *super;
	char uuid_str[37];
	__le64 *log_segs;
	u64 *ring_blknos;
	u64 total_chunks;
	int ret = 0;
	int err;

	/* XXX print both */
	super = read_block(fd, SCOUTFS_SUPER_BLKNO);
	if (!super)
		return -ENOMEM;

	uuid_unparse(super->uuid, uuid_str);

	total_chunks = le64_to_cpu(super->total_chunks);

	printf("super:\n");
	print_block_header(&super->hdr);
	printf("    id: %llx\n"
	       "    uuid: %s\n"
	       "    bloom_salts: ",
	       le64_to_cpu(super->id),
	       uuid_str);
	print_le32_list(18, super->bloom_salts, SCOUTFS_BLOOM_SALTS);
	printf("    total_chunks: %llu\n"
	       "    ring_map_blkno: %llu\n"
	       "    ring_map_seq: %llu\n"
	       "    ring_first_block: %llu\n"
	       "    ring_active_blocks: %llu\n"
	       "    ring_total_blocks: %llu\n"
	       "    ring_seq: %llu\n",
	       total_chunks,
	       le64_to_cpu(super->ring_map_blkno),
	       le64_to_cpu(super->ring_map_seq),
	       le64_to_cpu(super->ring_first_block),
	       le64_to_cpu(super->ring_active_blocks),
	       le64_to_cpu(super->ring_total_blocks),
	       le64_to_cpu(super->ring_seq));

	/*
	 * Allocate a bitmap big enough to describe all the chunks and
	 * we can have at most a full chunk worth of map blocks.
	 */
	log_segs = calloc(1, (total_chunks + 63) / 8);
	ring_blknos = calloc(1, SCOUTFS_CHUNK_SIZE);
	if (!log_segs || !ring_blknos) {
		ret = -ENOMEM;
		goto out;
	}

	err = print_map_blocks(fd, le64_to_cpu(super->ring_map_blkno),
			       ring_blknos);
	if (err && !ret)
		ret = err;

	err = print_ring_blocks(fd, super, ring_blknos, log_segs);
	if (err && !ret)
		ret = err;

	err = print_log_segments(fd, log_segs, total_chunks);
	if (err && !ret)
		ret = err;

out:
	if (log_segs)
		free(log_segs);
	if (ring_blknos)
		free(ring_blknos);
	free(super);
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

	ret = print_super_brick(fd);
	close(fd);
	return ret;
};

static void __attribute__((constructor)) print_ctor(void)
{
	cmd_register("print", "<device>", "print metadata structures",
			print_cmd);
}
