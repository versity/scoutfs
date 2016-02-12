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

static void *read_buf(int fd, u64 nr, size_t size)
{
	off_t off = nr * size;
	ssize_t ret;
	void *buf;

	buf = malloc(size);
	if (!buf)
		return NULL;

	ret = pread(fd, buf, size, off);
	if (ret != size) {
		fprintf(stderr, "read at blkno %llu (offset %llu) returned %zd: %s (%d)\n",
			nr, (long long)off, ret, strerror(errno), errno);
		free(buf);
		buf = NULL;
	}

	return buf;
}

static void *read_brick(int fd, u64 nr)
{
	return read_buf(fd, nr, SCOUTFS_BRICK_SIZE);
}

static void *read_block(int fd, u64 nr)
{
	return read_buf(fd, nr, SCOUTFS_BLOCK_SIZE);
}

static void print_header(struct scoutfs_header *hdr, size_t size)
{
	u32 crc = crc_header(hdr, size);
	char valid_str[40];

	if (crc != le32_to_cpu(hdr->crc))
		sprintf(valid_str, "# != %08x", crc);
	else
		valid_str[0] = '\0';

	printf("    header:\n"
	       "        crc: %08x %s\n"
	       "        fsid: %llx\n"
	       "        seq: %llu\n"
	       "        nr: %llu\n",
		le32_to_cpu(hdr->crc), valid_str, le64_to_cpu(hdr->fsid),
		le64_to_cpu(hdr->seq), le64_to_cpu(hdr->nr));
}

static void print_brick_header(struct scoutfs_header *hdr)
{
	return print_header(hdr, SCOUTFS_BRICK_SIZE);
}

static void print_block_header(struct scoutfs_header *hdr)
{
	return print_header(hdr, SCOUTFS_BLOCK_SIZE);
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
	       "                atime: %llu.%08u\n"
	       "                ctime: %llu.%08u\n"
	       "                mtime: %llu.%08u\n",
	       le64_to_cpu(inode->size), le64_to_cpu(inode->blocks),
	       le32_to_cpu(inode->nlink), le32_to_cpu(inode->uid),
	       le32_to_cpu(inode->gid), le32_to_cpu(inode->mode),
	       le32_to_cpu(inode->rdev), le32_to_cpu(inode->salt),
	       le64_to_cpu(inode->atime.sec),
	       le32_to_cpu(inode->atime.nsec),
	       le64_to_cpu(inode->ctime.sec),
	       le32_to_cpu(inode->ctime.nsec),
	       le64_to_cpu(inode->mtime.sec),
	       le32_to_cpu(inode->mtime.nsec));
}

static void print_item(struct scoutfs_item_header *ihdr, size_t off)
{
	printf("    item: &%zu\n"
	       "        key: "SKF"\n"
	       "        len: %u\n",
	       off, SKA(&ihdr->key), le16_to_cpu(ihdr->len));

	switch(ihdr->key.type) {
	case SCOUTFS_INODE_KEY:
		print_inode((void *)(ihdr + 1));
		break;
	}
}

static int print_block(int fd, u64 nr)
{
	struct scoutfs_item_header *ihdr;
	struct scoutfs_lsm_block *lblk;
	size_t off;
	int i;

	lblk = read_block(fd, nr);
	if (!lblk)
		return -ENOMEM;

	printf("block: &%llu\n", le64_to_cpu(lblk->hdr.nr));
	print_block_header(&lblk->hdr);
	printf("    first: "SKF"\n"
	       "    last: "SKF"\n"
	       "    nr_items: %u\n",
	       SKA(&lblk->first), SKA(&lblk->last),
	       le32_to_cpu(lblk->nr_items));
	off = (char *)(lblk + 1) - (char *)lblk + SCOUTFS_BLOOM_FILTER_BYTES;

	for (i = 0; i < le32_to_cpu(lblk->nr_items); i++) {
		ihdr = (void *)((char *)lblk + off);
		print_item(ihdr, off);

		off += sizeof(struct scoutfs_item_header) +
			le16_to_cpu(ihdr->len);
	}

	free(lblk);

	return 0;
}

static int print_blocks(int fd, __le64 *live_blocks, u64 total_blocks)
{
	int ret = 0;
	int err;
	s64 nr;

	while ((nr = find_first_le_bit(live_blocks, total_blocks)) >= 0) {
		clear_le_bit(live_blocks, nr);

		err = print_block(fd, nr);
		if (!ret && err)
			ret = err;
	}
	
	return ret;
}

static char *ent_type_str(u8 type)
{
	switch (type) {
		case SCOUTFS_RING_REMOVE_MANIFEST:
			return "REMOVE_MANIFEST";
		case SCOUTFS_RING_ADD_MANIFEST:
			return "ADD_MANIFEST";
		case SCOUTFS_RING_BITMAP:
			return "BITMAP";
		default:
			return "(unknown)";
	}
}

static void print_ring_entry(int fd, struct scoutfs_ring_entry *ent,
			     size_t off)
{
	struct scoutfs_ring_remove_manifest *rem;
	struct scoutfs_ring_add_manifest *add;
	struct scoutfs_ring_bitmap *bm;

	printf("    entry: &%zu\n"
	       "        type: %u # %s\n"
	       "        len: %u\n",
	       off, ent->type, ent_type_str(ent->type), le16_to_cpu(ent->len));

	switch(ent->type) {
	case SCOUTFS_RING_REMOVE_MANIFEST:
		rem = (void *)(ent + 1);
		printf("            block: %llu\n",
		       le64_to_cpu(rem->block));
		break;
	case SCOUTFS_RING_ADD_MANIFEST:
		add = (void *)(ent + 1);
		printf("            block: %llu\n"
		       "            seq: %llu\n"
		       "            level: %u\n"
		       "            first: "SKF"\n"
		       "            last: "SKF"\n",
		       le64_to_cpu(add->block), le64_to_cpu(add->seq),
		       add->level, SKA(&add->first), SKA(&add->last));
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

static void update_live_blocks(struct scoutfs_ring_entry *ent,
			       __le64 *live_blocks)
{
	struct scoutfs_ring_remove_manifest *rem;
	struct scoutfs_ring_add_manifest *add;

	switch(ent->type) {
	case SCOUTFS_RING_REMOVE_MANIFEST:
		rem = (void *)(ent + 1);
		clear_le_bit(live_blocks, le64_to_cpu(rem->block));
		break;
	case SCOUTFS_RING_ADD_MANIFEST:
		add = (void *)(ent + 1);
		set_le_bit(live_blocks, le64_to_cpu(add->block));
		break;
	}
}

static int print_ring_block(int fd, u64 block_nr, __le64 *live_blocks)
{
	struct scoutfs_ring_brick *ring;
	struct scoutfs_ring_entry *ent;
	size_t off;
	int ret = 0;
	u64 nr;
	int i;

	/* XXX just printing the first brick for now */

	nr = block_nr << SCOUTFS_BLOCK_BRICK;
	ring = read_brick(fd, nr);
	if (!ring)
		return -ENOMEM;

	printf("ring brick: &%llu\n", nr);
	print_brick_header(&ring->hdr);
	printf("    nr_entries: %u\n", le16_to_cpu(ring->nr_entries));

	off = sizeof(struct scoutfs_ring_brick);
	for (i = 0; i < le16_to_cpu(ring->nr_entries); i++) {
		ent = (void *)((char *)ring + off);

		update_live_blocks(ent, live_blocks);

		print_ring_entry(fd, ent, off);

		off += sizeof(struct scoutfs_ring_entry) + 
		       le16_to_cpu(ent->len);
	}

	free(ring);
	return ret;
}

static int print_ring_layout(int fd, u64 blkno, __le64 *live_blocks)
{
	struct scoutfs_ring_layout *rlo;
	int ret = 0;
	int err;
	int i;

	rlo = read_block(fd, blkno);
	if (!rlo)
		return -ENOMEM;

	printf("ring layout: &%llu\n", blkno);
	print_block_header(&rlo->hdr);
	printf("    nr_blocks: %u\n", le32_to_cpu(rlo->nr_blocks));

	printf("    blocks: ");
	for (i = 0; i < le32_to_cpu(rlo->nr_blocks); i++)
		printf("    %llu\n", le64_to_cpu(rlo->blocks[i]));

	for (i = 0; i < le32_to_cpu(rlo->nr_blocks); i++) {
		err = print_ring_block(fd, le64_to_cpu(rlo->blocks[i]),
				       live_blocks);
		if (err && !ret)
			ret = err;
	}

	free(rlo);
	return 0;
}

static int print_super_brick(int fd)
{
	struct scoutfs_super *super;
	char uuid_str[37];
	__le64 *live_blocks;
	u64 total_blocks;
	size_t bytes;
	int ret = 0;
	int err;

	/* XXX print both */
	super = read_brick(fd, SCOUTFS_SUPER_BRICK);
	if (!super)
		return -ENOMEM;

	uuid_unparse(super->uuid, uuid_str);

	total_blocks = le64_to_cpu(super->total_blocks);

	printf("super: &%llu\n", le64_to_cpu(super->hdr.nr));
	print_brick_header(&super->hdr);
	printf("    id: %llx\n"
	       "    uuid: %s\n"
	       "    total_blocks: %llu\n"
	       "    ring_layout_block: %llu\n"
	       "    ring_layout_seq: %llu\n"
	       "    last_ring_brick: %llu\n"
	       "    last_ring_seq: %llu\n"
	       "    last_block_seq: %llu\n",
	       le64_to_cpu(super->id),
	       uuid_str,
	       total_blocks,
	       le64_to_cpu(super->ring_layout_block),
	       le64_to_cpu(super->ring_layout_seq),
	       le64_to_cpu(super->last_ring_brick),
	       le64_to_cpu(super->last_ring_seq),
	       le64_to_cpu(super->last_block_seq));

	/* XXX by hand? */
	bytes = (total_blocks + 63) / 8;
	live_blocks = malloc(bytes);
	if (!live_blocks) {
		ret = -ENOMEM;
		goto out;
	}
	memset(live_blocks, 0, bytes);

	err = print_ring_layout(fd, le64_to_cpu(super->ring_layout_block),
				live_blocks);
	if (err && !ret)
		ret = err;

	err = print_blocks(fd, live_blocks, total_blocks);
	if (err && !ret)
		ret = err;

out:
	free(super);
	free(live_blocks);
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
