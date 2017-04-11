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
#include "bitmap.h"
#include "cmd.h"
#include "crc.h"

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

static void print_inode(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_inode_key *ikey = key;
	struct scoutfs_inode *inode = val;

	printf("    inode: ino %llu size %llu blocks %llu nlink %u\n"
	       "      uid %u gid %u mode 0%o rdev 0x%x\n"
	       "      next_readdir_pos %llu data_version %llu\n"
	       "      atime %llu.%08u ctime %llu.%08u\n"
	       "      mtime %llu.%08u\n",
	       be64_to_cpu(ikey->ino),
	       le64_to_cpu(inode->size), le64_to_cpu(inode->blocks),
	       le32_to_cpu(inode->nlink), le32_to_cpu(inode->uid),
	       le32_to_cpu(inode->gid), le32_to_cpu(inode->mode),
	       le32_to_cpu(inode->rdev),
	       le64_to_cpu(inode->next_readdir_pos),
	       le64_to_cpu(inode->data_version),
	       le64_to_cpu(inode->atime.sec),
	       le32_to_cpu(inode->atime.nsec),
	       le64_to_cpu(inode->ctime.sec),
	       le32_to_cpu(inode->ctime.nsec),
	       le64_to_cpu(inode->mtime.sec),
	       le32_to_cpu(inode->mtime.nsec));
}

static void print_orphan(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_orphan_key *okey = key;

	printf("    orphan: ino %llu\n", be64_to_cpu(okey->ino));
}

static u8 *global_printable_name(u8 *name, int name_len)
{
	static u8 name_buf[SCOUTFS_NAME_LEN + 1];
	int i;

	name_len = min(SCOUTFS_NAME_LEN, name_len);
	for (i = 0; i < name_len; i++)
		name_buf[i] = isprint(name[i]) ? name[i] : '.';
	name_buf[i] = '\0';

	return name_buf;
}

static void print_xattr(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_xattr_key *xkey = key;
	struct scoutfs_xattr_key_footer *foot = key + key_len - sizeof(*foot);
	struct scoutfs_xattr_val_header *vh = val;
	unsigned int name_len = key_len - sizeof(*xkey) - sizeof(*foot);
	u8 *name = global_printable_name(xkey->name, name_len);

	printf("    xattr: ino %llu part %u part_len %u last_part %u\n"
	       "      name %s\n",
	       be64_to_cpu(xkey->ino), foot->part, le16_to_cpu(vh->part_len),
	       vh->last_part, name);
}

static void print_dirent(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_dirent_key *dkey = key;
	struct scoutfs_dirent *dent = val;
	unsigned int name_len = key_len - sizeof(*dkey);
	u8 *name = global_printable_name(dkey->name, name_len);

	printf("    dirent: dir ino %llu type %u rdpos %llu targ ino %llu\n"
	       "      name %s\n",
	       be64_to_cpu(dkey->ino), dent->type,
	       le64_to_cpu(dent->readdir_pos), le64_to_cpu(dent->ino),
	       name);
}

static void print_readdir(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_readdir_key *rkey = key;
	struct scoutfs_dirent *dent = val;
	unsigned int name_len = val_len - sizeof(*dent);
	u8 *name = global_printable_name(dent->name, name_len);

	printf("    readdir: dir ino %llu pos %llu type %u targ ino %llu\n"
	       "      name %s\n",
	       be64_to_cpu(rkey->ino), be64_to_cpu(rkey->pos), 
	       dent->type, le64_to_cpu(dent->ino),
	       name);
}

static void print_data(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_data_key *dat = key;

	printf("      data: ino %llu block %llu\n",
	       be64_to_cpu(dat->ino), be64_to_cpu(dat->block));
}

static void print_link_backref(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_link_backref_key *lbkey = key;
	unsigned int name_len = key_len - sizeof(*lbkey);
	u8 *name = global_printable_name(lbkey->name, name_len);

	printf("      lbref: ino: %llu dir_ino %llu name %s\n",
	       be64_to_cpu(lbkey->ino), be64_to_cpu(lbkey->dir_ino), name);
}

static void print_symlink(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_symlink_key *skey = key;
	u8 *name = global_printable_name(val, val_len - 1);

	printf("    symlink: ino %llu\n"
	       "      target %s\n",
	       be64_to_cpu(skey->ino), name);
}

typedef void (*print_func_t)(void *key, int key_len, void *val, int val_len);

static print_func_t printers[] = {
	[SCOUTFS_INODE_KEY] = print_inode,
	[SCOUTFS_XATTR_KEY] = print_xattr,
	[SCOUTFS_ORPHAN_KEY] = print_orphan,
	[SCOUTFS_DIRENT_KEY] = print_dirent,
	[SCOUTFS_READDIR_KEY] = print_readdir,
	[SCOUTFS_SYMLINK_KEY] = print_symlink,
	[SCOUTFS_LINK_BACKREF_KEY] = print_link_backref,
	[SCOUTFS_DATA_KEY] = print_data,
};

/* utils uses big contiguous allocations */
static void *off_ptr(struct scoutfs_segment_block *sblk, u32 off)
{
	return (char *)sblk + off;
}

static u32 pos_off(struct scoutfs_segment_block *sblk, u32 pos)
{
	return offsetof(struct scoutfs_segment_block, items[pos]);
}

static void *pos_ptr(struct scoutfs_segment_block *sblk, u32 pos)
{
	return off_ptr(sblk, pos_off(sblk, pos));
}

static void print_item(struct scoutfs_segment_block *sblk, u32 pos)
{
	print_func_t printer;
	struct scoutfs_segment_item *item;
	void *key;
	void *val;
	__u8 type;

	item = pos_ptr(sblk, pos);

	key = (char *)sblk + le32_to_cpu(item->key_off);
	val = (char *)sblk + le32_to_cpu(item->val_off);
	type = *(__u8 *)key;

	printer = type < array_size(printers) ? printers[type] : NULL;

	printf("  [%u]: type %u seq %llu key_off %u val_off %u key_len %u "
	       "val_len %u flags %x%s\n",
		pos, type, le64_to_cpu(item->seq), le32_to_cpu(item->key_off),
		le32_to_cpu(item->val_off), le16_to_cpu(item->key_len),
		le16_to_cpu(item->val_len), item->flags,
		printer ? "" : " (unrecognized type)");

	if (printer)
		printer(key, le16_to_cpu(item->key_len),
			val, le16_to_cpu(item->val_len));
}

static void print_segment_block(struct scoutfs_segment_block *sblk)
{
	printf("  sblk: segno %llu seq %llu nr_items %u\n",
		le64_to_cpu(sblk->segno), le64_to_cpu(sblk->seq),
		le32_to_cpu(sblk->nr_items));
}

static int print_segments(int fd, unsigned long *seg_map, u64 total)
{
	struct scoutfs_segment_block *sblk;
	u64 s;
	u64 i;

	for (s = 0; (s = find_next_set_bit(seg_map, s, total)) < total; s++) {
		sblk = read_segment(fd, s);
		if (!sblk)
			return -ENOMEM;

		printf("segment segno %llu\n", s);
		print_segment_block(sblk);

		for (i = 0; i < le32_to_cpu(sblk->nr_items); i++)
			print_item(sblk, i);

		free(sblk);
	}

	return 0;
}

static void print_ring_descriptor(struct scoutfs_ring_descriptor *rdesc,
				  char *which)
{
	printf("  %s ring:\n    blkno %llu total_blocks %llu first_block %llu "
	       "first_seq %llu nr_blocks %llu\n",
	       which, le64_to_cpu(rdesc->blkno),
	       le64_to_cpu(rdesc->total_blocks),
	       le64_to_cpu(rdesc->first_block),
	       le64_to_cpu(rdesc->first_seq),
	       le64_to_cpu(rdesc->nr_blocks));
}

static int print_manifest_entry(int fd, struct scoutfs_ring_entry *rent,
				void *arg)
{
	struct scoutfs_manifest_entry *ment = (void *)rent->data;
	unsigned long *seg_map = arg;

	printf("      segno %llu seq %llu first_len %u last_len %u level %u\n",
	       le64_to_cpu(ment->segno),
	       le64_to_cpu(ment->seq),
	       le16_to_cpu(ment->first_key_len),
	       le16_to_cpu(ment->last_key_len),
	       ment->level);

	if (rent->flags & SCOUTFS_RING_ENTRY_FLAG_DELETION)
	       clear_bit(seg_map, le64_to_cpu(ment->segno));
	else
	       set_bit(seg_map, le64_to_cpu(ment->segno));

	return 0;
}

static int print_alloc_region(int fd, struct scoutfs_ring_entry *rent,
			      void *arg)
{
	struct scoutfs_alloc_region *reg = (void *)rent->data;
	int i;

	printf("      index %llu bits", le64_to_cpu(reg->index));
	for (i = 0; i < array_size(reg->bits); i++)
		printf(" %016llx", le64_to_cpu(reg->bits[i]));
	printf("\n");

	return 0;
}

typedef int (*rent_func)(int fd, struct scoutfs_ring_entry *rent, void *arg);

static int print_ring(int fd, struct scoutfs_super_block *super,
		      char *which, struct scoutfs_ring_descriptor *rdesc,
		      rent_func func, void *arg)
{
	struct scoutfs_ring_block *rblk;
	struct scoutfs_ring_entry *rent;
	u64 block;
	u64 blkno;
	int ret;
	u64 i;
	u32 e;

	block = le64_to_cpu(rdesc->first_block);
	for (i = 0; i < le64_to_cpu(rdesc->nr_blocks); i++) {
		blkno = le64_to_cpu(rdesc->blkno) + block;

		rblk = read_block(fd, blkno);
		if (!rblk)
			return -ENOMEM;

		printf("%s ring blkno %llu\n"
		       "  crc %08x fsid %llx seq %llu block %llu "
		       "nr_entries %u\n",
		       which, blkno, le32_to_cpu(rblk->crc),
		       le64_to_cpu(rblk->fsid),
		       le64_to_cpu(rblk->seq),
		       le64_to_cpu(rblk->block),
		       le32_to_cpu(rblk->nr_entries));

		rent = rblk->entries;
		for (e = 0; e < le32_to_cpu(rblk->nr_entries); e++) {

			printf("    entry [%u] off %lu data_len %u flags %x\n",
			       e, (char *)rent - (char *)rblk->entries,
			       le16_to_cpu(rent->data_len), rent->flags);

			ret = func(fd, rent, arg);
			if (ret) {
				free(rblk);
				return ret;
			}

			rent = (void *)&rent->data[le16_to_cpu(rent->data_len)];
		}

		block++;
		if (block == le64_to_cpu(rdesc->total_blocks))
			block = 0;

		free(rblk);
	}

	return 0;
}

static int print_super_blocks(int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_super_block recent = { .hdr.seq = 0 };
	unsigned long *seg_map;
	char uuid_str[37];
	__le64 *counts;
	int ret = 0;
	int err;
	int i;
	int j;

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
		printf("  next_ino %llu\n"
		       "  ring_blkno %llu ring_blocks %llu ring_tail_block %llu\n"
		       "  ring_gen %llu alloc_uninit %llu total_segs %llu\n"
		       "  next_seg_seq %llu free_segs %llu\n",
			le64_to_cpu(super->next_ino),
			le64_to_cpu(super->ring_blkno),
			le64_to_cpu(super->ring_blocks),
			le64_to_cpu(super->ring_tail_block),
			le64_to_cpu(super->ring_gen),
			le64_to_cpu(super->alloc_uninit),
			le64_to_cpu(super->total_segs),
			le64_to_cpu(super->next_seg_seq),
			le64_to_cpu(super->free_segs));

		print_ring_descriptor(&super->alloc_ring, "alloc");
		print_ring_descriptor(&super->manifest.ring, "manifest");

		printf("  level_counts:");
		counts = super->manifest.level_counts;
		for (j = 0; j < SCOUTFS_MANIFEST_MAX_LEVEL; j++) {
			if (le64_to_cpu(counts[j]))
				printf(" %u: %llu", j, le64_to_cpu(counts[j]));
		}
		printf("\n");

		if (le64_to_cpu(super->hdr.seq) > le64_to_cpu(recent.hdr.seq))
			memcpy(&recent, super, sizeof(recent));

		free(super);
	}

	super = &recent;

	seg_map = alloc_bits(le64_to_cpu(super->total_segs));
	if (!seg_map) {
		ret = -ENOMEM;
		fprintf(stderr, "failed to alloc %llu seg map: %s (%d)\n",
			le64_to_cpu(super->total_segs),
			strerror(errno), errno);
		return ret;
	}

	ret = print_ring(fd, super, "alloc", &super->alloc_ring,
			 print_alloc_region, NULL);

	err = print_ring(fd, super, "manifest", &super->manifest.ring,
			 print_manifest_entry, seg_map);
	if (err && !ret)
		ret = err;

	err = print_segments(fd, seg_map, le64_to_cpu(super->total_segs));
	if (err && !ret)
		ret = err;

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
