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

static void print_inode(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_inode_key *ikey = key;
	struct scoutfs_inode *inode = val;

	printf("    inode: ino %llu size %llu blocks %llu lctr %llu nlink %u\n"
	       "      uid %u gid %u mode 0%o rdev 0x%x\n"
	       "      salt 0x%x next_readdir_pos %llu data_version %llu\n"
	       "      atime %llu.%08u ctime %llu.%08u\n"
	       "      mtime %llu.%08u\n",
	       be64_to_cpu(ikey->ino),
	       le64_to_cpu(inode->size), le64_to_cpu(inode->blocks),
	       le64_to_cpu(inode->link_counter),
	       le32_to_cpu(inode->nlink), le32_to_cpu(inode->uid),
	       le32_to_cpu(inode->gid), le32_to_cpu(inode->mode),
	       le32_to_cpu(inode->rdev), le32_to_cpu(inode->salt),
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
#endif

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

#if 0
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

typedef void (*print_func_t)(void *key, int key_len, void *val, int val_len);

static print_func_t printers[] = {
	[SCOUTFS_INODE_KEY] = print_inode,
	[SCOUTFS_ORPHAN_KEY] = print_orphan,
	[SCOUTFS_DIRENT_KEY] = print_dirent,
	[SCOUTFS_READDIR_KEY] = print_readdir,
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

static int print_segment(int fd, struct scoutfs_treap_node *tnode)
{
	struct scoutfs_manifest_entry *ment = (void *)tnode->data;
	u64 segno = le64_to_cpu(ment->segno);
	struct scoutfs_segment_block *sblk;
	int i;

	sblk = read_segment(fd, segno);
	if (!sblk)
		return -ENOMEM;

	printf("segment segno %llu\n", segno);
	print_segment_block(sblk);

	for (i = 0; i < le32_to_cpu(sblk->nr_items); i++)
		print_item(sblk, i);

	free(sblk);

	return 0;
}

static void print_treap_ref(struct scoutfs_treap_ref *ref)
{
	printf(" off %llu gen %llu aug_bits %x",
	       le64_to_cpu(ref->off), le64_to_cpu(ref->gen),
	       ref->aug_bits);
}

static void print_treap_node(struct scoutfs_treap_node *tnode)
{
	char valid_str[40];
	__le32 crc;

	crc = crc_node(tnode);
	if (crc != tnode->crc)
		sprintf(valid_str, "(!= %08x) ", le32_to_cpu(crc));
	else
		valid_str[0] = '\0';

	printf("  node: crc %08x %soff %llu gen %llu bytes %u prio %016llx\n"
	       "        l:",
	       le32_to_cpu(tnode->crc), valid_str, le64_to_cpu(tnode->off),
	       le64_to_cpu(tnode->gen), le16_to_cpu(tnode->bytes),
	       le64_to_cpu(tnode->prio));
	print_treap_ref(&tnode->left);
	printf(" r:");
	print_treap_ref(&tnode->right);
	printf("\n");
}

static int print_manifest_entry(int fd, struct scoutfs_treap_node *tnode)
{
	struct scoutfs_manifest_entry *ment = (void *)tnode->data;

	print_treap_node(tnode);

	printf("    ment: segno %llu seq %llu first_len %u last_len %u level %u\n",
	       le64_to_cpu(ment->segno),
	       le64_to_cpu(ment->seq),
	       le16_to_cpu(ment->first_key_len),
	       le16_to_cpu(ment->last_key_len),
	       ment->level);

	return 0;
}

static int print_alloc_region(int fd, struct scoutfs_treap_node *tnode)
{
	struct scoutfs_alloc_region *reg = (void *)tnode->data;
	int i;

	print_treap_node(tnode);

	printf("    reg: index %llu bits", le64_to_cpu(reg->index));
	for (i = 0; i < array_size(reg->bits); i++)
		printf(" %016llx", le64_to_cpu(reg->bits[i]));
	printf("\n");

	return 0;
}

typedef int (*tnode_func)(int fd, struct scoutfs_treap_node *tnode);

static int walk_treap(int fd, struct scoutfs_super_block *super,
		      struct scoutfs_treap_ref *ref, tnode_func func)
{
	struct scoutfs_treap_node *tnode;
	u64 blkno;
	void *blk;
	u64 off;
	int ret;

	if (!ref->gen)
		return 0;

	off = le64_to_cpu(ref->off);
	blkno = le64_to_cpu(super->ring_blkno) + (off >> SCOUTFS_BLOCK_SHIFT);

	blk = read_block(fd, blkno);
	if (!blk)
		return -ENOMEM;

	tnode = blk + (off & SCOUTFS_BLOCK_MASK);

	ret = func(fd, tnode);
	if (ret == 0)
		ret = walk_treap(fd, super, &tnode->left, func) ?:
		      walk_treap(fd, super, &tnode->right, func);

	free(blk);

	return ret;
}

static int print_super_blocks(int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_super_block recent = { .hdr.seq = 0 };
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
		printf("  next_ino %llu total_blocks %llu free_blocks %llu\n"
		       "  ring_blkno %llu ring_blocks %llu ring_tail_block %llu\n"
		       "  ring_gen %llu alloc_uninit %llu total_segs %llu\n"
		       "  next_seg_seq %llu\n",
			le64_to_cpu(super->next_ino),
			le64_to_cpu(super->total_blocks),
			le64_to_cpu(super->free_blocks),
			le64_to_cpu(super->ring_blkno),
			le64_to_cpu(super->ring_blocks),
			le64_to_cpu(super->ring_tail_block),
			le64_to_cpu(super->ring_gen),
			le64_to_cpu(super->alloc_uninit),
			le64_to_cpu(super->total_segs),
			le64_to_cpu(super->next_seg_seq));
		printf("  alloc root:");
		print_treap_ref(&super->alloc_treap_root.ref);
		printf("\n");
		printf("  manifest root:");
		print_treap_ref(&super->manifest.root.ref);
		printf("\n");

		printf("    level_counts:");
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

	printf("manifest treap:\n");
	ret = walk_treap(fd, super, &super->manifest.root.ref,
			 print_manifest_entry);

	printf("alloc treap:\n");
	err = walk_treap(fd, super, &super->alloc_treap_root.ref,
			 print_alloc_region);
	if (err && !ret)
		ret = err;

	err = walk_treap(fd, super, &super->manifest.root.ref,
			 print_segment);
	if (err && !ret)
		ret = err;

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
