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
#include "key.h"

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

	printf("    inode: ino %llu size %llu nlink %u\n"
	       "      uid %u gid %u mode 0%o rdev 0x%x flags 0x%x\n"
	       "      next_readdir_pos %llu meta_seq %llu data_seq %llu data_version %llu\n"
	       "      atime %llu.%08u ctime %llu.%08u\n"
	       "      mtime %llu.%08u\n",
	       be64_to_cpu(ikey->ino),
	       le64_to_cpu(inode->size),
	       le32_to_cpu(inode->nlink), le32_to_cpu(inode->uid),
	       le32_to_cpu(inode->gid), le32_to_cpu(inode->mode),
	       le32_to_cpu(inode->rdev),
	       le32_to_cpu(inode->flags),
	       le64_to_cpu(inode->next_readdir_pos),
	       le64_to_cpu(inode->meta_seq),
	       le64_to_cpu(inode->data_seq),
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
	u8 *frag = val;
	u8 *name;

	/* don't try to print null term */
	if (frag[val_len - 1] == '\0')
		val_len--;
	name = global_printable_name(frag, val_len);

	printf("    symlink: ino %llu nr %u\n"
	       "      target %s\n",
	       be64_to_cpu(skey->ino), skey->nr, name);
}

/*
 * XXX not decoding the bytes yet
 */
static void print_block_mapping(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_block_mapping_key *bmk = key;
	u64 blk_off = be64_to_cpu(bmk->base) << SCOUTFS_BLOCK_MAPPING_SHIFT;
	u8 nr = *((u8 *)val) & 63;

	printf("      block mapping: ino %llu blk_off %llu blocks %u\n",
	       be64_to_cpu(bmk->ino), blk_off, nr);
}

static void print_free_bits(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_free_bits_key *fbk = key;
	struct scoutfs_free_bits *frb = val;
	int i;

	printf("      node_id %llx base %llu\n",
	       be64_to_cpu(fbk->node_id), be64_to_cpu(fbk->base));

	printf("      bits:");
	for (i = 0; i < array_size(frb->bits); i++)
		printf(" %016llx", le64_to_cpu(frb->bits[i]));
	printf("\n");
}

static void print_inode_index(void *key, int key_len, void *val, int val_len)
{
	struct scoutfs_inode_index_key *ikey = key;

	printf("      index: major %llu minor %u ino %llu\n",
	       be64_to_cpu(ikey->major), be32_to_cpu(ikey->minor),
	       be64_to_cpu(ikey->ino));
}

typedef void (*print_func_t)(void *key, int key_len, void *val, int val_len);

static print_func_t find_printer(u8 zone, u8 type)
{
	if (zone == SCOUTFS_INODE_INDEX_ZONE &&
	    type >= SCOUTFS_INODE_INDEX_META_SEQ_TYPE  &&
	    type <= SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE)
		return print_inode_index;

	if (zone == SCOUTFS_NODE_ZONE) {
		if (type == SCOUTFS_FREE_BITS_SEGNO_TYPE ||
		    type == SCOUTFS_FREE_BITS_BLKNO_TYPE)
			return print_free_bits;
		if (type == SCOUTFS_ORPHAN_TYPE)
			return print_orphan;
	}

	if (zone == SCOUTFS_FS_ZONE) {
		switch(type) {
			case SCOUTFS_INODE_TYPE: return print_inode;
			case SCOUTFS_XATTR_TYPE: return print_xattr;
			case SCOUTFS_DIRENT_TYPE: return print_dirent;
			case SCOUTFS_READDIR_TYPE: return print_readdir;
			case SCOUTFS_SYMLINK_TYPE: return print_symlink;
			case SCOUTFS_LINK_BACKREF_TYPE: return print_link_backref;
			case SCOUTFS_BLOCK_MAPPING_TYPE:
				return print_block_mapping;
		}
	}

	return NULL;
}

static void find_zone_type(void *key, u8 *zone, u8 *type)
{
	struct scoutfs_inode_index_key *idx_key = key;
	struct scoutfs_inode_key *ikey = key;
	struct scoutfs_orphan_key *okey = key;

	*zone = *(u8 *)key;

	switch (*zone) {
	case SCOUTFS_INODE_INDEX_ZONE:
		*type = idx_key->type;
		break;
	case SCOUTFS_NODE_ZONE:
		*type = okey->type;
		break;
	case SCOUTFS_FS_ZONE:
		*type = ikey->type;
		break;
	default:
		*type = 0;
	}
}

static void print_item(struct scoutfs_segment_block *sblk,
		       struct scoutfs_segment_item *item, u32 which, u32 off)
{
	print_func_t printer;
	void *key;
	void *val;
	u8 type;
	u8 zone;
	int i;

	key = (char *)&item->skip_links[item->nr_links];
	val = (char *)key + le16_to_cpu(item->key_len);

	find_zone_type(key, &zone, &type);
	printer = find_printer(zone, type);

	printf("  [%u]: off %u key_len %u val_len %u nr_links %u flags %x%s\n",
		which, off, le16_to_cpu(item->key_len),
		le16_to_cpu(item->val_len), item->nr_links,
		item->flags, printer ? "" : " (unrecognized zone+type)");
	printf("    links:");
	for (i = 0; i < item->nr_links; i++)
		printf(" %u", le32_to_cpu(item->skip_links[i]));
	printf("\n    key: ");
	print_key(key, le16_to_cpu(item->key_len));
	printf("\n");

	if (printer)
		printer(key, le16_to_cpu(item->key_len),
			val, le16_to_cpu(item->val_len));
}

static void print_segment_block(struct scoutfs_segment_block *sblk)
{
	int i;

	printf("  sblk: segno %llu seq %llu last_item_off %u total_bytes %u "
	       "nr_items %u\n",
		le64_to_cpu(sblk->segno), le64_to_cpu(sblk->seq),
		le32_to_cpu(sblk->last_item_off), le32_to_cpu(sblk->total_bytes),
		le32_to_cpu(sblk->nr_items));
	printf("    links:");
	for (i = 0; sblk->skip_links[i]; i++)
		printf(" %u", le32_to_cpu(sblk->skip_links[i]));
	printf("\n");
}

static int print_segments(int fd, unsigned long *seg_map, u64 total)
{
	struct scoutfs_segment_block *sblk;
	struct scoutfs_segment_item *item;
	u32 off;
	u64 s;
	u64 i;

	for (s = 0; (s = find_next_set_bit(seg_map, s, total)) < total; s++) {
		sblk = read_segment(fd, s);
		if (!sblk)
			return -ENOMEM;

		printf("segment segno %llu\n", s);
		print_segment_block(sblk);

		off = le32_to_cpu(sblk->skip_links[0]);
		for (i = 0; i < le32_to_cpu(sblk->nr_items); i++) {
			item = (void *)sblk + off;
			print_item(sblk, item, i, off);
			off = le32_to_cpu(item->skip_links[0]);
		}

		free(sblk);
	}

	return 0;
}

static int print_manifest_entry(void *key, unsigned key_len, void *val,
			        unsigned val_len, void *arg)
{
	struct scoutfs_manifest_btree_key *mkey = key;
	struct scoutfs_manifest_btree_val *mval = val;
	unsigned long *seg_map = arg;
	unsigned first_len;
	unsigned last_len;
	void *first;
	void *last;
	__be64 seq;

	/* parent items only have the key */
	if (val == NULL) {
		if (mkey->level == 0) {
			memcpy(&seq, mkey->bkey, sizeof(seq));
			printf("    level %u seq %llu\n",
			       mkey->level, be64_to_cpu(seq));
		} else {
			printf("    level %u first ", mkey->level);
			print_key(mkey->bkey, key_len - sizeof(mkey->level));
			printf("\n");
		}
		return 0;
	}

	/* leaf items print the whole entry */
	first_len = le16_to_cpu(mval->first_key_len);
	last_len = le16_to_cpu(mval->last_key_len);

	if (mkey->level == 0) {
		first = mval->keys;
		last = mval->keys + first_len;
	} else {
		first = mkey->bkey;
		last = mval->keys;
	}

	printf("    level %u segno %llu seq %llu first_len %u last_len %u\n",
	       mkey->level, le64_to_cpu(mval->segno), le64_to_cpu(mval->seq),
	       first_len, last_len);

	printf("    first ");
	print_key(first, first_len);
	printf("\n    last ");
	print_key(last, last_len);
	printf("\n");

	set_bit(seg_map, le64_to_cpu(mval->segno));

	return 0;
}

static int print_alloc_region(void *key, unsigned key_len, void *val,
			      unsigned val_len, void *arg)
{
	struct scoutfs_alloc_region_btree_key *reg_key = key;
	struct scoutfs_alloc_region_btree_val *reg_val = val;
	int i;

	/* XXX check sizes */

	printf("    index %llu bits", be64_to_cpu(reg_key->index));

	if (val == NULL)
		return 0;

	for (i = 0; i < array_size(reg_val->bits); i++)
		printf(" %016llx", le64_to_cpu(reg_val->bits[i]));
	printf("\n");

	return 0;
}

typedef int (*print_item_func)(void *key, unsigned key_len, void *val,
			       unsigned val_len, void *arg);

static int print_btree_ref(void *key, unsigned key_len, void *val,
			   unsigned val_len, print_item_func func, void *arg)
{
	struct scoutfs_btree_ref *ref = val;

	func(key, key_len, NULL, 0, arg);
	printf("    ref blkno %llu seq %llu\n",
		le64_to_cpu(ref->blkno), le64_to_cpu(ref->seq));

	return 0;
}

static int print_btree_block(int fd, struct scoutfs_super_block *super,
			     char *which, struct scoutfs_btree_ref *ref,
			     print_item_func func, void *arg, u8 level)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	unsigned key_len;
	unsigned val_len;
	void *key;
	void *val;
	int ret;
	int i;

	bt = read_block(fd, le64_to_cpu(ref->blkno));
	if (!bt)
		return -ENOMEM;

	if (bt->level == level) {
		printf("%s btree blkno %llu\n"
		       "  fsid %llx blkno %llu seq %llu crc %08x \n"
		       "  level %u free_end %u free_reclaim %u nr_items %u\n",
		       which, le64_to_cpu(ref->blkno),
		       le64_to_cpu(bt->fsid),
		       le64_to_cpu(bt->blkno),
		       le64_to_cpu(bt->seq),
		       le32_to_cpu(bt->crc),
		       bt->level,
		       le16_to_cpu(bt->free_end),
		       le16_to_cpu(bt->free_reclaim),
		       le16_to_cpu(bt->nr_items));
	}

	for (i = 0; i < le16_to_cpu(bt->nr_items); i++) {
		item = (void *)bt + le16_to_cpu(bt->item_hdrs[i].off);
		key_len = le16_to_cpu(item->key_len);
		val_len = le16_to_cpu(item->val_len);
		key = (void *)(item + 1);
		val = (void *)key + key_len;

		if (level < bt->level) {
			ref = val;
			/* XXX check len */
			if (ref->blkno) {
				ret = print_btree_block(fd, super, which, ref,
							func, arg, level);
				if (ret)
					break;
			}
			continue;
		}

		printf("  item [%u] off %u key_len %u val_len %u\n",
			i, le16_to_cpu(bt->item_hdrs[i].off), key_len, val_len);

		if (level)
			print_btree_ref(key, key_len, val, val_len, func, arg);
		else
			func(key, key_len, val, val_len, arg);
	}

	free(bt);
	return 0;
}

/*
 * We print btrees by a breadth-first search.  This way all the parent
 * blocks are printed before the factor of fanout more numerous leaf
 * blocks and their included items.
 */
static int print_btree(int fd, struct scoutfs_super_block *super, char *which,
		       struct scoutfs_btree_root *root,
		       print_item_func func, void *arg)
{
	int ret = 0;
	int i;

	for (i = root->height - 1; i >= 0; i--) {
		ret = print_btree_block(fd, super, which, &root->ref,
					func, arg, i);
		if (ret)
			break;
	}

	return ret;
}

static void print_super_block(struct scoutfs_super_block *super, u64 blkno)
{
	char uuid_str[37];
	__le64 *counts;
	int i;

	uuid_unparse(super->uuid, uuid_str);

	printf("super blkno %llu\n", blkno);
	print_block_header(&super->hdr);
	printf("  id %llx format_hash %llx\n"
	       "  uuid %s\n",
	       le64_to_cpu(super->id), le64_to_cpu(super->format_hash),
	       uuid_str);

	/* XXX these are all in a crazy order */
	printf("  next_ino %llu next_seq %llu next_seg_seq %llu\n"
	       "  alloc_uninit %llu total_segs %llu free_segs %llu\n"
	       "  btree ring: first_blkno %llu nr_blocks %llu next_block %llu "
	       "next_seq %llu\n"
	       "  alloc btree root: height %u blkno %llu seq %llu mig_len %u\n"
	       "  manifest btree root: height %u blkno %llu seq %llu mig_len %u\n",
		le64_to_cpu(super->next_ino),
		le64_to_cpu(super->next_seq),
		le64_to_cpu(super->next_seg_seq),
		le64_to_cpu(super->alloc_uninit),
		le64_to_cpu(super->total_segs),
		le64_to_cpu(super->free_segs),
		le64_to_cpu(super->bring.first_blkno),
		le64_to_cpu(super->bring.nr_blocks),
		le64_to_cpu(super->bring.next_block),
		le64_to_cpu(super->bring.next_seq),
		super->alloc_root.height,
		le64_to_cpu(super->alloc_root.ref.blkno),
		le64_to_cpu(super->alloc_root.ref.seq),
		le16_to_cpu(super->alloc_root.migration_key_len),
		super->manifest.root.height,
		le64_to_cpu(super->manifest.root.ref.blkno),
		le64_to_cpu(super->manifest.root.ref.seq),
		le16_to_cpu(super->manifest.root.migration_key_len));

	printf("  level_counts:");
	counts = super->manifest.level_counts;
	for (i = 0; i < SCOUTFS_MANIFEST_MAX_LEVEL; i++) {
		if (le64_to_cpu(counts[i]))
			printf(" %u: %llu", i, le64_to_cpu(counts[i]));
	}
	printf("\n");
}

static int print_super_blocks(int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_super_block recent = { .hdr.seq = 0 };
	unsigned long *seg_map;
	int ret = 0;
	int err;
	int i;
	int r = 0;

	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {
		super = read_block(fd, SCOUTFS_SUPER_BLKNO + i);
		if (!super)
			return -ENOMEM;

		if (le64_to_cpu(super->hdr.seq) > le64_to_cpu(recent.hdr.seq)) {
			memcpy(&recent, super, sizeof(recent));
			r = i;
		}

		free(super);
	}

	super = &recent;

	print_super_block(super, SCOUTFS_SUPER_BLKNO + r);

	seg_map = alloc_bits(le64_to_cpu(super->total_segs));
	if (!seg_map) {
		ret = -ENOMEM;
		fprintf(stderr, "failed to alloc %llu seg map: %s (%d)\n",
			le64_to_cpu(super->total_segs),
			strerror(errno), errno);
		return ret;
	}

	ret = print_btree(fd, super, "alloc", &super->alloc_root,
			  print_alloc_region, NULL);

	err = print_btree(fd, super, "manifest", &super->manifest.root,
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

	if (argc != 2) {
		printf("scoutfs print: a single path argument is required\n");
		return -EINVAL;
	}
	path = argv[1];

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
