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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

	printf("  hdr: crc %08x %smagic %08x fsid %llx seq %llu blkno %llu\n",
		le32_to_cpu(hdr->crc), valid_str, le32_to_cpu(hdr->magic),
		le64_to_cpu(hdr->fsid), le64_to_cpu(hdr->blkno),
		le64_to_cpu(hdr->seq));
}

static void print_inode(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_inode *inode = val;

	printf("    inode: ino %llu size %llu nlink %u\n"
	       "      uid %u gid %u mode 0%o rdev 0x%x flags 0x%x\n"
	       "      next_readdir_pos %llu meta_seq %llu data_seq %llu data_version %llu\n"
	       "      atime %llu.%08u ctime %llu.%08u\n"
	       "      mtime %llu.%08u\n",
	       le64_to_cpu(key->ski_ino),
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

static void print_orphan(struct scoutfs_key *key, void *val, int val_len)
{
	printf("    orphan: ino %llu\n", le64_to_cpu(key->sko_ino));
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

static void print_xattr(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_xattr *xat = val;

	printf("    xattr: ino %llu name_hash %08x id %llu part %u\n",
	       le64_to_cpu(key->skx_ino), (u32)le64_to_cpu(key->skx_name_hash),
	       le64_to_cpu(key->skx_id), key->skx_part);

	if (key->skx_part == 0)
		printf("      name_len %u val_len %u name %s\n",
		       xat->name_len, le16_to_cpu(xat->val_len),
		       global_printable_name(xat->name, xat->name_len));
}

static void print_dirent(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_dirent *dent = val;
	unsigned int name_len = val_len - sizeof(*dent);
	u8 *name = global_printable_name(dent->name, name_len);

	printf("    dirent: dir %llu hash %016llx pos %llu type %u ino %llu\n"
	       "      name %s\n",
	       le64_to_cpu(key->skd_ino), le64_to_cpu(dent->hash),
	       le64_to_cpu(dent->pos), dent->type, le64_to_cpu(dent->ino),
	       name);
}

static void print_symlink(struct scoutfs_key *key, void *val, int val_len)
{
	u8 *frag = val;
	u8 *name;

	/* don't try to print null term */
	if (frag[val_len - 1] == '\0')
		val_len--;
	name = global_printable_name(frag, val_len);

	printf("    symlink: ino %llu nr %llu\n"
	       "      target %s\n",
	       le64_to_cpu(key->sks_ino), le64_to_cpu(key->sks_nr), name);
}

static void print_file_extent(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_file_extent *fex = val;
	u64 iblock = le64_to_cpu(key->skfe_last) - le64_to_cpu(fex->len) + 1;

	printf("      extent: ino %llu (last %llu) iblock %llu len %llu "
	       "blkno %llu flags 0x%x\n",
	       le64_to_cpu(key->skfe_ino), le64_to_cpu(key->skfe_last),
	       iblock, le64_to_cpu(fex->len), le64_to_cpu(fex->blkno),
	       fex->flags);
}

static void print_free_extent(struct scoutfs_key *key, void *val, int val_len)
{
	u64 start = le64_to_cpu(key->sknf_major);
	u64 len = le64_to_cpu(key->sknf_minor);
	if (key->sk_type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
		swap(start, len);
	start -= (len - 1);

	printf("      free extent: major %llu minor %llu (start %llu "
	       "len %llu)\n",
	       le64_to_cpu(key->sknf_major), le64_to_cpu(key->sknf_minor),
	       start, len);
}

static void print_inode_index(struct scoutfs_key *key, void *val, int val_len)
{
	printf("      index: major %llu ino %llu\n",
	       le64_to_cpu(key->skii_major), le64_to_cpu(key->skii_ino));
}

static void print_xattr_index(struct scoutfs_key *key, void *val, int val_len)
{
	printf("      xattr index: hash 0x%016llx ino %llu id %llu\n",
	       le64_to_cpu(key->skxi_hash), le64_to_cpu(key->skxi_ino),
	       le64_to_cpu(key->skxi_id));
}

typedef void (*print_func_t)(struct scoutfs_key *key, void *val, int val_len);

static print_func_t find_printer(u8 zone, u8 type)
{
	if (zone == SCOUTFS_INODE_INDEX_ZONE &&
	    type >= SCOUTFS_INODE_INDEX_META_SEQ_TYPE  &&
	    type <= SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE)
		return print_inode_index;

	if (zone == SCOUTFS_XATTR_INDEX_ZONE &&
	    type >= SCOUTFS_XATTR_INDEX_NAME_TYPE)
		return print_xattr_index;

	if (zone == SCOUTFS_NODE_ZONE) {
		if (type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE ||
		    type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
			return print_free_extent;
		if (type == SCOUTFS_ORPHAN_TYPE)
			return print_orphan;
	}

	if (zone == SCOUTFS_FS_ZONE) {
		switch(type) {
			case SCOUTFS_INODE_TYPE: return print_inode;
			case SCOUTFS_XATTR_TYPE: return print_xattr;
			case SCOUTFS_DIRENT_TYPE: return print_dirent;
			case SCOUTFS_READDIR_TYPE: return print_dirent;
			case SCOUTFS_SYMLINK_TYPE: return print_symlink;
			case SCOUTFS_LINK_BACKREF_TYPE: return print_dirent;
			case SCOUTFS_FILE_EXTENT_TYPE: return print_file_extent;
		}
	}

	return NULL;
}

static void print_item(struct scoutfs_segment_block *sblk,
		       struct scoutfs_segment_item *item, u32 which, u32 off)
{
	print_func_t printer;
	void *val;
	int i;

	val = (char *)&item->skip_links[item->nr_links];

	printer = find_printer(item->key.sk_zone, item->key.sk_type);

	printf("  [%u]: key "SK_FMT" off %u val_len %u nr_links %u flags %x%s\n",
		which, SK_ARG(&item->key), off, le16_to_cpu(item->val_len),
		item->nr_links,
		item->flags, printer ? "" : " (unrecognized zone+type)");
	printf("    links:");
	for (i = 0; i < item->nr_links; i++)
		printf(" %u", le32_to_cpu(item->skip_links[i]));
	printf("\n");

	if (printer)
		printer(&item->key, val, le16_to_cpu(item->val_len));
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
	struct scoutfs_key first;
	unsigned long *seg_map = arg;

	scoutfs_key_from_be(&first, &mkey->first_key);

	printf("    level %u first "SK_FMT" seq %llu\n",
	       mkey->level, SK_ARG(&first), be64_to_cpu(mkey->seq));

	/* only items in leaf blocks have values */
	if (val) {
		printf("    segno %llu last "SK_FMT"\n",
		       le64_to_cpu(mval->segno), SK_ARG(&mval->last_key));

		set_bit(seg_map, le64_to_cpu(mval->segno));
	}

	return 0;
}

static int print_alloc_item(void *key, unsigned key_len, void *val,
			    unsigned val_len, void *arg)
{
	struct scoutfs_extent_btree_key *ebk = key;
	u64 start;
	u64 len;

	/* XXX check sizes */

	len = be64_to_cpu(ebk->minor);
	start = be64_to_cpu(ebk->major);
	if (ebk->type == SCOUTFS_FREE_EXTENT_BLOCKS_TYPE)
		swap(start, len);
	start -= len - 1;

	printf("    type %u major %llu minor %llu (start %llu len %llu)\n",
			ebk->type, be64_to_cpu(ebk->major),
			be64_to_cpu(ebk->minor), start, len);

	return 0;
}

static int print_lock_clients_entry(void *key, unsigned key_len, void *val,
				    unsigned val_len, void *arg)
{
	struct scoutfs_lock_client_btree_key *cbk = key;

	printf("    node_ld %llu\n", be64_to_cpu(cbk->node_id));

	return 0;
}

static int print_trans_seqs_entry(void *key, unsigned key_len, void *val,
				  unsigned val_len, void *arg)
{
	struct scoutfs_trans_seq_btree_key *tsk = key;

	printf("    trans_seq %llu node_ld %llu\n",
	       be64_to_cpu(tsk->trans_seq), be64_to_cpu(tsk->node_id));

	return 0;
}

/* XXX should make sure that the val is null terminated */
static int print_mounted_client_entry(void *key, unsigned key_len, void *val,
				      unsigned val_len, void *arg)
{
	struct scoutfs_mounted_client_btree_key *mck = key;
	struct scoutfs_mounted_client_btree_val *mcv = val;

	printf("    node_id %llu name %s\n",
			be64_to_cpu(mck->node_id), mcv->name);

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
		       "  crc %08x fsid %llx seq %llu blkno %llu \n"
		       "  level %u free_end %u free_reclaim %u nr_items %u\n",
		       which, le64_to_cpu(ref->blkno),
		       le32_to_cpu(bt->hdr.crc),
		       le64_to_cpu(bt->hdr.fsid),
		       le64_to_cpu(bt->hdr.seq),
		       le64_to_cpu(bt->hdr.blkno),
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

static int print_quorum_blocks(int fd, struct scoutfs_super_block *super)
{
	struct scoutfs_quorum_block *blk;
	u64 blkno;
	int ret;
	int i;

	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		blkno = SCOUTFS_QUORUM_BLKNO + i;
		blk = read_block(fd, blkno);
		if (!blk) {
			ret = -ENOMEM;
			break;
		}

		if (blk->fsid != 0 || blk->write_nr != 0) {
			printf("quorum block blkno %llu\n"
			       "  fsid %llx blkno %llu config_gen %llu crc 0x%08x\n"
			       "  write_nr %llu elected_nr %llu "
			       "unmount_barrier %llu vote_slot %u flags %02x\n",
			       blkno, le64_to_cpu(blk->fsid),
			       le64_to_cpu(blk->blkno),
			       le64_to_cpu(blk->config_gen),
			       le32_to_cpu(blk->crc),
			       le64_to_cpu(blk->write_nr),
			       le64_to_cpu(blk->elected_nr),
			       le64_to_cpu(blk->unmount_barrier),
			       blk->vote_slot, blk->flags);
		}

		free(blk);
		ret = 0;
	}

	return ret;
}

static void print_slot_flags(unsigned long flags)
{
	if (flags == 0) {
		printf("-");
		return;
	}

	while (flags) {
		if (flags & SCOUTFS_QUORUM_SLOT_ACTIVE) {
			printf("active");
			flags &= ~SCOUTFS_QUORUM_SLOT_ACTIVE;

		} else if (flags & SCOUTFS_QUORUM_SLOT_STALE) {
			printf("stale");
			flags &= ~SCOUTFS_QUORUM_SLOT_STALE;
		}

		if (flags)
			printf(",");
	}
}

static void print_super_block(struct scoutfs_super_block *super, u64 blkno)
{
	struct scoutfs_quorum_slot *slot;
	char uuid_str[37];
	struct in_addr in;
	u64 count;
	int i;

	uuid_unparse(super->uuid, uuid_str);

	printf("super blkno %llu\n", blkno);
	print_block_header(&super->hdr);
	printf("  format_hash %llx uuid %s\n",
	       le64_to_cpu(super->format_hash), uuid_str);

	/* XXX these are all in a crazy order */
	printf("  next_ino %llu next_trans_seq %llu next_seg_seq %llu\n"
	       " next_node_id %llu next_compact_id %llu\n"
	       "  total_blocks %llu free_blocks %llu alloc_cursor %llu\n"
	       "  btree ring: first_blkno %llu nr_blocks %llu next_block %llu "
	       "next_seq %llu\n"
	       "  lock_clients root: height %u blkno %llu seq %llu mig_len %u\n"
	       "  mounted_clients root: height %u blkno %llu seq %llu mig_len %u\n"
	       "  trans_seqs root: height %u blkno %llu seq %llu mig_len %u\n"
	       "  alloc btree root: height %u blkno %llu seq %llu mig_len %u\n"
	       "  manifest btree root: height %u blkno %llu seq %llu mig_len %u\n",
		le64_to_cpu(super->next_ino),
		le64_to_cpu(super->next_trans_seq),
		le64_to_cpu(super->next_seg_seq),
		le64_to_cpu(super->next_node_id),
		le64_to_cpu(super->next_compact_id),
		le64_to_cpu(super->total_blocks),
		le64_to_cpu(super->free_blocks),
		le64_to_cpu(super->alloc_cursor),
		le64_to_cpu(super->bring.first_blkno),
		le64_to_cpu(super->bring.nr_blocks),
		le64_to_cpu(super->bring.next_block),
		le64_to_cpu(super->bring.next_seq),
		super->lock_clients.height,
		le64_to_cpu(super->lock_clients.ref.blkno),
		le64_to_cpu(super->lock_clients.ref.seq),
		le16_to_cpu(super->lock_clients.migration_key_len),
		super->mounted_clients.height,
		le64_to_cpu(super->mounted_clients.ref.blkno),
		le64_to_cpu(super->mounted_clients.ref.seq),
		le16_to_cpu(super->mounted_clients.migration_key_len),
		super->trans_seqs.height,
		le64_to_cpu(super->trans_seqs.ref.blkno),
		le64_to_cpu(super->trans_seqs.ref.seq),
		le16_to_cpu(super->trans_seqs.migration_key_len),
		super->alloc_root.height,
		le64_to_cpu(super->alloc_root.ref.blkno),
		le64_to_cpu(super->alloc_root.ref.seq),
		le16_to_cpu(super->alloc_root.migration_key_len),
		super->manifest.root.height,
		le64_to_cpu(super->manifest.root.ref.blkno),
		le64_to_cpu(super->manifest.root.ref.seq),
		le16_to_cpu(super->manifest.root.migration_key_len));

	printf("  level_counts:");
	for (i = 0; i < SCOUTFS_MANIFEST_MAX_LEVEL; i++) {
		count = le64_to_cpu(super->manifest.level_counts[i]);
		if (count)
			printf(" %u: %llu", i, count);
	}
	printf("\n");

	printf("  quorum_config:\n    gen: %llu\n",
	       le64_to_cpu(super->quorum_config.gen));
	for (i = 0; i < array_size(super->quorum_config.slots); i++) {
		slot = &super->quorum_config.slots[i];
		if (slot->flags == 0)
			continue;

		in.s_addr = htonl(le32_to_cpu(slot->addr.addr));

		printf("    [%2u]: name %s priority %u addr %s:%u flags ",
		       i, slot->name, slot->vote_priority, inet_ntoa(in),
		       le16_to_cpu(slot->addr.port));
		print_slot_flags(slot->flags);
		printf("\n");
	}
}

static int print_volume(int fd)
{
	struct scoutfs_super_block *super = NULL;
	unsigned long *seg_map = NULL;
	u64 nr_segs;
	int ret = 0;
	int err;

	super = read_block(fd, SCOUTFS_SUPER_BLKNO);
	if (!super)
		return -ENOMEM;

	print_super_block(super, SCOUTFS_SUPER_BLKNO);

	nr_segs = le64_to_cpu(super->total_blocks) / SCOUTFS_SEGMENT_BLOCKS;
	seg_map = alloc_bits(nr_segs);
	if (!seg_map) {
		ret = -ENOMEM;
		fprintf(stderr, "failed to alloc %llu seg map: %s (%d)\n",
			nr_segs, strerror(errno), errno);
		goto out;
	}

	ret = print_quorum_blocks(fd, super);

	err = print_btree(fd, super, "lock_clients", &super->lock_clients,
			  print_lock_clients_entry, NULL);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "mounted_clients", &super->mounted_clients,
			  print_mounted_client_entry, NULL);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "trans_seqs", &super->trans_seqs,
			  print_trans_seqs_entry, NULL);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "alloc", &super->alloc_root,
  			  print_alloc_item, NULL);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "manifest", &super->manifest.root,
			  print_manifest_entry, seg_map);
	if (err && !ret)
		ret = err;

	err = print_segments(fd, seg_map, nr_segs);
	if (err && !ret)
		ret = err;

out:
	free(super);
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

	ret = print_volume(fd);
	close(fd);
	return ret;
};

static void __attribute__((constructor)) print_ctor(void)
{
	cmd_register("print", "<device>", "print metadata structures",
			print_cmd);
}
