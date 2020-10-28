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
#include "avl.h"
#include "srch.h"
#include "leaf_item_hash.h"

static void *read_block(int fd, u64 blkno, int shift)
{
	size_t size = 1ULL << shift;
	ssize_t ret;
	void *buf;

	buf = malloc(size);
	if (!buf)
		return NULL;

	ret = pread(fd, buf, size, blkno << shift);
	if (ret != size) {
		fprintf(stderr, "read blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		free(buf);
		buf = NULL;
	}

	return buf;
}

static void print_block_header(struct scoutfs_block_header *hdr, int size)
{
	u32 crc = crc_block(hdr, size);
	char valid_str[40];

	if (crc != le32_to_cpu(hdr->crc))
		sprintf(valid_str, "(!= %08x) ", crc);
	else
		valid_str[0] = '\0';

	printf("  hdr: crc %08x %smagic %08x fsid %llx blkno %llu seq %llu\n",
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

static void print_data_extent(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_data_extent_val *dv = val;
	u64 iblock;

	iblock = le64_to_cpu(key->skdx_end) - le64_to_cpu(key->skdx_len) + 1;

	printf("    extent: ino %llu iblock %llu len %llu blkno %llu flags %x\n",
	       le64_to_cpu(key->skdx_ino), iblock,
	       le64_to_cpu(key->skdx_len),
	       le64_to_cpu(dv->blkno), dv->flags);
}

static void print_inode_index(struct scoutfs_key *key, void *val, int val_len)
{
	printf("      index: major %llu ino %llu\n",
	       le64_to_cpu(key->skii_major), le64_to_cpu(key->skii_ino));
}

typedef void (*print_func_t)(struct scoutfs_key *key, void *val, int val_len);

static print_func_t find_printer(u8 zone, u8 type)
{
	if (zone == SCOUTFS_INODE_INDEX_ZONE &&
	    type >= SCOUTFS_INODE_INDEX_META_SEQ_TYPE  &&
	    type <= SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE)
		return print_inode_index;

	if (zone == SCOUTFS_RID_ZONE) {
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
			case SCOUTFS_DATA_EXTENT_TYPE: return print_data_extent;
		}
	}

	return NULL;
}

static int print_fs_item(struct scoutfs_key *key, void *val,
			 unsigned val_len, void *arg)
{
	print_func_t printer;

	printf("    "SK_FMT"\n", SK_ARG(key));

	/* only items in leaf blocks have values */
	if (val) {
		printer = find_printer(key->sk_zone, key->sk_type);
		if (printer)
			printer(key, val, val_len);
		else
			printf("      (unknown zone %u type %u)\n",
			       key->sk_zone, key->sk_type);
	}

	return 0;
}

/* same as fs item but with a small header in the value */
static int print_logs_item(struct scoutfs_key *key, void *val,
			   unsigned val_len, void *arg)
{
	struct scoutfs_log_item_value *liv;
	print_func_t printer;

	printf("    "SK_FMT"\n", SK_ARG(key));

	/* only items in leaf blocks have values */
	if (val) {
		liv = val;
		printf("    log_item_value: vers %llu flags %x\n",
		       le64_to_cpu(liv->vers), liv->flags);

		/* deletion items don't have values */
		if (!(liv->flags & SCOUTFS_LOG_ITEM_FLAG_DELETION)) {
			printer = find_printer(key->sk_zone,
					       key->sk_type);
			if (printer)
				printer(key, val + sizeof(*liv),
					val_len - sizeof(*liv));
			else
				printf("      (unknown zone %u type %u)\n",
				       key->sk_zone, key->sk_type);
		}
	}

	return 0;
}

#define BTREF_F \
	"blkno %llu seq %llu"
#define BTREF_A(ref) \
	le64_to_cpu((ref)->blkno), le64_to_cpu((ref)->seq)

#define BTROOT_F \
	BTREF_F" height %u"
#define BTROOT_A(root) \
	BTREF_A(&(root)->ref), (root)->height

#define AL_REF_F \
	"blkno %llu seq %llu"
#define AL_REF_A(p) \
	le64_to_cpu((p)->blkno), le64_to_cpu((p)->seq)

#define AL_HEAD_F \
	AL_REF_F" total_nr %llu first_nr %u"
#define AL_HEAD_A(p)					\
	AL_REF_A(&(p)->ref), le64_to_cpu((p)->total_nr),\
	le32_to_cpu((p)->first_nr)

#define ALCROOT_F \
	BTROOT_F" total_len %llu"
#define ALCROOT_A(ar) \
	BTROOT_A(&(ar)->root), le64_to_cpu((ar)->total_len)

#define SRE_FMT "%016llx.%llu.%llu"
#define SRE_A(sre)						\
	le64_to_cpu((sre)->hash), le64_to_cpu((sre)->ino),	\
	le64_to_cpu((sre)->id)

#define SRF_FMT \
	"f "SRE_FMT" l "SRE_FMT" blks %llu ents %llu hei %u blkno %llu seq %016llx"
#define SRF_A(srf)						\
	SRE_A(&(srf)->first), SRE_A(&(srf)->last),		\
	le64_to_cpu((srf)->blocks), le64_to_cpu((srf)->entries), \
	(srf)->height, le64_to_cpu((srf)->ref.blkno),		\
	le64_to_cpu((srf)->ref.seq)

/* same as fs item but with a small header in the value */
static int print_log_trees_item(struct scoutfs_key *key, void *val,
				unsigned val_len, void *arg)
{
	struct scoutfs_log_trees_val *ltv = val;

	printf("    rid %llu nr %llu\n",
	       le64_to_cpu(key->sklt_rid), le64_to_cpu(key->sklt_nr));

	/* only items in leaf blocks have values */
	if (val) {
		printf("      meta_avail: "AL_HEAD_F"\n"
		       "      meta_freed: "AL_HEAD_F"\n"
		       "      item_root: height %u blkno %llu seq %llu\n"
		       "      bloom_ref: blkno %llu seq %llu\n"
		       "      data_avail: "ALCROOT_F"\n"
		       "      data_freed: "ALCROOT_F"\n"
		       "      srch_file: "SRF_FMT"\n",
		       AL_HEAD_A(&ltv->meta_avail),
		       AL_HEAD_A(&ltv->meta_freed),
			ltv->item_root.height,
			le64_to_cpu(ltv->item_root.ref.blkno),
			le64_to_cpu(ltv->item_root.ref.seq),
			le64_to_cpu(ltv->bloom_ref.blkno),
			le64_to_cpu(ltv->bloom_ref.seq),
		       ALCROOT_A(&ltv->data_avail),
		       ALCROOT_A(&ltv->data_freed),
		       SRF_A(&ltv->srch_file));
	}

	return 0;
}

static int print_srch_root_item(struct scoutfs_key *key, void *val,
				unsigned val_len, void *arg)
{
	struct scoutfs_srch_compact *sc;
	struct scoutfs_srch_file *sfl;
	int i;

	printf("    "SK_FMT"\n", SK_ARG(key));

	/* only items in leaf blocks have values */
	if (val) {
		if (key->sk_type == SCOUTFS_SRCH_PENDING_TYPE ||
		    key->sk_type == SCOUTFS_SRCH_BUSY_TYPE) {
			sc = val;
			printf("      compact %s: nr %u flags 0x%x\n",
			       key->sk_type == SCOUTFS_SRCH_PENDING_TYPE ?
					"pending" : "busy",
			       sc->nr, sc->flags);
			for (i = 0; i < sc->nr; i++) {
				printf("        [%u] blk %llu pos %llu sfl "SRF_FMT"\n",
				       i, le64_to_cpu(sc->in[i].blk),
				       le64_to_cpu(sc->in[i].pos),
				       SRF_A(&sc->in[i].sfl));
			}
		} else {
			sfl = val;
			printf("      "SRF_FMT"\n", SRF_A(sfl));
		}
	}

	return 0;
}

static int print_lock_clients_entry(struct scoutfs_key *key, void *val,
				    unsigned val_len, void *arg)
{
	printf("    rid %016llx\n", le64_to_cpu(key->sklc_rid));

	return 0;
}

static int print_trans_seqs_entry(struct scoutfs_key *key, void *val,
				  unsigned val_len, void *arg)
{
	printf("    trans_seq %llu rid %016llx\n",
	       le64_to_cpu(key->skts_trans_seq), le64_to_cpu(key->skts_rid));

	return 0;
}

static int print_mounted_client_entry(struct scoutfs_key *key, void *val,
				      unsigned val_len, void *arg)
{
	struct scoutfs_mounted_client_btree_val *mcv = val;

	printf("    rid %016llx flags 0x%x\n",
	       le64_to_cpu(key->skmc_rid), mcv->flags);

	return 0;
}

static int print_alloc_item(struct scoutfs_key *key, void *val,
			    unsigned val_len, void *arg)
{
	if (key->sk_type == SCOUTFS_FREE_EXTENT_BLKNO_TYPE)
		printf("    free extent: blkno %llu len %llu end %llu\n",
		       le64_to_cpu(key->skfb_end) -
		       le64_to_cpu(key->skfb_len) + 1,
		       le64_to_cpu(key->skfb_len),
		       le64_to_cpu(key->skfb_end));
	else
		printf("    free extent: blkno %llu len %llu neglen %lld\n",
		       le64_to_cpu(key->skfl_blkno),
		       -le64_to_cpu(key->skfl_neglen),
		       (long long)le64_to_cpu(key->skfl_neglen));

	return 0;
}

typedef int (*print_item_func)(struct scoutfs_key *key, void *val,
			       unsigned val_len, void *arg);

static int print_btree_ref(struct scoutfs_key *key, void *val,
			   unsigned val_len, print_item_func func, void *arg)
{
	struct scoutfs_btree_ref *ref = val;

	func(key, NULL, 0, arg);
	printf("    ref blkno %llu seq %llu\n",
		le64_to_cpu(ref->blkno), le64_to_cpu(ref->seq));

	return 0;
}

static void print_leaf_item_hash(struct scoutfs_btree_block *bt)
{
	__le16 *b;
	int col;
	int nr;
	int i;

	/* print the leaf item hash */
	printf("  item hash: ");
	col = 13;

	b = leaf_item_hash_buckets(bt);
	nr = 0;
	for (i = 0; i < SCOUTFS_BTREE_LEAF_ITEM_HASH_NR; i++) {
		if (b[i] == 0)
			continue;

		nr++;
		col += snprintf(NULL, 0, "%u,%u ", i, le16_to_cpu(b[i]));
		if (col >= 78) {
			printf("\n   ");
			col = 3;
		}
		printf("%u,%u ", i, le16_to_cpu(b[i]));
	}
	if (col != 3)
		printf("\n");
	printf("    (%u / %u populated, %u%% load)\n",
	       nr, (int)SCOUTFS_BTREE_LEAF_ITEM_HASH_NR,
	       nr * 100 / (int)SCOUTFS_BTREE_LEAF_ITEM_HASH_NR);
}

static int print_btree_block(int fd, struct scoutfs_super_block *super,
			     char *which, struct scoutfs_btree_ref *ref,
			     print_item_func func, void *arg, u8 level)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *node;
	struct scoutfs_btree_block *bt;
	struct scoutfs_key *key;
	unsigned int val_len;
	unsigned int off;
	void *val;
	int ret;
	int i;

	bt = read_block(fd, le64_to_cpu(ref->blkno), SCOUTFS_BLOCK_LG_SHIFT);
	if (!bt)
		return -ENOMEM;

	if (bt->level == level) {
		printf("%s btree blkno %llu\n"
		       "  crc %08x fsid %llx seq %llu blkno %llu \n"
		       "  total_item_bytes %u mid_free_len %u\n"
		       "  level %u nr_items %u item_root.node %u\n",
		       which, le64_to_cpu(ref->blkno),
		       le32_to_cpu(bt->hdr.crc),
		       le64_to_cpu(bt->hdr.fsid),
		       le64_to_cpu(bt->hdr.seq),
		       le64_to_cpu(bt->hdr.blkno),
		       le16_to_cpu(bt->total_item_bytes),
		       le16_to_cpu(bt->mid_free_len),
		       bt->level,
		       le16_to_cpu(bt->nr_items),
		       le16_to_cpu(bt->item_root.node));

		if (bt->level == 0)
			print_leaf_item_hash(bt);
	}

	for (i = 0, node = avl_first(&bt->item_root);
	     node;
	     i++, node = avl_next(&bt->item_root, node)) {

		item = container_of(node, struct scoutfs_btree_item, node);
		off = (void *)item - (void *)bt;
		val_len = le16_to_cpu(item->val_len);
		key = &item->key;
		val = (void *)bt + le16_to_cpu(item->val_off);

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

		printf("  [%u] off %u par %u l %u r %u h %u vo %u vl %u\n",
			i, off, le16_to_cpu(item->node.parent),
			le16_to_cpu(item->node.left),
			le16_to_cpu(item->node.right),
			item->node.height, le16_to_cpu(item->val_off),
			val_len);

		if (level)
			print_btree_ref(key, val, val_len, func, arg);
		else
			func(key, val, val_len, arg);
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

static int print_alloc_list_block(int fd, char *str,
				  struct scoutfs_alloc_list_ref *ref)
{
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_alloc_list_ref next;
	u64 blkno;
	u64 start;
	u64 len;
	int wid;
	int i;

	blkno = le64_to_cpu(ref->blkno);
	if (blkno == 0)
		return 0;

	lblk = read_block(fd, blkno, SCOUTFS_BLOCK_LG_SHIFT);
	if (!lblk)
		return -ENOMEM;

	printf("%s alloc_list_block blkno %llu\n", str, blkno);
	print_block_header(&lblk->hdr, SCOUTFS_BLOCK_LG_SIZE);
	printf("  next "AL_REF_F" start %u nr %u\n",
	       AL_REF_A(&lblk->next), le32_to_cpu(lblk->start),
	       le32_to_cpu(lblk->nr));

	if (lblk->nr) {
		wid = printf("  exts: ");
		start = 0;
		len = 0;
		for (i = 0; i < le32_to_cpu(lblk->nr); i++) {
			if (len == 0)
				start = le64_to_cpu(lblk->blknos[i]);
			len++;

			if (i == (le32_to_cpu(lblk->nr) - 1) ||
			    start + len != le64_to_cpu(lblk->blknos[i + 1])) {
				if (wid >= 72)
					wid = printf("\n        ");

				wid += printf("%llu,%llu ", start, len);
				len = 0;
			}
		}
		printf("\n");
	}

	next = lblk->next;
	free(lblk);
	return print_alloc_list_block(fd, str, &next);
}

static int print_srch_block(int fd, struct scoutfs_srch_ref *ref, int level)
{
	struct scoutfs_srch_parent *srp;
	struct scoutfs_srch_block *srb;
	struct scoutfs_srch_entry sre;
	struct scoutfs_srch_entry prev;
	u64 blkno;
	int pos;
	int ret;
	int err;
	int i;

	blkno = le64_to_cpu(ref->blkno);
	if (blkno == 0)
		return 0;

	srp = read_block(fd, blkno, SCOUTFS_BLOCK_LG_SHIFT);
	if (!srp) {
		ret = -ENOMEM;
		goto out;
	}
	srb = (void *)srp;

	printf("srch %sblock blkno %llu\n", level ? "parent " : "", blkno);
	print_block_header(&srp->hdr, SCOUTFS_BLOCK_LG_SIZE);

	for (i = 0; level > 0 && i < SCOUTFS_SRCH_PARENT_REFS; i++) {
		if (le64_to_cpu(srp->refs[i].blkno) == 0)
			continue;
		printf("  [%u]: blkno %llu seq %llu\n",
		       i, le64_to_cpu(srp->refs[i].blkno),
		       le64_to_cpu(srp->refs[i].seq));
	}

	ret = 0;
	for (i = 0; level > 0 && i < SCOUTFS_SRCH_PARENT_REFS; i++) {
		if (le64_to_cpu(srp->refs[i].blkno) == 0)
			continue;
		err = print_srch_block(fd, &srp->refs[i], level - 1);
		if (err < 0 && ret == 0)
			ret = err;
	}

	if (level > 0)
		goto out;

	printf("  first "SRE_FMT" last "SRE_FMT" tail "SRE_FMT"\n"
	       "  entry_nr %u entry_bytes %u\n",
	       SRE_A(&srb->first), SRE_A(&srb->last), SRE_A(&srb->tail),
	       le32_to_cpu(srb->entry_nr), le32_to_cpu(srb->entry_bytes));

	memset(&prev, 0, sizeof(prev));
	pos = 0;
	for (i = 0; level == 0 && i < le32_to_cpu(srb->entry_nr); i++) {
		if (pos > SCOUTFS_SRCH_BLOCK_SAFE_BYTES) {
			ret = EIO;
			break;
		}

		ret = srch_decode_entry(srb->entries + pos, &sre, &prev);
		if (ret < 0)
			break;
		pos += ret;
		prev = sre;
		printf("  [%u]: (%u) "SRE_FMT"\n", i, ret, SRE_A(&sre));
	}

out:
	free(srp);

	return ret;
}

struct print_recursion_args {
	struct scoutfs_super_block *super;
	int fd;
	u8 __pad[4];
};

/* same as fs item but with a small header in the value */
static int print_log_trees_roots(struct scoutfs_key *key, void *val,
				unsigned val_len, void *arg)
{
	struct scoutfs_log_trees_val *ltv = val;
	struct print_recursion_args *pa = arg;
	int ret = 0;
	int err;

	/* XXX doesn't print the bloom block */

	err = print_alloc_list_block(pa->fd, "ltv_meta_avail",
				     &ltv->meta_avail.ref);
	if (err && !ret)
		ret = err;
	err = print_alloc_list_block(pa->fd, "ltv_meta_freed",
				     &ltv->meta_freed.ref);
	if (err && !ret)
		ret = err;
	err = print_btree(pa->fd, pa->super, "data_avail",
			  &ltv->data_avail.root, print_alloc_item, NULL);
	if (err && !ret)
		ret = err;
	err = print_btree(pa->fd, pa->super, "data_freed",
			  &ltv->data_freed.root, print_alloc_item, NULL);
	if (err && !ret)
		ret = err;
	err = print_srch_block(pa->fd, &ltv->srch_file.ref,
			       ltv->srch_file.height - 1);
	if (err && !ret)
		ret = err;

	err = print_btree(pa->fd, pa->super, "", &ltv->item_root,
			  print_logs_item, NULL);
	if (err && !ret)
		ret = err;

	return ret;
}

static int print_srch_root_files(struct scoutfs_key *key, void *val,
				 unsigned val_len, void *arg)
{
	struct print_recursion_args *pa = arg;
	struct scoutfs_srch_compact *sc;
	struct scoutfs_srch_file *sfl;
	int ret = 0;
	int i;

	if (key->sk_type == SCOUTFS_SRCH_PENDING_TYPE ||
	    key->sk_type == SCOUTFS_SRCH_BUSY_TYPE) {
		sc = val;
		for (i = 0; i < sc->nr; i++) {
			sfl = &sc->in[i].sfl;
			ret = print_srch_block(pa->fd, &sfl->ref,
					       sfl->height - 1);
			if (ret < 0)
				break;
		}

	} else {
		sfl = val;
		ret = print_srch_block(pa->fd, &sfl->ref, sfl->height - 1);
	}

	return ret;
}

static int print_btree_leaf_items(int fd, struct scoutfs_super_block *super,
				  struct scoutfs_btree_ref *ref,
				  print_item_func func, void *arg)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_avl_node *node;
	struct scoutfs_btree_block *bt;
	unsigned val_len;
	void *key;
	void *val;
	int ret;

	if (ref->blkno == 0)
		return 0;

	bt = read_block(fd, le64_to_cpu(ref->blkno), SCOUTFS_BLOCK_LG_SHIFT);
	if (!bt)
		return -ENOMEM;

	node = avl_first(&bt->item_root);
	while (node) {
		item = container_of(node, struct scoutfs_btree_item, node);
		val_len = le16_to_cpu(item->val_len);
		key = &item->key;
		val = (void *)bt + le16_to_cpu(item->val_off);

		if (bt->level > 0) {
			ret = print_btree_leaf_items(fd, super, val, func, arg);
			if (ret)
				break;
			continue;
		} else {
			func(key, val, val_len, arg);
		}

		node = avl_next(&bt->item_root, node);
	}

	free(bt);
	return 0;
}

static char *alloc_addr_str(struct scoutfs_inet_addr *ia)
{
	struct in_addr addr;
	char *quad;
	char *str;
	int len;

	memset(&addr, 0, sizeof(addr));
	addr.s_addr = htonl(le32_to_cpu(ia->addr));
	quad = inet_ntoa(addr);
	if (quad == NULL)
		return NULL;

	len = snprintf(NULL, 0, "%s:%u", quad, le16_to_cpu(ia->port));
	if (len < 1 || len > 22)
		return NULL;

	len++; /* null */
	str = malloc(len);
	if (!str)
		return NULL;

	snprintf(str, len, "%s:%u", quad, le16_to_cpu(ia->port));
	return str;
}

static int print_quorum_blocks(int fd, struct scoutfs_super_block *super)
{
	struct scoutfs_quorum_block *blk = NULL;
	char *log_addr = NULL;
	u64 blkno;
	int ret;
	int i;
	int j;

	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		blkno = SCOUTFS_QUORUM_BLKNO + i;
		free(blk);
		blk = read_block(fd, blkno, SCOUTFS_BLOCK_SM_SHIFT);
		if (!blk) {
			ret = -ENOMEM;
			goto out;
		}

		if (blk->voter_rid != 0) {
			printf("quorum block blkno %llu\n"
			       "  fsid %llx blkno %llu crc 0x%08x\n"
			       "  term %llu write_nr %llu voter_rid %016llx "
			       "vote_for_rid %016llx\n"
			       "  log_nr %u\n",
			       blkno, le64_to_cpu(blk->fsid),
			       le64_to_cpu(blk->blkno), le32_to_cpu(blk->crc),
			       le64_to_cpu(blk->term),
			       le64_to_cpu(blk->write_nr),
			       le64_to_cpu(blk->voter_rid),
			       le64_to_cpu(blk->vote_for_rid),
			       blk->log_nr);
			for (j = 0; j < blk->log_nr; j++) {
				free(log_addr);
				log_addr = alloc_addr_str(&blk->log[j].addr);
				if (!log_addr) {
					ret = -ENOMEM;
					goto out;
				}
				printf("  [%u]: term %llu rid %llu addr %s\n",
					j, le64_to_cpu(blk->log[j].term),
					le64_to_cpu(blk->log[j].rid),
					log_addr);
			}
		}
	}

	ret = 0;
out:
	free(log_addr);

	return ret;
}

static void print_super_block(struct scoutfs_super_block *super, u64 blkno)
{
	char uuid_str[37];
	char *server_addr;

	uuid_unparse(super->uuid, uuid_str);

	printf("super blkno %llu\n", blkno);
	print_block_header(&super->hdr, SCOUTFS_BLOCK_SM_SIZE);
	printf("  format_hash %llx uuid %s\n",
	       le64_to_cpu(super->format_hash), uuid_str);

	server_addr = alloc_addr_str(&super->server_addr);
	if (!server_addr)
		return;

	/* XXX these are all in a crazy order */
	printf("  next_ino %llu next_trans_seq %llu\n"
	       "  total_meta_blocks %llu first_meta_blkno %llu last_meta_blkno %llu\n"
	       "  total_data_blocks %llu first_data_blkno %llu last_data_blkno %llu\n"
	       "  quorum_fenced_term %llu quorum_server_term %llu unmount_barrier %llu\n"
	       "  quorum_count %u server_addr %s\n"
	       "  meta_alloc[0]: "ALCROOT_F"\n"
	       "  meta_alloc[1]: "ALCROOT_F"\n"
	       "  data_alloc: "ALCROOT_F"\n"
	       "  server_meta_avail[0]: "AL_HEAD_F"\n"
	       "  server_meta_avail[1]: "AL_HEAD_F"\n"
	       "  server_meta_freed[0]: "AL_HEAD_F"\n"
	       "  server_meta_freed[1]: "AL_HEAD_F"\n"
	       "  lock_clients root: height %u blkno %llu seq %llu\n"
	       "  mounted_clients root: height %u blkno %llu seq %llu\n"
	       "  srch_root root: height %u blkno %llu seq %llu\n"
	       "  trans_seqs root: height %u blkno %llu seq %llu\n"
	       "  fs_root btree root: height %u blkno %llu seq %llu\n",
		le64_to_cpu(super->next_ino),
		le64_to_cpu(super->next_trans_seq),
		le64_to_cpu(super->total_meta_blocks),
		le64_to_cpu(super->first_meta_blkno),
		le64_to_cpu(super->last_meta_blkno),
		le64_to_cpu(super->total_data_blocks),
		le64_to_cpu(super->first_data_blkno),
		le64_to_cpu(super->last_data_blkno),
		le64_to_cpu(super->quorum_fenced_term),
		le64_to_cpu(super->quorum_server_term),
		le64_to_cpu(super->unmount_barrier),
		super->quorum_count,
		server_addr,
		ALCROOT_A(&super->meta_alloc[0]),
		ALCROOT_A(&super->meta_alloc[1]),
		ALCROOT_A(&super->data_alloc),
		AL_HEAD_A(&super->server_meta_avail[0]),
		AL_HEAD_A(&super->server_meta_avail[1]),
		AL_HEAD_A(&super->server_meta_freed[0]),
		AL_HEAD_A(&super->server_meta_freed[1]),
		super->lock_clients.height,
		le64_to_cpu(super->lock_clients.ref.blkno),
		le64_to_cpu(super->lock_clients.ref.seq),
		super->mounted_clients.height,
		le64_to_cpu(super->mounted_clients.ref.blkno),
		le64_to_cpu(super->mounted_clients.ref.seq),
		super->srch_root.height,
		le64_to_cpu(super->srch_root.ref.blkno),
		le64_to_cpu(super->srch_root.ref.seq),
		super->trans_seqs.height,
		le64_to_cpu(super->trans_seqs.ref.blkno),
		le64_to_cpu(super->trans_seqs.ref.seq),
		super->fs_root.height,
		le64_to_cpu(super->fs_root.ref.blkno),
		le64_to_cpu(super->fs_root.ref.seq));

	free(server_addr);
}

static int print_volume(int fd)
{
	struct scoutfs_super_block *super = NULL;
	struct print_recursion_args pa;
	char str[80];
	int ret = 0;
	int err;
	int i;

	super = read_block(fd, SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT);
	if (!super)
		return -ENOMEM;

	print_super_block(super, SCOUTFS_SUPER_BLKNO);

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

	for (i = 0; i < array_size(super->server_meta_avail); i++) {
		snprintf(str, sizeof(str), "server_meta_avail[%u]", i);
		err = print_alloc_list_block(fd, str,
					&super->server_meta_avail[i].ref);
		if (err && !ret)
			ret = err;
	}

	for (i = 0; i < array_size(super->server_meta_freed); i++) {
		snprintf(str, sizeof(str), "server_meta_freed[%u]", i);
		err = print_alloc_list_block(fd, str,
					&super->server_meta_freed[i].ref);
		if (err && !ret)
			ret = err;
	}

	for (i = 0; i < array_size(super->meta_alloc); i++) {
		snprintf(str, sizeof(str), "meta_alloc[%u]", i);
		err = print_btree(fd, super, str, &super->meta_alloc[i].root,
				  print_alloc_item, NULL);
		if (err && !ret)
			ret = err;
	}

	err = print_btree(fd, super, "data_alloc", &super->data_alloc.root,
			  print_alloc_item, NULL);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "srch_root", &super->srch_root,
			  print_srch_root_item, NULL);
	if (err && !ret)
		ret = err;
	err = print_btree(fd, super, "logs_root", &super->logs_root,
			  print_log_trees_item, NULL);
	if (err && !ret)
		ret = err;

	pa.super = super;
	pa.fd = fd;
	err = print_btree_leaf_items(fd, super, &super->srch_root.ref,
				     print_srch_root_files, &pa);
	if (err && !ret)
		ret = err;
	err = print_btree_leaf_items(fd, super, &super->logs_root.ref,
				     print_log_trees_roots, &pa);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "fs_root", &super->fs_root,
			  print_fs_item, NULL);
	if (err && !ret)
		ret = err;

	free(super);

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
