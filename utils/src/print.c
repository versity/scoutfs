#define _GNU_SOURCE /* ffsll for glibc < 2.27 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <uuid/uuid.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <argp.h>

#include "sparse.h"
#include "parse.h"
#include "util.h"
#include "format.h"
#include "bitmap.h"
#include "cmd.h"
#include "crc.h"
#include "key.h"
#include "avl.h"
#include "srch.h"
#include "leaf_item_hash.h"
#include "dev.h"

struct print_args {
	char *meta_device;
	bool skip_likely_huge;
	bool roots_requested;
	bool items_requested;
	bool allocs_requested;
	bool walk_allocs;
	bool walk_logs_root;
	bool walk_fs_root;
	bool walk_srch_root;
	bool print_inodes;
	bool print_xattrs;
	bool print_dirents;
	bool print_symlinks;
	bool print_backrefs;
	bool print_extents;
};

static struct print_args print_args = {
	.meta_device	  = NULL,
	.skip_likely_huge = false,
	.roots_requested  = false,
	.items_requested  = false,
	.allocs_requested = false,
	.walk_allocs	  = true,
	.walk_logs_root	  = true,
	.walk_fs_root	  = true,
	.walk_srch_root	  = true,
	.print_inodes	  = true,
	.print_xattrs	  = true,
	.print_dirents	  = true,
	.print_symlinks	  = true,
	.print_backrefs	  = true,
	.print_extents	  = true
};

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

	printf("    inode: ino %llu size %llu version %llu proj %llu nlink %u\n"
	       "      uid %u gid %u mode 0%o rdev 0x%x flags 0x%x\n"
	       "      next_readdir_pos %llu meta_seq %llu data_seq %llu data_version %llu\n"
	       "      atime %llu.%08u ctime %llu.%08u\n"
	       "      mtime %llu.%08u\n",
	       le64_to_cpu(key->ski_ino),
	       le64_to_cpu(inode->size),
	       le64_to_cpu(inode->version),
	       le64_to_cpu(inode->proj),
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


#define SQR_FMT "[%u %llu,%u,%x %llu,%u,%x %llu,%u,%x %u %llu %x]"

#define SQR_ARGS(r)								\
	(r)->prio,								\
	le64_to_cpu((r)->name_val[0]), (r)->name_source[0], (r)->name_flags[0],	\
	le64_to_cpu((r)->name_val[1]), (r)->name_source[1], (r)->name_flags[1],	\
	le64_to_cpu((r)->name_val[2]), (r)->name_source[2], (r)->name_flags[2],	\
	(r)->op, le64_to_cpu((r)->limit), (r)->rule_flags

static void print_quota(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_quota_rule_val *rv = val;

	printf("    quota rule: hash 0x%016llx coll_nr %llu\n"
	       "      "SQR_FMT"\n",
	       le64_to_cpu(key->skqr_hash), le64_to_cpu(key->skqr_coll_nr), SQR_ARGS(rv));
}

static void print_xattr_totl(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_xattr_totl_val *tval = val;

	printf("    xattr totl: %llu.%llu.%llu = %lld, %lld\n",
	       le64_to_cpu(key->skxt_a), le64_to_cpu(key->skxt_b),
	       le64_to_cpu(key->skxt_c), le64_to_cpu(tval->total),
	       le64_to_cpu(tval->count));
}

static void print_xattr_indx(struct scoutfs_key *key, void *val, int val_len)
{
	u64 minor;
	u64 ino;
	u64 xid;
	u8 major;

	scoutfs_xattr_get_indx_key(key, &major, &minor, &ino, &xid);
	printf("    xattr indx: major %u minor %llu ino %llu xid %llu", major, minor, ino, xid);
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

static print_func_t find_printer(u8 zone, u8 type, bool *suppress)
{
	if (zone == SCOUTFS_INODE_INDEX_ZONE &&
	    type >= SCOUTFS_INODE_INDEX_META_SEQ_TYPE  &&
	    type <= SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE)
		return print_inode_index;

	if (zone == SCOUTFS_ORPHAN_ZONE) {
		if (type == SCOUTFS_ORPHAN_TYPE)
			return print_orphan;
	}

	if (zone == SCOUTFS_QUOTA_ZONE)
		return print_quota;

	if (zone == SCOUTFS_XATTR_TOTL_ZONE)
		return print_xattr_totl;

	if (zone == SCOUTFS_XATTR_INDX_ZONE)
		return print_xattr_indx;

	if (zone == SCOUTFS_FS_ZONE) {
		switch(type) {
			case SCOUTFS_INODE_TYPE:
				if (!print_args.print_inodes)
					*suppress = true;
				return print_inode;
			case SCOUTFS_XATTR_TYPE:
				if (!print_args.print_xattrs)
					*suppress = true;
				return print_xattr;
			case SCOUTFS_DIRENT_TYPE:
				if (!print_args.print_dirents)
					*suppress = true;
				return print_dirent;
			case SCOUTFS_READDIR_TYPE:
				if (!print_args.print_dirents)
					*suppress = true;
				return print_dirent;
			case SCOUTFS_SYMLINK_TYPE:
				if (!print_args.print_symlinks)
					*suppress = true;
				return print_symlink;
			case SCOUTFS_LINK_BACKREF_TYPE:
				if (!print_args.print_backrefs)
					*suppress = true;
				return print_dirent;
			case SCOUTFS_DATA_EXTENT_TYPE:
				if (!print_args.print_extents)
					*suppress = true;
				return print_data_extent;
		}
	}

	return NULL;
}

#define flag_char(val, bit, c) \
	(((val) & (bit)) ? (c) : '-')

static int print_fs_item(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
			 unsigned val_len, void *arg)
{
	print_func_t printer;

	printf("    "SK_FMT" %llu %c\n",
	       SK_ARG(key), seq, flag_char(flags, SCOUTFS_ITEM_FLAG_DELETION, 'd'));

	/* only items in leaf blocks have values */
	if (val != NULL && !(flags & SCOUTFS_ITEM_FLAG_DELETION)) {
		bool suppress = false;

		printer = find_printer(key->sk_zone, key->sk_type, &suppress);
		if (printer) {
			if (!suppress)
				printer(key, val, val_len);
		} else {
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
	AL_REF_F" total_nr %llu first_nr %u flags 0x%x"
#define AL_HEAD_A(p)					\
	AL_REF_A(&(p)->ref), le64_to_cpu((p)->total_nr),\
	le32_to_cpu((p)->first_nr), le32_to_cpu((p)->flags)

#define ALCROOT_F \
	BTROOT_F" total_len %llu flags 0x%x"
#define ALCROOT_A(ar) \
	BTROOT_A(&(ar)->root), le64_to_cpu((ar)->total_len), le32_to_cpu((ar)->flags)

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
static int print_log_trees_item(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
				unsigned val_len, void *arg)
{
	struct scoutfs_log_trees *lt = val;
	u64 zones;
	int bit;
	int i;

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
		       "      srch_file: "SRF_FMT"\n"
		       "      inode_count_delta: %lld\n"
		       "      get_trans_seq: %lld\n"
		       "      commit_trans_seq: %lld\n"
		       "      max_item_seq: %llu\n"
		       "      finalize_seq: %llu\n"
		       "      rid: %016llx\n"
		       "      nr: %llu\n"
		       "      flags: %llx\n"
		       "      data_alloc_zone_blocks: %llu\n"
		       "      data_alloc_zones: ",
		       AL_HEAD_A(&lt->meta_avail),
		       AL_HEAD_A(&lt->meta_freed),
			lt->item_root.height,
			le64_to_cpu(lt->item_root.ref.blkno),
			le64_to_cpu(lt->item_root.ref.seq),
			le64_to_cpu(lt->bloom_ref.blkno),
			le64_to_cpu(lt->bloom_ref.seq),
		       ALCROOT_A(&lt->data_avail),
		       ALCROOT_A(&lt->data_freed),
		       SRF_A(&lt->srch_file),
		       le64_to_cpu(lt->inode_count_delta),
		       le64_to_cpu(lt->get_trans_seq),
		       le64_to_cpu(lt->commit_trans_seq),
		       le64_to_cpu(lt->max_item_seq),
		       le64_to_cpu(lt->finalize_seq),
		       le64_to_cpu(lt->rid),
		       le64_to_cpu(lt->nr),
		       le64_to_cpu(lt->flags),
		       le64_to_cpu(lt->data_alloc_zone_blocks));

		for (i = 0; i < SCOUTFS_DATA_ALLOC_ZONE_LE64S; i++) {
			if (lt->data_alloc_zones[i] == 0)
				continue;

			zones = le64_to_cpu(lt->data_alloc_zones[i]);
			while (zones) {
				bit = ffsll(zones) - 1;
				printf("%u ", (i * 64) + bit);
				zones ^= (1ULL << bit);
			}
		}
		printf("\n");
	}

	return 0;
}

static int print_srch_root_item(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
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

static int print_mounted_client_entry(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
				      unsigned val_len, void *arg)
{
	struct scoutfs_mounted_client_btree_val *mcv = val;
	struct in_addr in;

	memset(&in, 0, sizeof(in));
	in.s_addr = htonl(le32_to_cpu(mcv->addr.v4.addr));

	printf("    rid %016llx ipv4_addr %s flags 0x%x\n",
	       le64_to_cpu(key->skmc_rid), inet_ntoa(in), mcv->flags);

	return 0;
}

static int print_log_merge_item(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
				unsigned val_len, void *arg)
{
	struct scoutfs_log_merge_status *stat;
	struct scoutfs_log_merge_range *rng;
	struct scoutfs_log_merge_request *req;
	struct scoutfs_log_merge_complete *comp;
	struct scoutfs_log_merge_freeing *fr;

	switch (key->sk_zone) {
	case SCOUTFS_LOG_MERGE_STATUS_ZONE:
		stat = val;
		printf("    status: next_range_key "SK_FMT" nr_req %llu nr_comp %llu seq %llu\n",
		       SK_ARG(&stat->next_range_key),
		       le64_to_cpu(stat->nr_requests),
		       le64_to_cpu(stat->nr_complete),
		       le64_to_cpu(stat->seq));
		break;
	case SCOUTFS_LOG_MERGE_RANGE_ZONE:
		rng = val;
		printf("    range: start "SK_FMT" end "SK_FMT"\n",
		       SK_ARG(&rng->start),
		       SK_ARG(&rng->end));
		break;
	case SCOUTFS_LOG_MERGE_REQUEST_ZONE:
		req = val;
		printf("    request: logs_root "BTROOT_F" logs_root "BTROOT_F" start "SK_FMT
		       " end "SK_FMT" input_seq %llu rid %016llx seq %llu flags 0x%llx\n",
		       BTROOT_A(&req->logs_root),
		       BTROOT_A(&req->root),
		       SK_ARG(&req->start),
		       SK_ARG(&req->end),
		       le64_to_cpu(req->input_seq),
		       le64_to_cpu(req->rid),
		       le64_to_cpu(req->seq),
		       le64_to_cpu(req->flags));
		break;
	case SCOUTFS_LOG_MERGE_COMPLETE_ZONE:
		comp = val;
		printf("    complete: root "BTROOT_F" start "SK_FMT" end "SK_FMT
		       " remain "SK_FMT" rid %016llx seq %llu flags %llx\n",
		       BTROOT_A(&comp->root),
		       SK_ARG(&comp->start),
		       SK_ARG(&comp->end),
		       SK_ARG(&comp->remain),
		       le64_to_cpu(comp->rid),
		       le64_to_cpu(comp->seq),
		       le64_to_cpu(comp->flags));
		break;
	case SCOUTFS_LOG_MERGE_FREEING_ZONE:
		fr = val;
		printf("    freeing: root "BTROOT_F" key "SK_FMT" seq %llu\n",
		       BTROOT_A(&fr->root),
		       SK_ARG(&fr->key),
		       le64_to_cpu(fr->seq));
		break;
	default:
		printf("    (unknown log merge key zone %u)\n", key->sk_zone);
		break;
	}

	return 0;
}

static int print_alloc_item(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
			    unsigned val_len, void *arg)
{
	if (key->sk_zone == SCOUTFS_FREE_EXTENT_BLKNO_ZONE)
		printf("    free extent: blkno %llu len %llu end %llu\n",
		       le64_to_cpu(key->skfb_end) -
		       le64_to_cpu(key->skfb_len) + 1,
		       le64_to_cpu(key->skfb_len),
		       le64_to_cpu(key->skfb_end));
	else
		printf("    free extent: blkno %llu len %llu order %llu\n",
		       le64_to_cpu(key->skfo_end) - le64_to_cpu(key->skfo_len) + 1,
		       le64_to_cpu(key->skfo_len),
		       (long long)(U64_MAX - le64_to_cpu(key->skfo_revord)));

	return 0;
}

typedef int (*print_item_func)(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
			       unsigned val_len, void *arg);

static int print_block_ref(struct scoutfs_key *key, void *val,
			   unsigned val_len, print_item_func func, void *arg)
{
	struct scoutfs_block_ref *ref = val;

	func(key, 0, 0, NULL, 0, arg);
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
			     char *which, struct scoutfs_block_ref *ref,
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

	ret = read_block(fd, le64_to_cpu(ref->blkno), SCOUTFS_BLOCK_LG_SHIFT, (void **)&bt);
	if (ret)
		return ret;

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
			print_block_ref(key, val, val_len, func, arg);
		else
			func(key, le64_to_cpu(item->seq), item->flags, val, val_len, arg);
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

static int print_alloc_list_block(int fd, char *str, struct scoutfs_block_ref *ref)
{
	struct scoutfs_alloc_list_block *lblk;
	struct scoutfs_block_ref next;
	u64 blkno;
	u64 start;
	u64 len;
	u64 st;
	u64 nr;
	int wid;
	int ret;
	int i;

	blkno = le64_to_cpu(ref->blkno);
	if (blkno == 0)
		return 0;

	ret = read_block(fd, blkno, SCOUTFS_BLOCK_LG_SHIFT, (void **)&lblk);
	if (ret)
		return ret;

	printf("%s alloc_list_block blkno %llu\n", str, blkno);
	print_block_header(&lblk->hdr, SCOUTFS_BLOCK_LG_SIZE);
	printf("  next "AL_REF_F" start %u nr %u\n",
	       AL_REF_A(&lblk->next), le32_to_cpu(lblk->start),
	       le32_to_cpu(lblk->nr));

	st = le32_to_cpu(lblk->start);
	nr = le32_to_cpu(lblk->nr);
	if (st >= SCOUTFS_ALLOC_LIST_MAX_BLOCKS ||
	    nr > SCOUTFS_ALLOC_LIST_MAX_BLOCKS ||
	    (st + nr) > SCOUTFS_ALLOC_LIST_MAX_BLOCKS) {
		printf("  (invalid start and nr fields)\n");
		goto out;
	}

	if (lblk->nr == 0)
		goto out;

	wid = printf("  exts: ");
	start = 0;
	len = 0;
	for (i = 0; i < nr; i++) {
		if (len == 0)
			start = le64_to_cpu(lblk->blknos[st + i]);
		len++;

		if (i == (nr - 1) || (start + len) != le64_to_cpu(lblk->blknos[st + i + 1])) {
			if (wid >= 72)
				wid = printf("\n        ");

			wid += printf("%llu,%llu ", start, len);
			len = 0;
		}
	}
	printf("\n");

out:
	next = lblk->next;
	free(lblk);
	return print_alloc_list_block(fd, str, &next);
}

static int print_srch_block(int fd, struct scoutfs_block_ref *ref, int level)
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

	ret = read_block(fd, blkno, SCOUTFS_BLOCK_LG_SHIFT, (void **)&srp);
	if (ret)
		goto out;

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
};

/* same as fs item but with a small header in the value */
static int print_log_trees_roots(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
				 unsigned val_len, void *arg)
{
	struct scoutfs_log_trees *lt = val;
	struct print_recursion_args *pa = arg;
	int ret = 0;
	int err;

	/* XXX doesn't print the bloom block */

	err = print_alloc_list_block(pa->fd, "lt_meta_avail",
				     &lt->meta_avail.ref);
	if (err && !ret)
		ret = err;
	err = print_alloc_list_block(pa->fd, "lt_meta_freed",
				     &lt->meta_freed.ref);
	if (err && !ret)
		ret = err;
	err = print_btree(pa->fd, pa->super, "data_avail",
			  &lt->data_avail.root, print_alloc_item, NULL);
	if (err && !ret)
		ret = err;
	err = print_btree(pa->fd, pa->super, "data_freed",
			  &lt->data_freed.root, print_alloc_item, NULL);
	if (err && !ret)
		ret = err;
	err = print_srch_block(pa->fd, &lt->srch_file.ref,
			       lt->srch_file.height - 1);
	if (err && !ret)
		ret = err;

	err = print_btree(pa->fd, pa->super, "", &lt->item_root,
			  print_fs_item, NULL);
	if (err && !ret)
		ret = err;

	return ret;
}

static int print_srch_root_files(struct scoutfs_key *key, u64 seq, u8 flags, void *val,
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
				  struct scoutfs_block_ref *ref,
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

	ret = read_block(fd, le64_to_cpu(ref->blkno), SCOUTFS_BLOCK_LG_SHIFT, (void **)&bt);
	if (ret)
		return ret;

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
			func(key, le64_to_cpu(item->seq), item->flags, val, val_len, arg);
		}

		node = avl_next(&bt->item_root, node);
	}

	free(bt);
	return 0;
}

static char *alloc_addr_str(union scoutfs_inet_addr *ia)
{
	struct in_addr addr;
	char *quad;
	char *str;
	int len;

	memset(&addr, 0, sizeof(addr));
	addr.s_addr = htonl(le32_to_cpu(ia->v4.addr));
	quad = inet_ntoa(addr);
	if (quad == NULL)
		return NULL;

	len = snprintf(NULL, 0, "%s:%u", quad, le16_to_cpu(ia->v4.port));
	if (len < 1 || len > 22)
		return NULL;

	len++; /* null */
	str = malloc(len);
	if (!str)
		return NULL;

	snprintf(str, len, "%s:%u", quad, le16_to_cpu(ia->v4.port));
	return str;
}

#define OFF_NAME(x) \
	{ offsetof(struct scoutfs_quorum_block, x), __stringify_1(x) }

static int print_quorum_blocks(int fd, struct scoutfs_super_block *super)
{
	const static char *event_names[] = {
		[SCOUTFS_QUORUM_EVENT_BEGIN] = "begin",
		[SCOUTFS_QUORUM_EVENT_TERM] = "term",
		[SCOUTFS_QUORUM_EVENT_ELECT] = "elect",
		[SCOUTFS_QUORUM_EVENT_FENCE] = "fence",
		[SCOUTFS_QUORUM_EVENT_STOP] = "stop",
		[SCOUTFS_QUORUM_EVENT_END] = "end",
	};
	struct scoutfs_quorum_block *blk = NULL;
	struct scoutfs_quorum_block_event *ev;
	u64 blkno;
	int ret;
	int i;
	int e;

	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		blkno = SCOUTFS_QUORUM_BLKNO + i;
		free(blk);
		blk = NULL;
		ret = read_block(fd, blkno, SCOUTFS_BLOCK_SM_SHIFT, (void **)&blk);
		if (ret)
			goto out;

		printf("quorum blkno %llu (slot %llu)\n",
		       blkno, blkno - SCOUTFS_QUORUM_BLKNO);
		print_block_header(&blk->hdr, SCOUTFS_BLOCK_SM_SIZE);
		printf("  write_nr %llu\n", le64_to_cpu(blk->write_nr));

		for (e = 0; e < array_size(event_names); e++) {
			ev = &blk->events[e];

			printf("  %12s: rid %016llx term %llu write_nr %llu ts %llu.%08u\n",
			       event_names[e], le64_to_cpu(ev->rid), le64_to_cpu(ev->term),
			       le64_to_cpu(ev->write_nr), le64_to_cpu(ev->ts.sec),
			       le32_to_cpu(ev->ts.nsec));
		}
	}

	ret = 0;
out:
	free(blk);

	return ret;
}

#define BTR_FMT "blkno %llu seq %016llx height %u"
#define BTR_ARG(rt) \
	le64_to_cpu((rt)->ref.blkno), le64_to_cpu((rt)->ref.seq), (rt)->height

static void print_super_block(struct scoutfs_super_block *super, u64 blkno)
{
	char uuid_str[37];
	char *addr;
	int i;

	uuid_unparse(super->uuid, uuid_str);

	printf("super blkno %llu\n", blkno);
	print_block_header(&super->hdr, SCOUTFS_BLOCK_SM_SIZE);
	printf("  fmt_vers %llu uuid %s\n",
	       le64_to_cpu(super->fmt_vers), uuid_str);
	printf("  flags: 0x%016llx\n", le64_to_cpu(super->flags));

	/* XXX these are all in a crazy order */
	printf("  next_ino %llu inode_count %llu seq %llu\n"
	       "  total_meta_blocks %llu total_data_blocks %llu\n"
	       "  meta_alloc[0]: "ALCROOT_F"\n"
	       "  meta_alloc[1]: "ALCROOT_F"\n"
	       "  data_alloc: "ALCROOT_F"\n"
	       "  server_meta_avail[0]: "AL_HEAD_F"\n"
	       "  server_meta_avail[1]: "AL_HEAD_F"\n"
	       "  server_meta_freed[0]: "AL_HEAD_F"\n"
	       "  server_meta_freed[1]: "AL_HEAD_F"\n"
	       "  fs_root: "BTR_FMT"\n"
	       "  logs_root: "BTR_FMT"\n"
	       "  log_merge: "BTR_FMT"\n"
	       "  mounted_clients: "BTR_FMT"\n"
	       "  srch_root: "BTR_FMT"\n",
		le64_to_cpu(super->next_ino),
		le64_to_cpu(super->inode_count),
		le64_to_cpu(super->seq),
		le64_to_cpu(super->total_meta_blocks),
		le64_to_cpu(super->total_data_blocks),
		ALCROOT_A(&super->meta_alloc[0]),
		ALCROOT_A(&super->meta_alloc[1]),
		ALCROOT_A(&super->data_alloc),
		AL_HEAD_A(&super->server_meta_avail[0]),
		AL_HEAD_A(&super->server_meta_avail[1]),
		AL_HEAD_A(&super->server_meta_freed[0]),
		AL_HEAD_A(&super->server_meta_freed[1]),
		BTR_ARG(&super->fs_root),
		BTR_ARG(&super->logs_root),
		BTR_ARG(&super->log_merge),
		BTR_ARG(&super->mounted_clients),
		BTR_ARG(&super->srch_root));

	printf("  volume options:\n"
	       "    set_bits: %016llx\n",
		le64_to_cpu(super->volopt.set_bits));
	if (le64_to_cpu(super->volopt.set_bits) & SCOUTFS_VOLOPT_DATA_ALLOC_ZONE_BLOCKS_BIT) {
		printf("    data_alloc_zone_blocks: %llu\n",
			le64_to_cpu(super->volopt.data_alloc_zone_blocks));
	}

	printf("  quorum config version %llu\n",
		le64_to_cpu(super->qconf.version));
	for (i = 0; i < array_size(super->qconf.slots); i++) {
		if (super->qconf.slots[i].addr.v4.family != cpu_to_le16(SCOUTFS_AF_IPV4))
			continue;

		addr = alloc_addr_str(&super->qconf.slots[i].addr);
		if (addr) {
			printf("    quorum slot %2u: %s\n", i, addr);
			free(addr);
		}
	}
}

static int print_volume(int fd)
{
	struct scoutfs_super_block *super = NULL;
	struct print_recursion_args pa;
	char str[80];
	int ret = 0;
	int err;
	int i;

	ret = read_block(fd, SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT, (void **)&super);
	if (ret)
		return ret;

	print_super_block(super, SCOUTFS_SUPER_BLKNO);

	if (!(le64_to_cpu(super->flags) & SCOUTFS_FLAG_IS_META_BDEV)) {
		fprintf(stderr,
			"**** Printing from data device is not allowed ****\n");
		ret = -EINVAL;
		goto out;
	}

	ret = print_quorum_blocks(fd, super);

	err = print_btree(fd, super, "mounted_clients", &super->mounted_clients,
			  print_mounted_client_entry, NULL);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "log_merge", &super->log_merge,
			  print_log_merge_item, NULL);
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

	if (print_args.walk_allocs) {
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
	}

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
	if (print_args.walk_srch_root) {
		err = print_btree_leaf_items(fd, super, &super->srch_root.ref,
					     print_srch_root_files, &pa);
		if (err && !ret)
			ret = err;
	}

	if (print_args.walk_logs_root) {
		err = print_btree_leaf_items(fd, super, &super->logs_root.ref,
					     print_log_trees_roots, &pa);
		if (err && !ret)
			ret = err;
	}

	if (print_args.walk_fs_root) {
		err = print_btree(fd, super, "fs_root", &super->fs_root,
				  print_fs_item, NULL);
		if (err && !ret)
			ret = err;
	}

out:
	free(super);

	return ret;
}

static int do_print(void)
{
	int ret;
	int fd;

	fd = open(print_args.meta_device, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			print_args.meta_device, strerror(errno), errno);
		return ret;
	}

	ret = flush_device(fd);
	if (ret < 0)
		goto out;

	ret = print_volume(fd);
out:
	close(fd);
	return ret;
};

enum {
	LOGS_OPT = 0,
	FS_OPT,
	SRCH_OPT
};

static char *const root_tokens[] = {
	[LOGS_OPT] = "logs",
	[FS_OPT] =   "fs",
	[SRCH_OPT] = "srch",
	NULL
};

enum {
	INODE_OPT = 0,
	XATTR_OPT,
	DIRENT_OPT,
	SYMLINK_OPT,
	BACKREF_OPT,
	EXTENT_OPT
};

static char *const item_tokens[] = {
	[INODE_OPT] =   "inode",
	[XATTR_OPT] =   "xattr",
	[DIRENT_OPT] =  "dirent",
	[SYMLINK_OPT] = "symlink",
	[BACKREF_OPT] = "backref",
	[EXTENT_OPT] =  "extent",
	NULL
};

static void clear_items(void)
{
	print_args.print_inodes = false;
	print_args.print_xattrs = false;
	print_args.print_dirents = false;
	print_args.print_symlinks = false;
	print_args.print_backrefs = false;
	print_args.print_extents = false;
}

static void clear_roots(void)
{
	print_args.walk_logs_root = false;
	print_args.walk_fs_root = false;
	print_args.walk_srch_root = false;
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	struct print_args *args = state->input;
	char *subopts;
	char *value;
	bool parse_err = false;

	switch (key) {
	case 'S':
		args->skip_likely_huge = true;
		break;

	case 'a':
		args->allocs_requested = true;
		args->walk_allocs = true;
		break;

	case 'i':
		/* Specific items being requested- clear them all to start */
		if (!args->items_requested) {
			clear_items();
			if (!args->allocs_requested)
				args->walk_allocs = false;
			args->items_requested = true;
		}

		subopts = arg;
		while (*subopts != '\0' && !parse_err) {
			switch (getsubopt(&subopts, item_tokens, &value)) {
			case INODE_OPT:
				args->print_inodes = true;
				break;
			case XATTR_OPT:
				args->print_xattrs = true;
				break;
			case DIRENT_OPT:
				args->print_dirents = true;
				break;
			case SYMLINK_OPT:
				args->print_symlinks = true;
				break;
			case BACKREF_OPT:
				args->print_backrefs = true;
				break;
			case EXTENT_OPT:
				args->print_extents = true;
				break;
			default:
				argp_usage(state);
				parse_err = true;
				break;
			}
		}
		break;

	case 'r':
		/* Specific roots being requested- clear them all to start */
		if (!args->roots_requested) {
			clear_roots();
			if (!args->allocs_requested)
				args->walk_allocs = false;
			args->roots_requested = true;
		}

		subopts = arg;
		while (*subopts != '\0' && !parse_err) {
			switch (getsubopt(&subopts, root_tokens, &value)) {
			case LOGS_OPT:
				args->walk_logs_root = true;
				break;
			case FS_OPT:
				args->walk_fs_root = true;
				break;
			case SRCH_OPT:
				args->walk_srch_root = true;
				break;
			default:
				argp_usage(state);
				parse_err = true;
				break;
			}
		}
		break;

	case ARGP_KEY_ARG:
		if (!args->meta_device)
			args->meta_device = strdup_or_error(state, arg);
		else
			argp_error(state, "more than one argument given");
		break;

	case ARGP_KEY_FINI:
		if (!args->meta_device)
			argp_error(state, "no metadata device argument given");

		/*
		 * For backwards compatibility, translate -S. Should we warn if
		 * this conflicts with other explicit options?
		 */
		if (args->skip_likely_huge) {
			if (!args->allocs_requested)
				args->walk_allocs = false;
			args->walk_fs_root = false;
			args->walk_srch_root = false;
		}

		break;

	default:
		break;
	}

	return 0;
}

static struct argp_option options[] = {
	{ "allocs", 'a', NULL, 0, "Print metadata and data alloc lists" },
	{ "items", 'i', "ITEMS", 0, "Item(s) to print (inode, xattr, dirent, symlink, backref, extent)" },
	{ "roots", 'r', "ROOTS", 0, "Tree root(s) to walk (logs, srch, fs)" },
	{ "skip-likely-huge", 'S', NULL, 0, "Skip allocs, srch root and fs root to minimize output size" },
	{ NULL }
};

static struct argp argp = {
	options,
	parse_opt,
	"META-DEV",
	"Print metadata structures"
};

static int print_cmd(int argc, char **argv)
{
	int ret;

	ret = argp_parse(&argp, argc, argv, 0, NULL, &print_args);
	if (ret)
		return ret;

	return do_print();
}

static void __attribute__((constructor)) print_ctor(void)
{
	cmd_register_argp("print", &argp, GROUP_DEBUG, print_cmd);
}
