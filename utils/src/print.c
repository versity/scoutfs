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
#include "radix.h"

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

static void print_packed_extent(struct scoutfs_key *key, void *val, int val_len)
{
	struct scoutfs_packed_extent *pe = val;

	printf("      packed_extent: ino %llu base %llu part %u count %u diff_bytes %u flags 0x%x final %u\n",
	       le64_to_cpu(key->skpe_ino), le64_to_cpu(key->skpe_base),
	       key->skpe_part, le16_to_cpu(pe->count), pe->diff_bytes,
	       pe->flags, pe->final);
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
			case SCOUTFS_PACKED_EXTENT_TYPE:
				return print_packed_extent;
		}
	}

	return NULL;
}

static int print_fs_item(void *key, unsigned key_len, void *val,
			 unsigned val_len, void *arg)
{
	struct scoutfs_key item_key;
	print_func_t printer;

	scoutfs_key_from_be(&item_key, key);

	printf("    "SK_FMT"\n", SK_ARG(&item_key));

	/* only items in leaf blocks have values */
	if (val) {
		printer = find_printer(item_key.sk_zone, item_key.sk_type);
		if (printer)
			printer(&item_key, val, val_len);
		else
			printf("      (unknown zone %u type %u)\n",
			       item_key.sk_zone, item_key.sk_type);
	}

	return 0;
}

/* same as fs item but with a small header in the value */
static int print_logs_item(void *key, unsigned key_len, void *val,
			   unsigned val_len, void *arg)
{
	struct scoutfs_key item_key;
	struct scoutfs_log_item_value *liv;
	print_func_t printer;

	scoutfs_key_from_be(&item_key, key);

	printf("    "SK_FMT"\n", SK_ARG(&item_key));

	/* only items in leaf blocks have values */
	if (val) {
		liv = val;
		printf("    log_item_value: vers %llu flags %x\n",
		       le64_to_cpu(liv->vers), liv->flags);

		/* deletion items don't have values */
		if (!(liv->flags & SCOUTFS_LOG_ITEM_FLAG_DELETION)) {
			printer = find_printer(item_key.sk_zone,
					       item_key.sk_type);
			if (printer)
				printer(&item_key, val + sizeof(*liv),
					val_len - sizeof(*liv));
			else
				printf("      (unknown zone %u type %u)\n",
				       item_key.sk_zone, item_key.sk_type);
		}
	}

	return 0;
}

#define RADREF_F \
	"blkno %llu seq %llu sm_total %llu lg_total %llu"
#define RADREF_A(ref) \
	le64_to_cpu((ref)->blkno), le64_to_cpu((ref)->seq), \
	le64_to_cpu((ref)->sm_total), le64_to_cpu((ref)->lg_total)

#define RADROOT_F \
	"height %u next_find_bit %llu ref: "RADREF_F
#define RADROOT_A(root) \
	(root)->height, le64_to_cpu((root)->next_find_bit), \
	RADREF_A(&(root)->ref)

/* same as fs item but with a small header in the value */
static int print_log_trees_item(void *key, unsigned key_len, void *val,
				unsigned val_len, void *arg)
{
	struct scoutfs_log_trees_key *ltk = key;
	struct scoutfs_log_trees_val *ltv = val;

	printf("    rid %llu nr %llu\n",
	       be64_to_cpu(ltk->rid), be64_to_cpu(ltk->nr));

	/* only items in leaf blocks have values */
	if (val) {
		printf("      meta_avail: "RADROOT_F"\n"
		       "      meta_freed: "RADROOT_F"\n"
		       "      item_root: height %u blkno %llu seq %llu\n"
		       "      bloom_ref: blkno %llu seq %llu\n"
		       "      data_avail: "RADROOT_F"\n"
		       "      data_freed: "RADROOT_F"\n",
		       RADROOT_A(&ltv->meta_avail),
		       RADROOT_A(&ltv->meta_freed),
			ltv->item_root.height,
			le64_to_cpu(ltv->item_root.ref.blkno),
			le64_to_cpu(ltv->item_root.ref.seq),
			le64_to_cpu(ltv->bloom_ref.blkno),
			le64_to_cpu(ltv->bloom_ref.seq),
		       RADROOT_A(&ltv->data_avail),
		       RADROOT_A(&ltv->data_freed));
	}

	return 0;
}

static int print_lock_clients_entry(void *key, unsigned key_len, void *val,
				    unsigned val_len, void *arg)
{
	struct scoutfs_lock_client_btree_key *cbk = key;

	printf("    rid %016llx\n", be64_to_cpu(cbk->rid));

	return 0;
}

static int print_trans_seqs_entry(void *key, unsigned key_len, void *val,
				  unsigned val_len, void *arg)
{
	struct scoutfs_trans_seq_btree_key *tsk = key;

	printf("    trans_seq %llu rid %016llx\n",
	       be64_to_cpu(tsk->trans_seq), be64_to_cpu(tsk->rid));

	return 0;
}

static int print_mounted_client_entry(void *key, unsigned key_len, void *val,
				      unsigned val_len, void *arg)
{
	struct scoutfs_mounted_client_btree_key *mck = key;
	struct scoutfs_mounted_client_btree_val *mcv = val;

	printf("    rid %016llx flags 0x%x\n",
			be64_to_cpu(mck->rid), mcv->flags);

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
		       "  level %u free_end %u nr_items %u\n",
		       which, le64_to_cpu(ref->blkno),
		       le32_to_cpu(bt->hdr.crc),
		       le64_to_cpu(bt->hdr.fsid),
		       le64_to_cpu(bt->hdr.seq),
		       le64_to_cpu(bt->hdr.blkno),
		       bt->level,
		       le32_to_cpu(bt->free_end),
		       le32_to_cpu(bt->nr_items));
	}

	for (i = 0; i < le32_to_cpu(bt->nr_items); i++) {
		item = (void *)bt + le32_to_cpu(bt->item_hdrs[i].off);
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
			i, le32_to_cpu(bt->item_hdrs[i].off), key_len, val_len);

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

static int print_radix_block(int fd, struct scoutfs_radix_ref *par, int level)
{
	struct scoutfs_radix_block *rdx;
	u64 blkno;
	int prev;
	int ret;
	int err;
	int i;

	/* XXX not printing bitmap leaf blocks */
	blkno = le64_to_cpu(par->blkno);
	if (blkno == 0 || blkno == U64_MAX || level == 0)
		return 0;

	rdx = read_block(fd, le64_to_cpu(par->blkno));
	if (!rdx) {
		ret = -ENOMEM;
		goto out;
	}

	printf("radix parent block blkno %llu\n", le64_to_cpu(par->blkno));
	print_block_header(&rdx->hdr);
	printf("  sm_first %u lg_first %u\n",
	       le32_to_cpu(rdx->sm_first), le32_to_cpu(rdx->lg_first));

	prev = 0;
	for (i = 0; i < SCOUTFS_RADIX_REFS; i++) {
		/* only skip if the next ref is identically full/empty */
		if ((le64_to_cpu(rdx->refs[i].blkno) == 0 ||
		     le64_to_cpu(rdx->refs[i].blkno) == U64_MAX) &&
		    (i + 1) < SCOUTFS_RADIX_REFS &&
		    (le64_to_cpu(rdx->refs[i].blkno) ==
		     le64_to_cpu(rdx->refs[i + 1].blkno))) {
			prev++;
			continue;
		}

		if (prev) {
			printf("  [%u - %u]: (%s): ", i - prev, i,
			     (le64_to_cpu(rdx->refs[i].blkno) == 0) ? "empty" :
								      "full");
			prev = 0;
		} else {
			printf("  [%u]: ", i);
		}

		printf(RADREF_F"\n", RADREF_A(&rdx->refs[i]));
	}

	ret = 0;
	for (i = 0; i < SCOUTFS_RADIX_REFS; i++) {
		if (le64_to_cpu(rdx->refs[i].blkno) != 0 &&
		    le64_to_cpu(rdx->refs[i].blkno) != U64_MAX) {
			err = print_radix_block(fd, &rdx->refs[i], level - 1);
			if (err < 0 && ret == 0)
				ret = err;
		}
	}

out:
	free(rdx);

	return ret;
}

struct print_recursion_args {
	struct scoutfs_super_block *super;
	int fd;
};

/* same as fs item but with a small header in the value */
static int print_log_trees_roots(void *key, unsigned key_len, void *val,
				unsigned val_len, void *arg)
{
//	struct scoutfs_log_trees_key *ltk = key;
	struct scoutfs_log_trees_val *ltv = val;
	struct print_recursion_args *pa = arg;
	int ret = 0;
	int err;

	/* XXX doesn't print the bloom block */

	err = print_radix_block(pa->fd, &ltv->meta_avail.ref,
				ltv->meta_avail.height - 1);
	if (err && !ret)
		ret = err;
	err = print_radix_block(pa->fd, &ltv->meta_freed.ref,
				ltv->meta_avail.height - 1);
	if (err && !ret)
		ret = err;
	err = print_radix_block(pa->fd, &ltv->data_avail.ref,
				ltv->data_avail.height - 1);
	if (err && !ret)
		ret = err;
	err = print_radix_block(pa->fd, &ltv->meta_freed.ref,
				ltv->data_avail.height - 1);
	if (err && !ret)
		ret = err;

	err = print_btree(pa->fd, pa->super, "", &ltv->item_root,
			  print_logs_item, NULL);
	if (err && !ret)
		ret = err;

	return ret;
}

static int print_btree_leaf_items(int fd, struct scoutfs_super_block *super,
				  struct scoutfs_btree_ref *ref,
				  print_item_func func, void *arg)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	unsigned key_len;
	unsigned val_len;
	void *key;
	void *val;
	int ret;
	int i;

	if (ref->blkno == 0)
		return 0;

	bt = read_block(fd, le64_to_cpu(ref->blkno));
	if (!bt)
		return -ENOMEM;

	for (i = 0; i < le32_to_cpu(bt->nr_items); i++) {
		item = (void *)bt + le32_to_cpu(bt->item_hdrs[i].off);
		key_len = le16_to_cpu(item->key_len);
		val_len = le16_to_cpu(item->val_len);
		key = (void *)(item + 1);
		val = (void *)key + key_len;

		if (bt->level > 0) {
			ret = print_btree_leaf_items(fd, super, val, func, arg);
			if (ret)
				break;
			continue;
		} else {
			func(key, key_len, val, val_len, arg);
		}
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
		blk = read_block(fd, blkno);
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
	print_block_header(&super->hdr);
	printf("  format_hash %llx uuid %s\n",
	       le64_to_cpu(super->format_hash), uuid_str);

	server_addr = alloc_addr_str(&super->server_addr);
	if (!server_addr)
		return;

	/* XXX these are all in a crazy order */
	printf("  next_ino %llu next_trans_seq %llu\n"
	       "  total_meta_blocks %llu first_meta_blkno %llu last_meta_blkno %llu\n"
	       "  total_data_blocks %llu first_data_blkno %llu last_data_blkno %llu\n"
	       "  free_blocks %llu\n"
	       "  quorum_fenced_term %llu quorum_server_term %llu unmount_barrier %llu\n"
	       "  quorum_count %u server_addr %s\n"
	       "  core_meta_avail: "RADROOT_F"\n"
	       "  core_meta_freed: "RADROOT_F"\n"
	       "  core_data_avail: "RADROOT_F"\n"
	       "  core_data_freed: "RADROOT_F"\n"
	       "  lock_clients root: height %u blkno %llu seq %llu\n"
	       "  mounted_clients root: height %u blkno %llu seq %llu\n"
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
		le64_to_cpu(super->free_blocks),
		le64_to_cpu(super->quorum_fenced_term),
		le64_to_cpu(super->quorum_server_term),
		le64_to_cpu(super->unmount_barrier),
		super->quorum_count,
		server_addr,
		RADROOT_A(&super->core_meta_avail),
		RADROOT_A(&super->core_meta_freed),
		RADROOT_A(&super->core_data_avail),
		RADROOT_A(&super->core_data_freed),
		super->lock_clients.height,
		le64_to_cpu(super->lock_clients.ref.blkno),
		le64_to_cpu(super->lock_clients.ref.seq),
		super->mounted_clients.height,
		le64_to_cpu(super->mounted_clients.ref.blkno),
		le64_to_cpu(super->mounted_clients.ref.seq),
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
	int ret = 0;
	int err;

	super = read_block(fd, SCOUTFS_SUPER_BLKNO);
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

	err = print_radix_block(fd, &super->core_meta_avail.ref,
				super->core_meta_avail.height - 1);
	if (err && !ret)
		ret = err;
	err = print_radix_block(fd, &super->core_meta_freed.ref,
				super->core_meta_freed.height - 1);
	if (err && !ret)
		ret = err;
	err = print_radix_block(fd, &super->core_data_avail.ref,
				super->core_data_avail.height - 1);
	if (err && !ret)
		ret = err;
	err = print_radix_block(fd, &super->core_data_freed.ref,
				super->core_data_freed.height - 1);
	if (err && !ret)
		ret = err;

	err = print_btree(fd, super, "logs_root", &super->logs_root,
			  print_log_trees_item, NULL);
	if (err && !ret)
		ret = err;

	pa.super = super;
	pa.fd = fd;
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
