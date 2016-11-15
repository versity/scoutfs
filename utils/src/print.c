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

static void print_inode(struct scoutfs_inode *inode)
{
	printf("      inode: size: %llu blocks: %llu lctr: %llu nlink: %u\n"
	       "             uid: %u gid: %u mode: 0%o rdev: 0x%x\n"
	       "             salt: 0x%x data_version %llu\n"
	       "             atime: %llu.%08u ctime: %llu.%08u\n"
	       "             mtime: %llu.%08u\n",
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
			 struct scoutfs_file_extent *ext)
{
	printf("      extent: (offest %llu) blkno %llu, len %llu flags %s%s\n",
	       le64_to_cpu(key->offset), le64_to_cpu(ext->blkno),
	       le64_to_cpu(ext->len),
	       EXT_FLAG(SCOUTFS_EXTENT_FLAG_OFFLINE, ext->flags, "OFF"));
}

static void print_block_ref(struct scoutfs_block_ref *ref)
{
	printf("      ref: blkno %llu seq %llu\n",
	       le64_to_cpu(ref->blkno), le64_to_cpu(ref->seq));
}

static void print_btree_val(struct scoutfs_btree_item *item, u8 level)
{

	if (level) {
		print_block_ref((void *)item->val);
		return;
	}

	switch(item->key.type) {
	case SCOUTFS_INODE_KEY:
		print_inode((void *)item->val);
		break;
	case SCOUTFS_XATTR_KEY:
		print_xattr((void *)item->val);
		break;
	case SCOUTFS_XATTR_VAL_HASH_KEY:
		print_xattr_val_hash((void *)item->val);
		break;
	case SCOUTFS_DIRENT_KEY:
		print_dirent((void *)item->val, le16_to_cpu(item->val_len));
		break;
	case SCOUTFS_LINK_BACKREF_KEY:
		print_link_backref((void *)item->val,
				   le16_to_cpu(item->val_len));
		break;
	case SCOUTFS_SYMLINK_KEY:
		print_symlink((void *)item->val, le16_to_cpu(item->val_len));
		break;
	case SCOUTFS_EXTENT_KEY:
		print_extent(&item->key, (void *)item->val);
		break;
	}
}

static int print_btree_block(int fd, __le64 blkno, u8 level)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block_ref *ref;
	unsigned int nr;
	int ret = 0;
	int err;
	int i;

	bt = read_block(fd, le64_to_cpu(blkno));
	if (!bt)
		return -ENOMEM;

	nr = le16_to_cpu(bt->nr_items);

	printf("btree blkno %llu\n", le64_to_cpu(blkno));
	print_block_header(&bt->hdr);
	printf("  free_end %u free_reclaim %u nr_items %u\n",
	       le16_to_cpu(bt->free_end), le16_to_cpu(bt->free_reclaim), nr);

	for (i = 0; i < nr; i++) {
		item = (void *)bt + le16_to_cpu(bt->item_offs[i]);

		printf("    [%u] off %u: key "SKF" seq %llu val_len %u\n",
			i, le16_to_cpu(bt->item_offs[i]),
			SKA(&item->key), le64_to_cpu(item->seq),
			le16_to_cpu(item->val_len));

		print_btree_val(item, level);
	}

	for (i = 0; level && i < nr; i++) {
		item = (void *)bt + le16_to_cpu(bt->item_offs[i]);

		ref = (void *)item->val;
		err = print_btree_block(fd, ref->blkno, level - 1);
		if (err && !ret)
			ret = err;
	}

	free(bt);

	return ret;
}

/* print populated buddy blocks */
static int print_buddy_block(int fd, struct buddy_info *binf,
			     int level, u64 base, u8 off)
{
	struct scoutfs_buddy_block *bud;
	struct scoutfs_buddy_slot *slot;
	int ret = 0;
	u64 blkno;
	u16 first;
	int err;
	int i;

	blkno = binf->blknos[level] + base + off;
	bud = read_block(fd, blkno);
	if (!bud)
		return -ENOMEM;

	printf("buddy blkno %llu\n", blkno);
	print_block_header(&bud->hdr);
	printf("  first_set:");
	for (i = 0; i < SCOUTFS_BUDDY_ORDERS; i++) {
		first = le16_to_cpu(bud->first_set[i]);
		if (first == U16_MAX)
			printf(" -");
		else
			printf(" %u", first);
	}
	printf("\n");
	printf("  level: %u\n", bud->level);

	for (i = 0; level && i < SCOUTFS_BUDDY_SLOTS; i++) {
		slot = &bud->slots[i];

		if (slot->seq == 0)
			continue;

		printf("  slots[%u]: seq %llu free_orders: %x blkno_off %u\n",
			i, le64_to_cpu(slot->seq),
			le16_to_cpu(slot->free_orders), slot->blkno_off);
	}

	for (i = 0; level && i < SCOUTFS_BUDDY_SLOTS; i++) {
		slot = &bud->slots[i];

		if (slot->seq == 0)
			continue;

		err = print_buddy_block(fd, binf, level - 1,
					(base * SCOUTFS_BUDDY_SLOTS) + (i * 2),
					slot->blkno_off);
		if (err && !ret)
			ret = err;
	}

	free(bud);

	return ret;
}

static int print_super_blocks(int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_super_block recent = { .hdr.seq = 0 };
	char uuid_str[37];
	int ret = 0;
	int err;
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
		printf("  next_ino %llu total_blocks %llu buddy_blocks %llu\n"
		       "  free_blocks %llu\n",
			le64_to_cpu(super->next_ino),
			le64_to_cpu(super->total_blocks),
			le64_to_cpu(super->buddy_blocks),
			le64_to_cpu(super->free_blocks));
		printf("  buddy_root: height %u seq %llu free_orders %x blkno_off %u\n",
			super->buddy_root.height,
			le64_to_cpu(super->buddy_root.slot.seq),
			le16_to_cpu(super->buddy_root.slot.free_orders),
			super->buddy_root.slot.blkno_off);
		printf("  btree_root: height %u seq %llu blkno %llu\n",
			super->btree_root.height,
			le64_to_cpu(super->btree_root.ref.seq),
			le64_to_cpu(super->btree_root.ref.blkno));

		if (le64_to_cpu(super->hdr.seq) > le64_to_cpu(recent.hdr.seq))
			memcpy(&recent, super, sizeof(recent));

		free(super);
	}

	super = &recent;


	if (super->buddy_root.height) {
		struct buddy_info binf;

		buddy_init(&binf, le64_to_cpu(super->total_blocks));
		err = print_buddy_block(fd, &binf,
					super->buddy_root.height - 1, 0,
					super->buddy_root.slot.blkno_off);
		if (err && !ret)
			ret = err;
	}

	if (super->btree_root.height) {
		err = print_btree_block(fd, super->btree_root.ref.blkno,
					super->btree_root.height - 1);
		if (err && !ret)
			ret = err;
	}

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
