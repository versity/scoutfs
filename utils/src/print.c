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
	printf("        inode: size: %llu blocks: %llu nlink: %u\n"
	       "               uid: %u gid: %u mode: 0%o rdev: 0x%x\n"
	       "               salt: 0x%x max_dirent_hash_nr: %u\n"
	       "               atime: %llu.%08u ctime: %llu.%08u\n"
	       "               mtime: %llu.%08u\n",
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

	printf("      dirent: ino: %llu type: %u name: \"%.*s\"\n",
	       le64_to_cpu(dent->ino), dent->type, i, name);
}

static void print_btree_item(unsigned int off, struct scoutfs_btree_item *item)
{
	printf("    item: key "SKF" val_len %u off %u tnode: parent %u left %u right %u "
	       "prio %x\n",
		SKA(&item->key), le16_to_cpu(item->val_len), off,
		le16_to_cpu(item->tnode.parent),
		le16_to_cpu(item->tnode.left),
		le16_to_cpu(item->tnode.right),
		le32_to_cpu(item->tnode.prio));

	switch(item->key.type) {
	case SCOUTFS_INODE_KEY:
		print_inode((void *)item->val);
		break;
	case SCOUTFS_DIRENT_KEY:
		print_dirent((void *)item->val, le16_to_cpu(item->val_len));
		break;
	}
}

static int print_btree_block(int fd, __le64 blkno, u8 level)
{
	struct scoutfs_btree_item *item;
	struct scoutfs_btree_block *bt;
	struct scoutfs_block_ref *ref;
	unsigned int off;
	int ret = 0;
	int err;
	int i;

	bt = read_block(fd, le64_to_cpu(blkno));
	if (!bt)
		return -ENOMEM;

	printf("btree blkno %llu\n", le64_to_cpu(blkno));
	print_block_header(&bt->hdr);
	printf("  treap.off %u total_free %u tail_free %u nr_items %u\n",
	       le16_to_cpu(bt->treap.off),
	       le16_to_cpu(bt->total_free),
	       le16_to_cpu(bt->tail_free),
	       le16_to_cpu(bt->nr_items));

	/* XXX just print in offset order */
	item = (void *)(bt + 1);
	for (i = 0; i < le16_to_cpu(bt->nr_items); i++) {
		if (item->tnode.parent == cpu_to_le16(1)) {
			i--;
		} else  {
			off = (char *)&item->tnode - (char *)&bt->treap;
			print_btree_item(off, item);
		}

		item = (void *)&item->val[le16_to_cpu(item->val_len)];
	}

	item = (void *)(bt + 1);
	for (i = 0; level && i < le16_to_cpu(bt->nr_items); i++) {
		if (item->tnode.parent == cpu_to_le16(1)) {
			i--;
		} else  {
			ref = (void *)item->val;

			err = print_btree_block(fd, ref->blkno, level - 1);
			if (err && !ret)
				ret = err;
		}

		item = (void *)&item->val[le16_to_cpu(item->val_len)];
	}

	free(bt);

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
		printf("  btree_root: height %u seq %llu blkno %llu\n",
			super->btree_root.height,
			le64_to_cpu(super->btree_root.ref.seq),
			le64_to_cpu(super->btree_root.ref.blkno));

		if (le64_to_cpu(super->hdr.seq) > le64_to_cpu(recent.hdr.seq))
			memcpy(&recent, super, sizeof(recent));

		free(super);
	}

	super = &recent;

	if (super->btree_root.height)
		err = print_btree_block(fd, super->btree_root.ref.blkno,
					super->btree_root.height - 1);
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
