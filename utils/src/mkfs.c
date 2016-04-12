#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <uuid/uuid.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sparse.h"
#include "cmd.h"
#include "util.h"
#include "format.h"
#include "crc.h"
#include "rand.h"
#include "dev.h"
#include "bitops.h"

/*
 * Update the block's header and write it out.
 */
static int write_block(int fd, u64 blkno, struct scoutfs_block_header *hdr)
{
	ssize_t ret;

	hdr->blkno = cpu_to_le64(blkno);
	hdr->crc = cpu_to_le32(crc_block(hdr));

	ret = pwrite(fd, hdr, SCOUTFS_BLOCK_SIZE, blkno << SCOUTFS_BLOCK_SHIFT);
	if (ret != SCOUTFS_BLOCK_SIZE) {
		fprintf(stderr, "write to blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		return -errno;
	}

	return 0;
}

static int write_new_fs(char *path, int fd)
{
	struct scoutfs_super_block *super;
	struct scoutfs_inode *inode;
	struct scoutfs_btree_block *bt;
	struct scoutfs_btree_item *item;
	struct scoutfs_key root_key;
	struct timeval tv;
	char uuid_str[37];
	unsigned int i;
	u64 size;
	u64 blkno;
	void *buf;
	int ret;

	gettimeofday(&tv, NULL);

	buf = malloc(SCOUTFS_BLOCK_SIZE);
	super = malloc(SCOUTFS_BLOCK_SIZE);
	if (!buf || !super) {
		ret = -errno;
		fprintf(stderr, "failed to allocate a block: %s (%d)\n",
			strerror(errno), errno);
		goto out;
	}

	ret = device_size(path, fd, &size);
	if (ret) {
		fprintf(stderr, "failed to stat '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	root_key.inode = cpu_to_le64(SCOUTFS_ROOT_INO);
	root_key.type = SCOUTFS_INODE_KEY;
	root_key.offset = 0;

	/* start with the block after the supers */
	blkno = SCOUTFS_SUPER_BLKNO + SCOUTFS_SUPER_NR;

	/* first initialize the super so we can use it to build structures */
	memset(super, 0, SCOUTFS_BLOCK_SIZE);
	pseudo_random_bytes(&super->hdr.fsid, sizeof(super->hdr.fsid));
	super->hdr.seq = cpu_to_le64(1);
	super->id = cpu_to_le64(SCOUTFS_SUPER_ID);
	uuid_generate(super->uuid);

	/* write a btree leaf root inode item */
	memset(buf, 0, SCOUTFS_BLOCK_SIZE);
	bt = buf;
	bt->hdr = super->hdr;
	bt->nr_items = cpu_to_le16(1);

	item = (void *)(bt + 1);
	item->key = root_key;
	item->tnode.parent = 0;
	item->tnode.left = 0;
	item->tnode.right = 0;
	pseudo_random_bytes(&item->tnode.prio, sizeof(item->tnode.prio));
	item->val_len = cpu_to_le16(sizeof(struct scoutfs_inode));

	inode = (void *)(item + 1);
	inode->nlink = cpu_to_le32(2);
	inode->mode = cpu_to_le32(0755 | 0040000);
	inode->atime.sec = cpu_to_le64(tv.tv_sec);
	inode->atime.nsec = cpu_to_le32(tv.tv_usec * 1000);
	inode->ctime.sec = inode->atime.sec;
	inode->ctime.nsec = inode->atime.nsec;
	inode->mtime.sec = inode->atime.sec;
	inode->mtime.nsec = inode->atime.nsec;

	bt->treap.off = cpu_to_le16((char *)&item->tnode - (char *)&bt->treap);
	bt->total_free = cpu_to_le16(SCOUTFS_BLOCK_SIZE -
				     ((char *)(inode + 1) - (char *)bt));
	bt->tail_free = bt->total_free;

	ret = write_block(fd, blkno, &bt->hdr);
	if (ret)
		goto out;

	/* make sure the super references everything we just wrote */
	super->btree_root.height = 1;
	super->btree_root.ref.blkno = bt->hdr.blkno;
	super->btree_root.ref.seq = bt->hdr.seq;

	/* write the two super blocks */
	for (i = 0; i < SCOUTFS_SUPER_NR; i++) {
		super->hdr.seq = cpu_to_le64(i + 1);
		ret = write_block(fd, SCOUTFS_SUPER_BLKNO + i, &super->hdr);
		if (ret)
			goto out;
	}

	if (fsync(fd)) {
		ret = -errno;
		fprintf(stderr, "failed to fsync '%s': %s (%d)\n",
			path, strerror(errno), errno);
		goto out;
	}

	uuid_unparse(super->uuid, uuid_str);

	printf("Created scoutfs filesystem:\n"
	       "  block size: %u\n"
	       "  fsid: %llx\n"
	       "  uuid: %s\n",
		SCOUTFS_BLOCK_SIZE, le64_to_cpu(super->hdr.fsid), uuid_str);

	ret = 0;
out:
	if (super)
		free(super);
	if (buf)
		free(buf);
	return ret;
}

static int mkfs_func(int argc, char *argv[])
{
	char *path = argv[0];
	int ret;
	int fd;

	if (argc != 1) {
		printf("scoutfs: mkfs: a single path argument is required\n");
		return -EINVAL;
	}

	fd = open(path, O_RDWR | O_EXCL);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
		return ret;
	}

	ret = write_new_fs(path, fd);
	close(fd);

	return ret;
}

static void __attribute__((constructor)) mkfs_ctor(void)
{
	cmd_register("mkfs", "<path>", "write a new file system", mkfs_func);

	/* for lack of some other place to put these.. */
	build_assert(sizeof(uuid_t) == SCOUTFS_UUID_BYTES);
}
