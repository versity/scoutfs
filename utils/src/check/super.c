#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "crc.h"

#include "block.h"
#include "super.h"
#include "problem.h"

/*
 * After we check the super blocks we provide a global buffer to track
 * the current super block.  It is referenced to get static information
 * about the system and is also modified and written as part of
 * transactions.
 */
struct scoutfs_super_block *global_super;

/*
 * Check superblock crc. We can't use global_super here since it's not the
 * whole block itself, but only the struct scoutfs_super_block, so it needs
 * to reload a copy here.
 */
int check_super_crc(void)
{
	struct scoutfs_super_block *super = NULL;
	struct scoutfs_block_header *hdr;
	struct block *blk = NULL;
	u32 crc;
	int ret;

	ret = block_get(&blk, SCOUTFS_SUPER_BLKNO, BF_SM | BF_DIRTY);
	if (ret < 0) {
		fprintf(stderr, "error reading super block\n");
		return ret;
	}

	super = block_buf(blk);
	crc = crc_block((struct scoutfs_block_header *)super, block_size(blk));
	hdr = &global_super->hdr;
	debug("superblock crc 0x%04x calculated 0x%04x " "%s", le32_to_cpu(hdr->crc), crc, le32_to_cpu(hdr->crc) == crc ? "(match)" : "(mismatch)");

	if (crc != le32_to_cpu(hdr->crc))
		problem(PB_SB_HDR_CRC_INVALID, "crc 0x%04x calculated 0x%04x", le32_to_cpu(hdr->crc), crc);
	block_put(&blk);

	return 0;
}

/*
 * Crude check for the unlikely cases where the fs appears to still be mounted.
 */
int check_super_in_use(int meta_fd)
{
	int ret = meta_super_in_use(meta_fd, global_super);
	debug("meta_super_in_use ret %d", ret);

	if (ret < 0)
		problem(PB_FS_IN_USE, "File system appears in use. ret %d", ret);

	debug("global_super->mounted_clients.ref.blkno 0x%08llx", global_super->mounted_clients.ref.blkno);
	if (global_super->mounted_clients.ref.blkno != 0)
		problem(PB_MOUNTED_CLIENTS_REF_BLKNO, "Mounted clients ref blkno 0x%08llx",
			 global_super->mounted_clients.ref.blkno);

	return ret;
}

/*
 * quick glance data device superblock checks.
 *
 * -EIO for crc failures, all others -EINVAL
 *
 * caller must have run check_supers() first so that global_super is
 * setup, so that we can cross-ref to it.
 */
static int check_data_super(int data_fd)
{
	struct scoutfs_super_block *super = NULL;
	char *buf;
	int ret = 0;
	u32 crc;
	ssize_t size = SCOUTFS_BLOCK_SM_SIZE;
	off_t off = SCOUTFS_SUPER_BLKNO << SCOUTFS_BLOCK_SM_SHIFT;

	buf = aligned_alloc(4096, size); /* XXX static alignment :/ */
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, size);

	if (lseek(data_fd, off, SEEK_SET) != off)
		return -errno;

	if (read(data_fd, buf, size) < 0) {
		ret = -errno;
		goto out;
	}

	super = (struct scoutfs_super_block *)buf;

	crc = crc_block((struct scoutfs_block_header *)buf, size);

	debug("data fsid 0x%016llx", le64_to_cpu(super->hdr.fsid));
	debug("data super magic 0x%04x", super->hdr.magic);
	debug("data crc calc 0x%08x exp 0x%08x %s", crc, le32_to_cpu(super->hdr.crc),
	      crc == le32_to_cpu(super->hdr.crc) ? "(match)" : "(mismatch)");
	debug("data flags %llu fmt_vers %llu", le64_to_cpu(super->flags), le64_to_cpu(super->fmt_vers));

	if (crc != le32_to_cpu(super->hdr.crc))
		/* tis but a scratch */
		ret = -EIO;

	if (le64_to_cpu(super->hdr.fsid) != le64_to_cpu(global_super->hdr.fsid))
		/* mismatched data bdev? not good */
		ret = -EINVAL;

	if (le32_to_cpu(super->hdr.magic) != SCOUTFS_BLOCK_MAGIC_SUPER)
		/* fsid matched but not a superblock? yikes */
		ret = -EINVAL;

	if (le64_to_cpu(super->flags) != 0) /* !SCOUTFS_FLAG_IS_META_BDEV */
		ret = -EINVAL;

	if ((le64_to_cpu(super->fmt_vers) < SCOUTFS_FORMAT_VERSION_MIN) ||
	    (le64_to_cpu(super->fmt_vers) > SCOUTFS_FORMAT_VERSION_MAX))
		ret = -EINVAL;

	if (ret != 0)
		problem(PB_DATA_DEV_SB_INVALID, "data device is invalid or corrupt (%d)", ret);
out:
	free(buf);
	return ret;
}

/*
 * After checking the supers we save a copy of it in a global buffer that's used by
 * other modules to track the current super.  It can be modified and written during commits.
 */
int check_supers(int data_fd)
{
	struct scoutfs_super_block *super = NULL;
	struct block *blk = NULL;
	struct scoutfs_quorum_slot* slot = NULL;
	struct in_addr in;
	uint16_t family;
	uint16_t port;
	int ret;

	sns_push("supers", 0, 0);

	global_super = malloc(sizeof(struct scoutfs_super_block));
	if (!global_super) {
		fprintf(stderr, "error allocating super block buffer\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = block_get(&blk, SCOUTFS_SUPER_BLKNO, BF_SM);
	if (ret < 0) {
		fprintf(stderr, "error reading super block\n");
		goto out;
	}

	ret = block_hdr_valid(blk, SCOUTFS_SUPER_BLKNO, BF_SM, SCOUTFS_BLOCK_MAGIC_SUPER);

	super = block_buf(blk);

	if (ret < 0) {
		/* */
		if (ret == -EINVAL) {
			/* that's really bad */
			fprintf(stderr, "superblock invalid magic\n");
			goto out;
		} else if (ret == -EIO)
			/* just report/count a CRC error */
			problem(PB_SB_HDR_MAGIC_INVALID, "superblock magic invalid: 0x%04x is not 0x%04x",
				super->hdr.magic, SCOUTFS_BLOCK_MAGIC_SUPER);
	}

	memcpy(global_super, super, sizeof(struct scoutfs_super_block));

	debug("Superblock flag: %llu", global_super->flags);
	if (le64_to_cpu(global_super->flags) != SCOUTFS_FLAG_IS_META_BDEV)
		problem(PB_SB_BAD_FLAG, "Bad flag: %llu expecting: 1 or 0", global_super->flags);

	debug("Superblock fmt_vers: %llu", le64_to_cpu(global_super->fmt_vers));
	if ((le64_to_cpu(global_super->fmt_vers) < SCOUTFS_FORMAT_VERSION_MIN) ||
	    (le64_to_cpu(global_super->fmt_vers) > SCOUTFS_FORMAT_VERSION_MAX))
		problem(PB_SB_BAD_FMT_VERS, "Bad fmt_vers: %llu outside supported range (%d-%d)",
			le64_to_cpu(global_super->fmt_vers), SCOUTFS_FORMAT_VERSION_MIN,
			SCOUTFS_FORMAT_VERSION_MAX);

	debug("Quorum Config Version: %llu", global_super->qconf.version);
	if (le64_to_cpu(global_super->qconf.version) != 1)
		problem(PB_QCONF_WRONG_VERSION, "Wrong Version: %llu (expected 1)", global_super->qconf.version);

	for (int i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		slot = &global_super->qconf.slots[i];
		family = le16_to_cpu(slot->addr.v4.family);
		port = le16_to_cpu(slot->addr.v4.port);
		in.s_addr = le32_to_cpu(slot->addr.v4.addr);

		if (family == SCOUTFS_AF_NONE) {
			debug("Quorum slot %u is empty", i);
			continue;
		}

		debug("Quorum slot %u family: %u, port: %u, address: %s", i, family, port, inet_ntoa(in));
		if (family != SCOUTFS_AF_IPV4)
			problem(PB_QSLOT_BAD_FAM, "Quorum Slot %u doesn't have valid address", i);

		if (port == 0)
			problem(PB_QSLOT_BAD_PORT, "Quorum Slot %u has bad port", i);

		if (!in.s_addr) {
			problem(PB_QSLOT_NO_ADDR, "Quorum Slot %u has not been assigned ipv4 address", i);
		} else if (!(in.s_addr & 0xff000000)) {
			problem(PB_QSLOT_BAD_ADDR, "Quorum Slot %u has invalid ipv4 address", i);
		} else if ((in.s_addr & 0xff) == 0xff) {
			problem(PB_QSLOT_BAD_ADDR, "Quorum Slot %u has invalid ipv4 address", i);
		}
	}

	debug("super magic 0x%04x", global_super->hdr.magic);
	if (le32_to_cpu(global_super->hdr.magic) != SCOUTFS_BLOCK_MAGIC_SUPER)
		problem(PB_SB_HDR_MAGIC_INVALID, "superblock magic invalid: 0x%04x is not 0x%04x",
			global_super->hdr.magic, SCOUTFS_BLOCK_MAGIC_SUPER);

	/* `scoutfs image` command doesn't open data_fd */
	if (data_fd < 0)
		ret = 0;
	else
		ret = check_data_super(data_fd);
out:
	block_put(&blk);

	sns_pop();

	return ret;
}

void super_shutdown(void)
{
	free(global_super);
}
