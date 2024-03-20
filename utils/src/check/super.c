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
int check_super_crc(bool repair)
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
	debug("superblock crc 0x%04x calculated 0x%04x " "%s", hdr->crc, crc, hdr->crc == crc ? "(match)" : "(mismatch)");

	if (crc != hdr->crc) {
		problem(PB_SB_HDR_CRC_INVALID, "crc 0x%04x calculated 0x%04x", hdr->crc, crc);
		if (repair) {
			super->hdr.crc = crc;
			block_try_commit(true);
		}
	}
	block_put(&blk);

	return 0;
}

/*
 * Crude checks and fix for some unlikely cases where the fs appears
 * to still be mounted. Fixing requires --force, to avoid modifying
 * a possibly still mounted filesystem.
 */
int check_super_in_use(int meta_fd, bool repair, bool force)
{
	int ret = meta_super_in_use(meta_fd, global_super);
	debug("meta_super_in_use ret %d", ret);

	if (ret < 0) {
		problem(PB_FS_IN_USE, "File system appears in use. ret %d", ret);
		if (force)
			ret = 0;
	}

	debug("global_super->mounted_clients.ref.blkno 0x%08llx", global_super->mounted_clients.ref.blkno);
	if (global_super->mounted_clients.ref.blkno != 0) {
		problem(PB_MOUNTED_CLIENTS_REF_BLKNO, "Mounted clients ref blkno 0x%08llx",
			 global_super->mounted_clients.ref.blkno);
		if (repair && force) {
			global_super->mounted_clients.ref.blkno = 0;
			ret = super_commit();
		} else {
			fprintf(stderr, "Refusing to repair PB_MOUNTED_CLIENTS_REF_BLKNO.\n"
				"Assure the filesystem is truly unmounted by disabling auto mount\n"
				"and rebooting the system before retrying with `--force`.\n");
		}
	}

	return ret;
}

/*
 * Writes back any change to global_super. Caller must have called check_supers()
 * Only writes back the super to the metadata device.
 */
int super_commit(void)
{
	struct scoutfs_super_block *super = NULL;
	struct block *blk = NULL;
	int ret;

	ret = block_get(&blk, SCOUTFS_SUPER_BLKNO, BF_SM | BF_DIRTY);
	if (ret < 0) {
		fprintf(stderr, "error reading super block\n");
		return ret;
	}

	super = block_buf(blk);

	memcpy(super, global_super, sizeof(struct scoutfs_super_block));

	/* recalculate the CRC */
	super->hdr.crc = crc_block((struct scoutfs_block_header *)super, block_size(blk));

	block_try_commit(true);

	block_put(&blk);

	return 0;
}

/*
 * After checking the supers we save a copy of it in a global buffer that's used by
 * other modules to track the current super.  It can be modified and written during commits.
 */
int check_supers(void)
{
	struct scoutfs_super_block *super = NULL;
	struct block *blk = NULL;
	struct scoutfs_quorum_slot* slot = NULL;
	struct in_addr in;
	uint16_t family;
	uint16_t port;
	int ret;

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

	super = block_buf(blk);

	memcpy(global_super, super, sizeof(struct scoutfs_super_block));

	debug("Superblock flag: %llu", global_super->flags);
	if (global_super->flags != SCOUTFS_FLAG_IS_META_BDEV)
		problem(PB_SB_BAD_FLAG, "Bad flag: %llu expecting: 1 or 0", global_super->flags);

	debug("Quorum Config Version: %llu", global_super->qconf.version);
	if (global_super->qconf.version != 1)
		problem(PB_QCONF_WRONG_VERSION, "Wrong Version: %llu (expected 1)", global_super->qconf.version);

	for (int i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		slot = &global_super->qconf.slots[i];
		family = le16_to_cpu(slot->addr.v4.family);
		port = le16_to_cpu(slot->addr.v4.port);
		in.s_addr = htonl(slot->addr.v4.addr);

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
	if (global_super->hdr.magic != SCOUTFS_BLOCK_MAGIC_SUPER)
		problem(PB_SB_HDR_MAGIC_INVALID, "superblock magic invalid: 0x%04x is not 0x%04x",
			global_super->hdr.magic, SCOUTFS_BLOCK_MAGIC_SUPER);

	ret = 0;
out:
	block_put(&blk);

	return ret;
}

void super_shutdown(void)
{
	free(global_super);
}
