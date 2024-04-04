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
			correct(PB_SB_HDR_CRC_INVALID);
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
			correct(PB_MOUNTED_CLIENTS_REF_BLKNO);
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

	if (super->hdr.magic != SCOUTFS_BLOCK_MAGIC_SUPER)
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
int check_supers(int data_fd, bool repair)
{
	struct scoutfs_super_block *super = NULL;
	struct block *blk = NULL;
	struct scoutfs_quorum_slot* slot = NULL;
	uint32_t addr;
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

	debug("fsid 0x%016llx", le64_to_cpu(global_super->hdr.fsid));
	debug("super magic 0x%04x", global_super->hdr.magic);

	debug("Superblock flag: %llu", global_super->flags);
	if (global_super->flags != SCOUTFS_FLAG_IS_META_BDEV) {
		problem(PB_SB_BAD_FLAG, "Bad flag: %llu expecting: 1 or 0", global_super->flags);
		if (repair) {
			global_super->flags = SCOUTFS_FLAG_IS_META_BDEV;
			ret = super_commit();

			if (ret < 0) {
				fprintf(stderr, "error writing superblock\n");
				goto out;
			} else
				correct(PB_SB_BAD_FLAG);
		}
	}

	debug("Superblock fmt_vers: %llu", le64_to_cpu(global_super->fmt_vers));
	if ((le64_to_cpu(global_super->fmt_vers) < SCOUTFS_FORMAT_VERSION_MIN) ||
	    (le64_to_cpu(global_super->fmt_vers) > SCOUTFS_FORMAT_VERSION_MAX))
		problem(PB_SB_BAD_FMT_VERS, "Bad fmt_vers: %llu outside supported range (%d-%d)",
			le64_to_cpu(global_super->fmt_vers), SCOUTFS_FORMAT_VERSION_MIN,
			SCOUTFS_FORMAT_VERSION_MAX);

	debug("Quorum Config Version: %llu", global_super->qconf.version);
	if (global_super->qconf.version != 1) {
		problem(PB_QCONF_WRONG_VERSION, "Wrong Version: %llu (expected 1)", global_super->qconf.version);
		if (repair) {
			global_super->qconf.version = 1;
			ret = super_commit();

			if (ret < 0) {
				fprintf(stderr, "error writing superblock\n");
				goto out;
			} else
				correct(PB_QCONF_WRONG_VERSION);
		}
	}

	for (int i = 0; i < SCOUTFS_QUORUM_MAX_SLOTS; i++) {
		slot = &global_super->qconf.slots[i];
		family = le16_to_cpu(slot->addr.v4.family);
		port = le16_to_cpu(slot->addr.v4.port);
		addr = le64_to_cpu(slot->addr.v4.addr);

		if (family == SCOUTFS_AF_NONE) {
			debug("Quorum slot %u is empty", i);
			continue;
		}

		debug("Quorum slot %u family: %u, port: %u, address: %u.%u.%u.%u", i, family, port, (addr >> 24) & 0xff, (addr >> 16) & 0xff,
																							(addr >> 8) & 0xff, addr & 0xff);
		if (family != SCOUTFS_AF_IPV4) {
			problem(PB_QSLOT_BAD_ADDR, "Quorum Slot %u doesn't have valid address family", i);
			if (repair) {
				slot->addr.v4.family = SCOUTFS_AF_IPV4;
				ret = super_commit();

				if (ret < 0) {
					fprintf(stderr, "error writing superblock\n");
					goto out;
				} else
					correct(PB_QSLOT_BAD_ADDR);
			}
		}

		if (port == 0) {
			problem(PB_QSLOT_BAD_ADDR, "Quorum Slot %u has bad port", i);
			fprintf(stderr, "Quorum slot %u is listening on a restricted port %u\n"
					"and needs to be reconfigured\n"
					"use \'scoutfs change-quorum-config -F -Q NR,ADDR,PORT\' to"
					"reconfigure the port\n", i, port);
		}

		if (!addr) {
			problem(PB_QSLOT_BAD_ADDR, "Quorum Slot %u has not been assigned ipv4 address", i);
			fprintf(stderr, "Quorum slot %u has not been assigned an ip address\n"
					"to assign an address use \'scoutfs change-quorum-config -F -Q NR,ADDR,PORT\'\n", i);
		} else if (!(addr & 0xff000000)) {
			problem(PB_QSLOT_BAD_ADDR, "Quorum Slot %u has invalid ipv4 address: Wildcard", i);
			fprintf(stderr, "Quorum slot %u has a wildcard address ex: 0.x.x.x\n"
					"to reassign an address use \'scoutfs change-quorum-config -F -Q NR,ADDR,PORT\'\n", i);
		} else if ((addr & 0xff) == 0xff) {
			problem(PB_QSLOT_BAD_ADDR, "Quorum Slot %u has invalid ipv4 address: Broadcast", i);
			fprintf(stderr, "Quorum slot %u has a broadcast address ex: x.x.x.255\n"
					"to reassign an address use \'scoutfs change-quorum-config -F -Q NR,ADDR,PORT\'\n", i);
		}
	}

	if (global_super->hdr.magic != SCOUTFS_BLOCK_MAGIC_SUPER)
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
