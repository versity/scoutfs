#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <wordexp.h>

#include "util.h"
#include "format.h"
#include "crc.h"
#include "quorum.h"

#define ENV_PATH "SCOUTFS_MOUNT_PATH"

static int open_path(char *path, int flags)
{
	wordexp_t exp_result;
	int ret;

	ret = wordexp(path, &exp_result, WRDE_NOCMD | WRDE_SHOWERR | WRDE_UNDEF);
	if (ret) {
		fprintf(stderr, "wordexp() failure for \"%s\": %d\n", path, ret);
		ret = -EINVAL;
		goto out;
	}

	ret = open(exp_result.we_wordv[0], flags);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open '%s': %s (%d)\n",
			path, strerror(errno), errno);
	}

out:
	wordfree(&exp_result);

	return ret;
}

/*
 * 1. if path option given, use that
 * 2. if env var, use that
 * 3. if cwd is in a scoutfs fs, use that
 * 4. else error
 */
int get_path(char *path, int flags)
{
	char *env_path;
	char *cur_dir_path;
	int ret;

	if (path)
		return open_path(path, flags);

	env_path = getenv(ENV_PATH);
	if (env_path)
		return open_path(path, flags);

	cur_dir_path = get_current_dir_name();
	if (!cur_dir_path) {
		ret = -errno;
		return ret;
	}

	ret = open_path(cur_dir_path, flags);
	free(cur_dir_path);

	// TODO: check this is within a scoutfs mount?

	return ret;
}

int read_block(int fd, u64 blkno, int shift, void **ret_val)
{
	size_t size = 1ULL << shift;
	void *buf;
	int ret;

	buf = NULL;
	*ret_val = NULL;

	ret = posix_memalign(&buf, size, size);
	if (ret != 0) {
		ret = -errno;
		fprintf(stderr, "%zu byte aligned buffer allocation failed: %s (%d)\n",
			size, strerror(errno), errno);
		return ret;
	}

	ret = pread(fd, buf, size, blkno << shift);
	if (ret == -1) {
		fprintf(stderr, "read blkno %llu returned %d: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		free(buf);
		return -errno;
	} else if (ret != size) {
		fprintf(stderr, "incomplete pread\n");
		free(buf);
		return -EINVAL;
	} else {
		*ret_val = buf;
		return 0;
	}
}

int read_block_crc(int fd, u64 blkno, int shift, void **ret_val)
{
	struct scoutfs_block_header *hdr;
	size_t size = 1ULL << shift;
	int ret;
	u32 crc;

	ret = read_block(fd, blkno, shift, ret_val);
	if (ret == 0) {
		hdr = *ret_val;
		crc = crc_block(hdr, size);
		if (crc != le32_to_cpu(hdr->crc)) {
			fprintf(stderr, "crc of read blkno %llu failed, stored %08x != calculated %08x\n",
				blkno, le32_to_cpu(hdr->crc), crc);
			free(*ret_val);
			*ret_val = NULL;
			ret = -EIO;
		}
	}

	return ret;
}

int read_block_verify(int fd, u32 magic, u64 fsid, u64 blkno, int shift, void **ret_val)
{
	struct scoutfs_block_header *hdr = NULL;
	int ret;

	ret = read_block_crc(fd, blkno, shift, ret_val);
	if (ret == 0) {
		hdr = *ret_val;
		ret = -EIO;
		if (le32_to_cpu(hdr->magic) != magic)
			fprintf(stderr, "read blkno %llu has bad magic %08x != expected %08x\n",
				blkno, le32_to_cpu(hdr->magic), magic);
		else if (fsid != 0 && le64_to_cpu(hdr->fsid) != fsid)
			fprintf(stderr, "read blkno %llu has bad fsid %016llx != expected %016llx\n",
				blkno, le64_to_cpu(hdr->fsid), fsid);
		else if (le32_to_cpu(hdr->blkno) != blkno)
			fprintf(stderr, "read blkno %llu has bad blkno %llu != expected %llu\n",
				blkno, le64_to_cpu(hdr->blkno), blkno);
		else
			ret = 0;

		if (ret < 0) {
			free(*ret_val);
			*ret_val = NULL;
		}
	}


	return ret;
}

/*
 * Update the block header fields and write out the block.
 */
int write_block(int fd, u32 magic, __le64 fsid, u64 seq, u64 blkno,
		int shift, struct scoutfs_block_header *hdr)
{
	size_t size = 1ULL << shift;
	ssize_t ret;

	hdr->magic = cpu_to_le32(magic);
	hdr->fsid = fsid;
	hdr->blkno = cpu_to_le64(blkno);
	hdr->seq = cpu_to_le64(seq);
	hdr->crc = cpu_to_le32(crc_block(hdr, size));

	ret = pwrite(fd, hdr, size, blkno << shift);
	if (ret != size) {
		fprintf(stderr, "write to blkno %llu returned %zd: %s (%d)\n",
			blkno, ret, strerror(errno), errno);
		return -errno;
	}

	return 0;
}

int write_block_sync(int fd, u32 magic, __le64 fsid, u64 seq, u64 blkno,
		     int shift, struct scoutfs_block_header *hdr)
{
	int ret = write_block(fd, magic, fsid, seq, blkno, shift, hdr);
	if (ret != 0)
		return ret;

	if (fsync(fd)) {
		ret = -errno;
		fprintf(stderr, "fsync after write to blkno %llu failed: %s (%d)\n",
			blkno, strerror(errno), errno);
		return ret;
	}

	return 0;
}

/*
 * Check to see if the metadata super block indicates that there might
 * be active mounts using the system.  Returns -errno, 0, or -EBUSY if
 * we found evidence that the device might be in use.
 */
int meta_super_in_use(int meta_fd, struct scoutfs_super_block *meta_super)
{
	struct scoutfs_quorum_block *qblk = NULL;
	struct scoutfs_quorum_block_event *beg;
	struct scoutfs_quorum_block_event *end;
	int ret = 0;
	int i;

	if (meta_super->mounted_clients.ref.blkno != 0) {
		fprintf(stderr, "meta superblock mounted clients btree is not empty.\n");
		ret = -EBUSY;
		goto out;
	}

	/* check for active quorum slots */
	for (i = 0; i < SCOUTFS_QUORUM_BLOCKS; i++) {
		if (!quorum_slot_present(meta_super, i))
			continue;
		ret = read_block(meta_fd, SCOUTFS_QUORUM_BLKNO + i, SCOUTFS_BLOCK_SM_SHIFT,
				 (void **)&qblk);
		if (ret < 0) {
			fprintf(stderr, "error reading quorum block for slot %u\n", i);
			goto out;
		}

		beg = &qblk->events[SCOUTFS_QUORUM_EVENT_BEGIN];
		end = &qblk->events[SCOUTFS_QUORUM_EVENT_END];

		if (le64_to_cpu(beg->write_nr) > le64_to_cpu(end->write_nr)) {
			fprintf(stderr, "mount in quorum slot %u could still be running.\n"
					"  begin event: write_nr %llu timestamp %llu.%08u\n"
					"    end event: write_nr %llu timestamp %llu.%08u\n",
				i, le64_to_cpu(beg->write_nr), le64_to_cpu(beg->ts.sec),
				le32_to_cpu(beg->ts.nsec),
				le64_to_cpu(end->write_nr), le64_to_cpu(end->ts.sec),
				le32_to_cpu(end->ts.nsec));
			ret = -EBUSY;
			goto out;
		}

		free(qblk);
		qblk = NULL;
	}

out:
	return ret;
}
