#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <blkid/blkid.h>

#include "util.h"
#include "format.h"
#include "blkid.h"

static int check_bdev_blkid(int fd, char *devname, char *usage)
{
	blkid_probe pr;
	int ret = 0;

	pr = blkid_new_probe_from_filename(devname);
	if (!pr) {
		fprintf(stderr, "%s: failed to create a new libblkid probe\n", devname);
		goto out;
	}

	/* enable partitions probing (superblocks are enabled by default) */
	ret = blkid_probe_enable_partitions(pr, true);
	if (ret == -1) {
		fprintf(stderr, "%s: blkid_probe_enable_partitions() failed\n", devname);
		goto out;
	}

	ret = blkid_do_fullprobe(pr);
	if (ret == -1) {
		fprintf(stderr, "%s: blkid_do_fullprobe() failed", devname);
		goto out;
	} else if (ret == 0) {
		const char *type;

		if (!blkid_probe_lookup_value(pr, "TYPE", &type, NULL)) {
			fprintf(stderr, "%s: appears to contain an existing "
					"%s superblock\n", devname, type);
			ret = -1;
			goto out;
		}

		if (!blkid_probe_lookup_value(pr, "PTTYPE", &type, NULL)) {
			fprintf(stderr, "%s: appears to contain a partition "
					"table (%s)\n", devname, type);
			ret = -1;
			goto out;
		}
	} else {
		/* return 0 if ok */
		ret = 0;
	}

out:
	blkid_free_probe(pr);

	return ret;
}

static int check_bdev_scoutfs(int fd, char *devname, char *usage)
{
	struct scoutfs_super_block *super = NULL;
	int ret;

	ret = read_block(fd, SCOUTFS_SUPER_BLKNO, SCOUTFS_BLOCK_SM_SHIFT, (void **)&super);
	if (ret)
		return ret;

	if (le32_to_cpu(super->hdr.magic) == SCOUTFS_SUPER_MAGIC) {
		fprintf(stderr, "%s: appears to contain an existing "
			"ScoutFS superblock\n", devname);
		ret = -EINVAL;
	}

	free(super);

	return ret;
}


/*
 * Returns -1 on error, 0 otherwise.
 */
int check_bdev(int fd, char *devname, char *usage)
{
	return check_bdev_blkid(fd, devname, usage) ?:
		/* Our sig is not in blkid (yet) so check explicitly for us. */
		check_bdev_scoutfs(fd, devname, usage);
}
