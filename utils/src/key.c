#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sparse.h"
#include "util.h"
#include "format.h"
#include "key.h"

/*
 * This is mechanically derived from scoutfs_key_str() in the kernel:
 *  - s/key->data/key_data/
 *  - s/key->key_len/key_len/
 *  - s/return snprintf_null(buf, size, /return printf(/
 */
int print_key(void *key_data, unsigned key_len)
{
	int len;
	u8 type;

	if (key_data == NULL)
		return printf("[NULL]");

	if (key_len == 0)
		return printf("[0 len]");

	type = *(u8 *)key_data;

	switch(type) {

	case SCOUTFS_INODE_KEY: {
		struct scoutfs_inode_key *ikey = key_data;

		if (key_len < sizeof(struct scoutfs_inode_key))
			break;

		return printf("ino.%llu",
				     be64_to_cpu(ikey->ino));
	}

	case SCOUTFS_XATTR_KEY: {
		struct scoutfs_xattr_key *xkey = key_data;

		len = (int)key_len - offsetof(struct scoutfs_xattr_key,
						   name[1]);
		if (len <= 0)
			break;

		return printf("xat.%llu.%.*s",
				     be64_to_cpu(xkey->ino), len, xkey->name);
	}

	case SCOUTFS_DIRENT_KEY: {
		struct scoutfs_dirent_key *dkey = key_data;

		len = (int)key_len - sizeof(struct scoutfs_dirent_key);
		if (len <= 0)
			break;

		return printf("dnt.%llu.%.*s",
				     be64_to_cpu(dkey->ino), len, dkey->name);
	}

	case SCOUTFS_READDIR_KEY: {
		struct scoutfs_readdir_key *rkey = key_data;

		return printf("rdr.%llu.%llu",
				     be64_to_cpu(rkey->ino),
				     be64_to_cpu(rkey->pos));
	}

	case SCOUTFS_LINK_BACKREF_KEY: {
		struct scoutfs_link_backref_key *lkey = key_data;

		len = (int)key_len - sizeof(*lkey);
		if (len <= 0)
			break;

		return printf("lbr.%llu.%llu.%.*s",
				     be64_to_cpu(lkey->ino),
				     be64_to_cpu(lkey->dir_ino), len,
				     lkey->name);
	}

	case SCOUTFS_SYMLINK_KEY: {
		struct scoutfs_symlink_key *skey = key_data;

		return printf("sym.%llu",
				     be64_to_cpu(skey->ino));
	}

	case SCOUTFS_FILE_EXTENT_KEY: {
		struct scoutfs_file_extent_key *ekey = key_data;

		return printf("ext.%llu.%llu.%llu.%llu.%x",
				     be64_to_cpu(ekey->ino),
				     be64_to_cpu(ekey->last_blk_off),
				     be64_to_cpu(ekey->last_blkno),
				     be64_to_cpu(ekey->blocks),
				     ekey->flags);
	}

	case SCOUTFS_ORPHAN_KEY: {
		struct scoutfs_orphan_key *okey = key_data;

		return printf("orp.%llu",
				     be64_to_cpu(okey->ino));
	}

	case SCOUTFS_FREE_EXTENT_BLKNO_KEY:
	case SCOUTFS_FREE_EXTENT_BLOCKS_KEY: {
		struct scoutfs_free_extent_blkno_key *fkey = key_data;

		return printf("%s.%llu.%llu.%llu",
			fkey->type == SCOUTFS_FREE_EXTENT_BLKNO_KEY ? "fel" :
								      "fes",
				be64_to_cpu(fkey->node_id),
				be64_to_cpu(fkey->last_blkno),
				be64_to_cpu(fkey->blocks));
	}

	case SCOUTFS_INODE_INDEX_CTIME_KEY:
	case SCOUTFS_INODE_INDEX_MTIME_KEY:
	case SCOUTFS_INODE_INDEX_SIZE_KEY:
	case SCOUTFS_INODE_INDEX_META_SEQ_KEY:
	case SCOUTFS_INODE_INDEX_DATA_SEQ_KEY: {
		struct scoutfs_inode_index_key *ikey = key_data;

		return printf("%s.%llu.%u.%llu",
			ikey->type == SCOUTFS_INODE_INDEX_CTIME_KEY ? "ctm" :
			ikey->type == SCOUTFS_INODE_INDEX_MTIME_KEY ? "mtm" :
			ikey->type == SCOUTFS_INODE_INDEX_SIZE_KEY ? "siz" :
			ikey->type == SCOUTFS_INODE_INDEX_META_SEQ_KEY ? "msq" :
			ikey->type == SCOUTFS_INODE_INDEX_DATA_SEQ_KEY ? "dsq" :
				"uii", be64_to_cpu(ikey->major),
				be32_to_cpu(ikey->minor),
				be64_to_cpu(ikey->ino));
	}

	default:
		return printf("[unknown type %u len %u]",
				     type, key_len);
	}

	return printf("[truncated type %u len %u]",
			     type, key_len);
}
