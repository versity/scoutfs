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
 *  - :.,$s/key->data/key_data/g
 *  - :.,$s/key->key_len/key_len/g
 *  - :.,$s/return snprintf_null(buf, size, /return printf(/g
 */
int print_key(void *key_data, unsigned key_len)
{
	struct scoutfs_inode_key *ikey;
	u8 zone = 0;
	u8 type = 0;
	int len;

	if (key_data == NULL)
		return printf("[NULL]");

	if (key_len == 0)
		return printf("[0 len]");

	zone = *(u8 *)key_data;

	/* handle smaller and unknown zones, fall through to fs types */
	switch(zone) {
	case SCOUTFS_INODE_INDEX_ZONE: {
		struct scoutfs_inode_index_key *ikey = key_data;
		static char *type_strings[] = {
			[SCOUTFS_INODE_INDEX_CTIME_TYPE]	= "ctm",
			[SCOUTFS_INODE_INDEX_MTIME_TYPE]	= "mtm",
			[SCOUTFS_INODE_INDEX_SIZE_TYPE]		= "siz",
			[SCOUTFS_INODE_INDEX_META_SEQ_TYPE]	= "msq",
			[SCOUTFS_INODE_INDEX_DATA_SEQ_TYPE]	= "dsq",
		};

		if (key_len < sizeof(struct scoutfs_inode_index_key))
			break;

		if (type_strings[ikey->type])
			return printf("iin.%s.%llu.%u.%llu",
					     type_strings[ikey->type],
					     be64_to_cpu(ikey->major),
					     be32_to_cpu(ikey->minor),
					     be64_to_cpu(ikey->ino));
		else
			return printf("[iin type %u?]",
					     ikey->type);
	}

	/* node zone keys start with zone, node, type */
	case SCOUTFS_NODE_ZONE: {
		struct scoutfs_free_extent_blkno_key *fkey = key_data;

		static char *type_strings[] = {
			[SCOUTFS_FREE_EXTENT_BLKNO_TYPE]	= "fno",
			[SCOUTFS_FREE_EXTENT_BLOCKS_TYPE]	= "fks",
		};

		switch(fkey->type) {
		case SCOUTFS_ORPHAN_TYPE: {
			struct scoutfs_orphan_key *okey = key_data;

			if (key_len < sizeof(struct scoutfs_orphan_key))
				break;
			return printf("nod.%llu.orp.%llu",
					     be64_to_cpu(okey->node_id),
					     be64_to_cpu(okey->ino));
		}

		case SCOUTFS_FREE_EXTENT_BLKNO_TYPE:
		case SCOUTFS_FREE_EXTENT_BLOCKS_TYPE:
			return printf("nod.%llu.%s.%llu.%llu",
					     be64_to_cpu(fkey->node_id),
					     type_strings[fkey->type],
					     be64_to_cpu(fkey->last_blkno),
					     be64_to_cpu(fkey->blocks));
		default:
			return printf("[nod type %u?]",
					     fkey->type);
		}
	}

	case SCOUTFS_FS_ZONE:
		break;

	default:
		return printf("[zone %u?]", zone);
	}

	/* everything in the fs tree starts with zone, ino, type */
	ikey = key_data;
	switch(ikey->type) {
	case SCOUTFS_INODE_TYPE: {
		struct scoutfs_inode_key *ikey = key_data;

		if (key_len < sizeof(struct scoutfs_inode_key))
			break;

		return printf("fs.%llu.ino",
				     be64_to_cpu(ikey->ino));
	}

	case SCOUTFS_XATTR_TYPE: {
		struct scoutfs_xattr_key *xkey = key_data;

		len = (int)key_len - offsetof(struct scoutfs_xattr_key,
						   name[1]);
		if (len <= 0)
			break;

		return printf("fs.%llu.xat.%.*s",
				     be64_to_cpu(xkey->ino), len, xkey->name);
	}

	case SCOUTFS_DIRENT_TYPE: {
		struct scoutfs_dirent_key *dkey = key_data;

		len = (int)key_len - sizeof(struct scoutfs_dirent_key);
		if (len <= 0)
			break;

		return printf("fs.%llu.dnt.%.*s",
				     be64_to_cpu(dkey->ino), len, dkey->name);
	}

	case SCOUTFS_READDIR_TYPE: {
		struct scoutfs_readdir_key *rkey = key_data;

		return printf("fs.%llu.rdr.%llu",
				     be64_to_cpu(rkey->ino),
				     be64_to_cpu(rkey->pos));
	}

	case SCOUTFS_LINK_BACKREF_TYPE: {
		struct scoutfs_link_backref_key *lkey = key_data;

		len = (int)key_len - sizeof(*lkey);
		if (len <= 0)
			break;

		return printf("fs.%llu.lbr.%llu.%.*s",
				     be64_to_cpu(lkey->ino),
				     be64_to_cpu(lkey->dir_ino), len,
				     lkey->name);
	}

	case SCOUTFS_SYMLINK_TYPE: {
		struct scoutfs_symlink_key *skey = key_data;

		return printf("fs.%llu.sym",
				     be64_to_cpu(skey->ino));
	}

	case SCOUTFS_FILE_EXTENT_TYPE: {
		struct scoutfs_file_extent_key *ekey = key_data;

		return printf("fs.%llu.ext.%llu.%llu.%llu.%x",
				     be64_to_cpu(ekey->ino),
				     be64_to_cpu(ekey->last_blk_off),
				     be64_to_cpu(ekey->last_blkno),
				     be64_to_cpu(ekey->blocks),
				     ekey->flags);
	}

	default:
		return printf("[fs type %u?]", type);
	}

	return printf("[fs type %u trunc len %u]",
			     type, key_len);

}
