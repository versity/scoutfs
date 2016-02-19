#ifndef _SCOUTFS_FORMAT_H_
#define _SCOUTFS_FORMAT_H_

/* statfs(2) f_type */
#define SCOUTFS_SUPER_MAGIC	0x554f4353		/* "SCOU" */
/* super block id */
#define SCOUTFS_SUPER_ID	0x2e736674756f6373ULL	/* "scoutfs." */

/*
 * Structures are stored and referenced in fixed 4k chunks to
 * simplify block buffer access at run time.
 */
#define SCOUTFS_BLOCK_SHIFT 12
#define SCOUTFS_BLOCK_SIZE (1 << SCOUTFS_BLOCK_SHIFT)

/*
 * Logs are a logical structure that is made up of a fixed number of
 * contiguously allocated blocks.
 *
 * The allocator manages log-sized regions.  Smaller metadata blocks
 * like the ring and super blocks are stored inside large log
 * allocations.
 */
#define SCOUTFS_LOG_SHIFT 22
#define SCOUTFS_LOG_SIZE (1 << SCOUTFS_LOG_SHIFT)
#define SCOUTFS_LOG_BLOCK_SHIFT (SCOUTFS_LOG_SHIFT - SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_BLOCKS_PER_LOG (1 << SCOUTFS_LOG_BLOCK_SHIFT)

/*
 * The super blocks leave some room at the start of the first block for
 * platform structures like boot loaders.
 */
#define SCOUTFS_SUPER_BLKNO ((64 * 1024) >> SCOUTFS_BLOCK_SHIFT)
#define SCOUTFS_SUPER_NR 2

/*
 * This header is found at the start of every block so that we can
 * verify that it's what we were looking for.  The crc and padding
 * starts the block so that its calculation operations on a nice 64bit
 * aligned region.
 */
struct scoutfs_block_header {
	__le32 crc;
	__le32 _pad;
	__le64 fsid;
	__le64 seq;
	__le64 blkno;
} __packed;

#define SCOUTFS_UUID_BYTES 16

/*
 * The super is stored in a pair of blocks in log 0 on the device.
 *
 * The ring layout blocks describe the location of the ring blocks.  The
 * ring start and length refers to the logical ring blocks within that
 * storage which contain live data.
 */
struct scoutfs_super_block {
	struct scoutfs_block_header hdr;
	__le64 id;
	__u8 uuid[SCOUTFS_UUID_BYTES];
	__le64 total_logs;
	__le64 ring_layout_blkno;
	__le64 ring_layout_nr_blocks;
	__le64 ring_layout_seq;
	__le64 ring_block;
	__le64 ring_nr_blocks;
	__le64 ring_seq;
} __packed;

/*
 * We should be able to make the offset smaller if neither dirents nor
 * data items use the full 64 bits.
 */
struct scoutfs_key {
	__le64 inode;
	u8 type;
	__le64 offset;
} __packed;

#define SCOUTFS_ROOT_INO 1

#define SCOUTFS_INODE_KEY 128
#define SCOUTFS_DIRENT_KEY 192

struct scoutfs_layout_block {
	struct scoutfs_block_header hdr;
	__le32 nr_blocks;
	__le64 blknos[0];
} __packed;

struct scoutfs_ring_entry {
	u8 type;
	__le16 len;
} __packed;

/*
 * Ring blocks are 4k blocks stored inside the regions described by the
 * ring layout block referenced by the super.
 *
 * The manifest entries describe the position of a given block in the
 * manifest.  They're keyed by the block number so that we can log
 * movement of a block in the manifest with one log entry and we can log
 * deletion with just the block number.
 */ 
struct scoutfs_ring_block {
	struct scoutfs_block_header hdr;
	__le16 nr_entries;
} __packed;

enum {
	SCOUTFS_RING_REMOVE_MANIFEST = 0,
	SCOUTFS_RING_ADD_MANIFEST,
	SCOUTFS_RING_BITMAP,
};

/*
 * Manifest entries are logged by their block number.  This lets us log
 * a change with one entry and a removal with a tiny block number
 * without the key.
 */
struct scoutfs_ring_remove_manifest {
	__le64 blkno;
} __packed;

/*
 * Including both keys might make the manifest too large.  It might be
 * better to only include one key and infer a block's range from the
 * neighbour's key.  The downside of that is that we assume that there
 * isn't unused key space between blocks in a level.  We might search
 * blocks when we didn't need to.
 */
struct scoutfs_ring_add_manifest {
	__le64 blkno;
	__le64 seq;
	__u8 level;
	struct scoutfs_key first;
	struct scoutfs_key last;
} __packed;

struct scoutfs_ring_bitmap {
	__le32 offset;
	__le64 bits[2];
} __packed;

/*
 * To start the logs are a trivial single item block.  We'll flesh this out
 * into larger blocks once the rest of the architecture is in
 * place.
 */
struct scoutfs_item_block {
	struct scoutfs_block_header hdr;
	struct scoutfs_key first;
	struct scoutfs_key last;
	__le32 nr_items;
	/* struct scoutfs_item_header items[0] .. */
} __packed;

struct scoutfs_item_header {
	struct scoutfs_key key;
	__le16 len;
} __packed;

struct scoutfs_timespec {
	__le64 sec;
	__le32 nsec;
} __packed;

/*
 * XXX
 *	- otime?
 *	- compat flags?
 *	- version?
 *	- generation?
 *	- be more careful with rdev?
 */
struct scoutfs_inode {
	__le64 size;
	__le64 blocks;
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le32 rdev;
	__le32 salt;
	struct scoutfs_timespec atime;
	struct scoutfs_timespec ctime;
	struct scoutfs_timespec mtime;
} __packed;

#define SCOUTFS_ROOT_INO 1

/*
 * Dirents are stored in items with an offset of the hash of their name.
 * Colliding names are packed into the value.
 */
struct scoutfs_dirent {
	__le64 ino;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 type:4,
	     coll_nr:4;
#else
	__u8 coll_nr:4,
	     type:4;
#endif
	__u8 name_len;
	__u8 name[0];
} __packed;

#define SCOUTFS_NAME_LEN 255

/*
 * We only use 31 bits for readdir positions so that we don't confuse
 * old signed 32bit f_pos applications or those on the other side of
 * network protocols that have limited readir positions.
 */

#define SCOUTFS_DIRENT_OFF_BITS 27
#define SCOUTFS_DIRENT_OFF_MASK ((1 << SCOUTFS_DIRENT_OFF_BITS) - 1)
#define SCOUTFS_DIRENT_COLL_BITS 4
#define SCOUTFS_DIRENT_COLL_MASK ((1 << SCOUTFS_DIRENT_COLL_BITS) - 1)

/* getdents returns the *next* pos with each entry. so we can't return ~0 */
#define SCOUTFS_DIRENT_MAX_POS \
	(((1 << (SCOUTFS_DIRENT_OFF_BITS + SCOUTFS_DIRENT_COLL_BITS)) - 1) - 1)

enum {
	SCOUTFS_DT_FIFO = 0,
	SCOUTFS_DT_CHR,
	SCOUTFS_DT_DIR,
	SCOUTFS_DT_BLK,
	SCOUTFS_DT_REG,
	SCOUTFS_DT_LNK,
	SCOUTFS_DT_SOCK,
	SCOUTFS_DT_WHT,
};

#endif
