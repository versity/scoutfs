#ifndef _SCOUTFS_IOCTL_H_
#define _SCOUTFS_IOCTL_H_

/*
 * We naturally align explicit width fields in the ioctl structs so that
 * userspace doesn't need to deal with padding or unaligned packing and
 * we don't have to deal with 32/64 compat.  It makes it a little
 * awkward to communicate persistent packed structs through the ioctls
 * but that happens very rarely.  An interesting special case are
 * 0length arrays that follow the structs.  We make those start at the
 * next aligned offset of the struct to be safe.
 *
 * This is enforced by pahole scripting in external build environments.
 */

#define SCOUTFS_IOCTL_MAGIC 0xE8  /* arbitrarily chosen hole in ioctl-number.rst */

/*
 * Packed scoutfs keys rarely cross the ioctl boundary so we have a
 * translation struct.
 */
struct scoutfs_ioctl_key {
	__le64	_sk_first;
	__le64	_sk_second;
	__le64	_sk_third;
	__u8	_sk_fourth;
	__u8	sk_type;
	__u8	sk_zone;
	__u8	_pad[5];
};

struct scoutfs_ioctl_walk_inodes_entry {
	__u64 major;
	__u64 ino;
	__u32 minor;
	__u8  _pad[4];
};

/*
 * Walk inodes in an index that is sorted by one of their fields.
 *
 * Each index is built from generic index items that have major and
 * minor values that are set to the field being indexed.  In time
 * indices, for example, major is seconds and minor is nanoseconds.
 *
 * @first       The first index entry that can be returned.
 * @last        The last index entry that can be returned.
 * @entries_ptr Pointer to emory containing buffer for entry results.
 * @nr_entries  The number of entries that can fit in the buffer.
 * @index       Which index to walk, enumerated in _WALK_INODES_ constants.
 *
 * To start iterating first can be memset to 0 and last to 0xff.  Then
 * after each set of results first can be set to the last entry returned
 * and then the fields can be incremented in reverse sort order (ino <
 * minor < major) as each increasingly significant value wraps around to
 * 0.
 *
 * These indexes are not strictly consistent.  The items that back these
 * index entries aren't updated with cluster locks so they're not
 * guaranteed to be visible the moment you read after writing.  They're
 * only visible when the transaction that updated them is synced.
 *
 * In addition, the seq indexes will only allow walking through sequence
 * space that has been consistent.  This prevents old dirty entries from
 * becoming visible after newer stable entries are displayed.
 *
 * If first is greater than last then the walk will return 0 entries.
 *
 * XXX invalidate before reading.
 */
struct scoutfs_ioctl_walk_inodes {
	struct scoutfs_ioctl_walk_inodes_entry first;
	struct scoutfs_ioctl_walk_inodes_entry last;
	__u64 entries_ptr;
	__u32 nr_entries;
	__u8 index;
	__u8 _pad[11]; /* padded to align walk_inodes_entry total size */
};

enum scoutfs_ino_walk_seq_type {
	SCOUTFS_IOC_WALK_INODES_META_SEQ = 0,
	SCOUTFS_IOC_WALK_INODES_DATA_SEQ,
	SCOUTFS_IOC_WALK_INODES_UNKNOWN,
};

/*
 * Adds entries to the user's buffer for each inode that is found in the
 * given index between the first and last positions.
 */
#define SCOUTFS_IOC_WALK_INODES _IOW(SCOUTFS_IOCTL_MAGIC, 1, \
				     struct scoutfs_ioctl_walk_inodes)

/*
 * Fill the result buffer with the next absolute path to the target
 * inode searching from a given position in a parent directory.
 *
 * @ino: The target ino that we're finding paths to.  Constant across
 * all the calls that make up an iteration over all the inode's paths.
 *
 * @dir_ino: The inode number of the directory containing the entry to
 * our inode to search from.  If this parent directory contains no more
 * entries to our inode then we'll search through other parent directory
 * inodes in inode order.
 *
 * @dir_pos: The position in the dir_ino parent directory of the entry
 * to our inode to search from.  If there is no entry at this position
 * then we'll search through other entry positions in increasing order.
 * If we exhaust the parent directory then we'll search through
 * additional parent directories in inode order.
 *
 * @result_ptr: A pointer to the buffer where the result struct and
 * absolute path will be stored.
 *
 * @result_bytes: The size of the buffer that will contain the result
 * struct and the null terminated absolute path name.
 *
 * To start iterating set the desired target inode, dir_ino to 0,
 * dir_pos to 0, and set result_ptr and _bytes to a sufficiently large
 * buffeer (sizeof(result) + PATH_MAX is a solid choice).
 *
 * After each returned result set the next search dir_ino and dir_pos to
 * the returned dir_ino and dir_pos.  Then increment the search dir_pos,
 * and if it wrapped to 0, increment dir_ino.
 *
 * This only walks back through full hard links.  None of the returned
 * paths will reflect symlinks to components in the path.
 *
 * This doesn't ensure that the caller has permissions to traverse the
 * returned paths to the inode.  It requires CAP_DAC_READ_SEARCH which
 * bypasses permissions checking.
 *
 * This call is not serialized with any modification (create, rename,
 * unlink) of the path components.  It will return all the paths that
 * were stable both before and after the call.  It may or may not return
 * paths which are created or unlinked during the call.
 *
 * On success 0 is returned and result struct is filled with the next
 * absolute path.  The path_bytes length of the path includes a null
 * terminating byte.  dir_ino and dir_pos refer to the position of the
 * final component in its parent directory and can be advanced to search
 * for the next terminal entry whose path is then built by walking up
 * parent directories.
 *
 * ENOENT is returned when no paths are found.
 *
 * ENAMETOOLONG is returned when the result struct and path found
 * doesn't fit in the result buffer.
 *
 * Many other errnos indicate hard failure to find the next path.
 */
struct scoutfs_ioctl_ino_path {
	__u64 ino;
	__u64 dir_ino;
	__u64 dir_pos;
	__u64 result_ptr;
	__u16 result_bytes;
	__u8 _pad[6];
};

struct scoutfs_ioctl_ino_path_result {
	__u64 dir_ino;
	__u64 dir_pos;
	__u16 path_bytes;
	__u8  _pad[6];
	__u8  path[];
};

/* Get a single path from the root to the given inode number */
#define SCOUTFS_IOC_INO_PATH _IOW(SCOUTFS_IOCTL_MAGIC, 2, \
				  struct scoutfs_ioctl_ino_path)

/*
 * "Release" a contiguous range of logical blocks of file data.
 * Released blocks are removed from the file system like truncation, but
 * an offline record is left behind to trigger demand staging if the
 * file is read.
 *
 * The starting file offset and number of bytes to release must be in
 * multiples of 4KB.
 *
 * The specified range can extend past i_size and can straddle sparse
 * regions or blocks that are already offline.  The only change it makes
 * is to free and mark offline any existing blocks that intersect with
 * the region.
 *
 * Returns 0 if the operation succeeds.  If an error is returned then
 * some partial region of the blocks in the region may have been marked
 * offline.
 *
 * If the operation succeeds then inode metadata that reflects file data
 * contents are not updated.  This is intended to be transparent to the
 * presentation of the data in the file.
 */
struct scoutfs_ioctl_release {
	__u64 offset;
	__u64 length;
	__u64 data_version;
};

#define SCOUTFS_IOC_RELEASE _IOW(SCOUTFS_IOCTL_MAGIC, 3, \
				 struct scoutfs_ioctl_release)

struct scoutfs_ioctl_stage {
	__u64 data_version;
	__u64 buf_ptr;
	__u64 offset;
	__s32 length;
	__u32 _pad;
};

#define SCOUTFS_IOC_STAGE _IOW(SCOUTFS_IOCTL_MAGIC, 4, \
			       struct scoutfs_ioctl_stage)

/*
 * Give the user inode fields that are not otherwise visible.  statx()
 * isn't always available and xattrs are relatively expensive.
 */
struct scoutfs_ioctl_stat_more {
	__u64 meta_seq;
	__u64 data_seq;
	__u64 data_version;
	__u64 online_blocks;
	__u64 offline_blocks;
	__u64 crtime_sec;
	__u32 crtime_nsec;
	__u8  _pad[4];
};

#define SCOUTFS_IOC_STAT_MORE _IOR(SCOUTFS_IOCTL_MAGIC, 5, \
				   struct scoutfs_ioctl_stat_more)


struct scoutfs_ioctl_data_waiting_entry {
	__u64 ino;
	__u64 iblock;
	__u8 op;
	__u8 _pad[7];
};

#define SCOUTFS_IOC_DWO_READ		(1 << 0)
#define SCOUTFS_IOC_DWO_WRITE		(1 << 1)
#define SCOUTFS_IOC_DWO_CHANGE_SIZE	(1 << 2)
#define SCOUTFS_IOC_DWO_UNKNOWN		(U8_MAX << 3)

struct scoutfs_ioctl_data_waiting {
	__u64 flags;
	__u64 after_ino;
	__u64 after_iblock;
	__u64 ents_ptr;
	__u16 ents_nr;
	__u8 _pad[6];
};

#define SCOUTFS_IOC_DATA_WAITING_FLAGS_UNKNOWN		(U64_MAX << 0)

#define SCOUTFS_IOC_DATA_WAITING _IOW(SCOUTFS_IOCTL_MAGIC, 6, \
				      struct scoutfs_ioctl_data_waiting)

/*
 * If i_size is set then data_version must be non-zero.  If the offline
 * flag is set then i_size must be set and a offline extent will be
 * created from offset 0 to i_size.  The time fields are always applied
 * to the inode.
 */
struct scoutfs_ioctl_setattr_more {
	__u64 data_version;
	__u64 i_size;
	__u64 flags;
	__u64 ctime_sec;
	__u32 ctime_nsec;
	__u32 crtime_nsec;
	__u64 crtime_sec;
};

#define SCOUTFS_IOC_SETATTR_MORE_OFFLINE		(1 << 0)
#define SCOUTFS_IOC_SETATTR_MORE_UNKNOWN		(U64_MAX << 1)

#define SCOUTFS_IOC_SETATTR_MORE _IOW(SCOUTFS_IOCTL_MAGIC, 7, \
				      struct scoutfs_ioctl_setattr_more)

struct scoutfs_ioctl_listxattr_hidden {
	__u64 id_pos;
	__u64 buf_ptr;
	__u32 buf_bytes;
	__u32 hash_pos;
};

#define SCOUTFS_IOC_LISTXATTR_HIDDEN _IOWR(SCOUTFS_IOCTL_MAGIC, 8, \
					   struct scoutfs_ioctl_listxattr_hidden)

/*
 * Return the inode numbers of inodes which might contain the given
 * xattr.  The inode may not have a set xattr with that name, the caller
 * must check the returned inodes to see if they match.
 *
 * @next_ino: The next inode number that could be returned.  Initialized
 * to 0 when first searching and set to one past the last inode number
 * returned to continue searching.
 * @last_ino: The last inode number that could be returned.  U64_MAX to
 * find all inodes.
 * @name_ptr: The address of the name of the xattr to search for.  It is
 * not null terminated.
 * @inodes_ptr: The address of the array of uint64_t inode numbers in
 * which to store inode numbers that may contain the xattr.  EFAULT may
 * be returned if this address is not naturally aligned.
 * @output_flags: Set as success is returned.  If an error is returned
 * then this field is undefined and should not be read.
 * @nr_inodes: The number of elements in the array found at inodes_ptr.
 * @name_bytes: The number of non-null bytes found in the name at
 * name_ptr.
 *
 * This requires the CAP_SYS_ADMIN capability and will return -EPERM if
 * it's not granted.
 *
 * The number of inode numbers stored in the inodes_ptr array is
 * returned.  If nr_inodes is 0 or last_ino is less than next_ino then 0
 * will be immediately returned.
 *
 * Partial progress can be returned if an error is hit or if nr_inodes
 * was larger than the internal limit on the number of inodes returned
 * in a search pass.  The _END output flag is set if all the results
 * including last_ino were searched in this pass.
 *
 * It's valuable to provide a large inodes array so that all the results
 * can be found in one search pass and _END can be set.  There are
 * significant constant costs for performing each search pass.
 */
struct scoutfs_ioctl_search_xattrs {
	__u64 next_ino;
	__u64 last_ino;
	__u64 name_ptr;
	__u64 inodes_ptr;
	__u64 output_flags;
	__u64 nr_inodes;
	__u16 name_bytes;
	__u8 _pad[6];
};

/* set in output_flags if returned inodes reached last_ino */
#define SCOUTFS_SEARCH_XATTRS_OFLAG_END (1ULL << 0)

#define SCOUTFS_IOC_SEARCH_XATTRS _IOW(SCOUTFS_IOCTL_MAGIC, 9, \
				       struct scoutfs_ioctl_search_xattrs)

/*
 * Give the user information about the filesystem.
 *
 * @committed_seq: All seqs up to and including this seq have been
 * committed.  Can be compared with meta_seq and data_seq from inodes in
 * stat_more to discover if changes have been committed to disk.
 */
struct scoutfs_ioctl_statfs_more {
	__u64 fsid;
	__u64 rid;
	__u64 committed_seq;
	__u64 total_meta_blocks;
	__u64 total_data_blocks;
	__u64 reserved_meta_blocks;
};

#define SCOUTFS_IOC_STATFS_MORE _IOR(SCOUTFS_IOCTL_MAGIC, 10, \
				     struct scoutfs_ioctl_statfs_more)

/*
 * Cause matching waiters to return an error.
 *
 * Find current waiters that match the inode, op, and block range to wake
 * up and return an error.
 */
struct scoutfs_ioctl_data_wait_err {
	__u64 ino;
	__u64 data_version;
	__u64 offset;
	__u64 count;
	__u64 op;
	__s64 err;
};

#define SCOUTFS_IOC_DATA_WAIT_ERR _IOW(SCOUTFS_IOCTL_MAGIC, 11, \
				       struct scoutfs_ioctl_data_wait_err)


struct scoutfs_ioctl_alloc_detail {
	__u64 entries_ptr;
	__u64 entries_nr;
};

struct scoutfs_ioctl_alloc_detail_entry {
	__u64 id;
	__u64 blocks;
	__u8 type;
	__u8 meta:1,
	     avail:1;
	__u8 __bit_pad:6;
	__u8 __pad[6];
};

#define SCOUTFS_IOC_ALLOC_DETAIL _IOW(SCOUTFS_IOCTL_MAGIC, 12, \
				      struct scoutfs_ioctl_alloc_detail)

/*
 * Move extents from one regular file to another at a different offset,
 * on the same file system.
 *
 * from_fd specifies the source file and the ioctl is called on the
 * destination file.  Both files must have write access.  from_off specifies
 * the byte offset in the source, to_off is the byte offset in the
 * destination, and len is the number of bytes in the region to move.  All of
 * the offsets and lengths must be in multiples of 4KB, except in the case
 * where the from_off + len ends at the i_size of the source
 * file. data_version is only used when STAGE flag is set (see below).  flags
 * field is currently only used to optionally specify STAGE behavior.
 *
 * This interface only moves extents which are block granular, it does
 * not perform RMW of sub-block byte extents and it does not overwrite
 * existing extents in the destination.  It will split extents in the
 * source.
 *
 * Only extents within i_size on the source are moved.  The destination
 * i_size will be updated if extents are moved beyond its current
 * i_size.  The i_size update will maintain final partial blocks in the
 * source.
 *
 * If STAGE flag is not set, it will return an error if either of the files
 * have offline extents.  It will return 0 when all of the extents in the
 * source region have been moved to the destination.  Moving extents updates
 * the ctime, mtime, meta_seq, data_seq, and data_version fields of both the
 * source and destination inodes.  If an error is returned then partial
 * progress may have been made and inode fields may have been updated.
 *
 * If STAGE flag is set, as above except destination range must be in an
 * offline extent. Fields are updated only for source inode.
 *
 * Errors specific to this interface include:
 *
 * EINVAL: from_off, len, or to_off aren't a multiple of 4KB; the source
 *	   and destination files are the same inode; either the source or
 *	   destination is not a regular file; the destination file has
 *	   an existing overlapping extent (if STAGE flag not set); the
 *	   destination range is not in an offline extent (if STAGE set).
 * EOVERFLOW: either from_off + len or to_off + len exceeded 64bits.
 * EBADF: from_fd isn't a valid open file descriptor.
 * EXDEV: the source and destination files are in different filesystems.
 * EISDIR: either the source or destination is a directory.
 * ENODATA: either the source or destination file have offline extents and
 *	    STAGE flag is not set.
 * ESTALE: data_version does not match destination data_version.
 */
#define SCOUTFS_IOC_MB_STAGE		(1 << 0)
#define SCOUTFS_IOC_MB_UNKNOWN		(U64_MAX << 1)

struct scoutfs_ioctl_move_blocks {
	__u64 from_fd;
	__u64 from_off;
	__u64 len;
	__u64 to_off;
	__u64 data_version;
	__u64 flags;
};

#define SCOUTFS_IOC_MOVE_BLOCKS _IOW(SCOUTFS_IOCTL_MAGIC, 13, \
				     struct scoutfs_ioctl_move_blocks)

struct scoutfs_ioctl_resize_devices {
	__u64 new_total_meta_blocks;
	__u64 new_total_data_blocks;
};

#define SCOUTFS_IOC_RESIZE_DEVICES \
	_IOW(SCOUTFS_IOCTL_MAGIC, 14, struct scoutfs_ioctl_resize_devices)

#define SCOUTFS_IOCTL_XATTR_TOTAL_NAME_NR 3

/*
 * Copy global totals of .totl. xattr value payloads to the user.   This
 * only sees xattrs which have been committed and this doesn't force
 * commits of dirty data throughout the system.  This can be out of sync
 * by the amount of xattrs that can be dirty in open transactions that
 * are being built throughout the system.
 *
 * pos_name: The array name of the first total that can be returned.
 * The name is derived from the key of the xattrs that contribute to the
 * total.  For xattrs with a .totl.1.2.3 key, the pos_name[] should be
 * {1, 2, 3}.
 *
 * totals_ptr: An aligned pointer to a buffer that will be filled with
 * an array of scoutfs_ioctl_xattr_total structs for each total copied.
 *
 * totals_bytes: The size of the buffer in bytes.  There must be room
 * for at least one struct element so that returning 0 can promise that
 * there were no more totals to copy after the pos_name.
 *
 * The number of copied elements is returned and 0 is returned if there
 * were no more totals to copy after the pos_name.
 *
 * In addition to the usual errnos (EIO, EINVAL, EPERM, EFAULT) this
 * adds:
 *
 * EINVAL: The totals_ buffer was not aligned or was not large enough
 * for a single struct entry.
 */
struct scoutfs_ioctl_read_xattr_totals {
	__u64 pos_name[SCOUTFS_IOCTL_XATTR_TOTAL_NAME_NR];
	__u64 totals_ptr;
	__u64 totals_bytes;
};

/*
 * An individual total that is given to userspace.   The total is the
 * sum of all the values in the xattr payloads matching the name.  The
 * count is the number of xattrs, not number of files, contributing to
 * the total.
 */
struct scoutfs_ioctl_xattr_total {
	__u64 name[SCOUTFS_IOCTL_XATTR_TOTAL_NAME_NR];
	__u64 total;
	__u64 count;
};

#define SCOUTFS_IOC_READ_XATTR_TOTALS \
	_IOW(SCOUTFS_IOCTL_MAGIC, 15, struct scoutfs_ioctl_read_xattr_totals)

/*
 * This fills the caller's inos array with inode numbers that are in use
 * after the start ino, within an internal inode group.
 *
 * This only makes a promise about the state of the inode numbers within
 * the first and last numbers returned by one call.  At one time, all of
 * those inodes were still allocated.   They could have changed before
 * the call returned.   And any numbers outside of the first and last
 * (or single) are undefined.
 *
 * This doesn't iterate over all allocated inodes, it only probes a
 * single group that the start inode is within.   This interface was
 * first introduced to support tests that needed to find out about a
 * specific inode, while having some other similarly niche uses.   It is
 * unsuitable for a consistent iteration over all the inode numbers in
 * use.
 *
 * This test of inode items doesn't serialize with the inode lifetime
 * mechanism.   It only tells you the numbers of inodes that were once
 * active in the system and haven't yet been fully deleted.  The inode
 * numbers returned could have been in the process of being deleted and
 * were already unreachable even before the call started.
 *
 * @start_ino: the first inode number that could be returned
 * @inos_ptr: pointer to an aligned array of 64bit inode numbers
 * @inos_bytes: the number of bytes available in the inos_ptr array
 *
 * Returns errors or the count of inode numbers returned, quite possibly
 * including 0.
 */
struct scoutfs_ioctl_get_allocated_inos {
	__u64 start_ino;
	__u64 inos_ptr;
	__u64 inos_bytes;
};

#define SCOUTFS_IOC_GET_ALLOCATED_INOS \
	_IOW(SCOUTFS_IOCTL_MAGIC, 16, struct scoutfs_ioctl_get_allocated_inos)

/*
 * Get directory entries that refer to a specific inode.
 *
 * @ino: The target ino that we're finding referring entries to.
 * Constant across all the calls that make up an iteration over all the
 * inode's entries.
 *
 * @dir_ino: The inode number of a directory containing the entry to our
 * inode to search from.  If this parent directory contains no more
 * entries to our inode then we'll search through other parent directory
 * inodes in inode order.
 *
 * @dir_pos: The position in the dir_ino parent directory of the entry
 * to our inode to search from.  If there is no entry at this position
 * then we'll search through other entry positions in increasing order.
 * If we exhaust the parent directory then we'll search through
 * additional parent directories in inode order.
 *
 * @entries_ptr: A pointer to the buffer where found entries will be
 * stored.  The pointer must be aligned to 16 bytes.
 *
 * @entries_bytes: The size of the buffer that will contain entries.
 *
 * To start iterating set the desired target ino, dir_ino to 0, dir_pos
 * to 0, and set result_ptr and _bytes to a sufficiently large buffer.
 * Each entry struct that's stored in the buffer adds some overhead so a
 * large multiple of the largest possible name is a reasonable choice.
 * (A few multiples of PATH_MAX perhaps.)
 *
 * Each call returns the total number of entries that were stored in the
 * entries buffer.  Zero is returned when the search was successful and
 * no referring entries were found.  The entries can be iterated over by
 * advancing each starting struct offset by the total number of bytes in
 * each entry.  If the _LAST flag is set on an entry then there were no
 * more entries referring to the inode at the time of the call and
 * iteration can be stopped.
 *
 * To resume iteration set the next call's starting dir_ino and dir_pos
 * to one past the last entry seen.  Increment the last entry's dir_pos,
 * and if it wrapped to 0, increment its dir_ino.
 *
 * This does not check that the caller has permission to read the
 * entries found in each containing directory.  It requires
 * CAP_DAC_READ_SEARCH which bypasses path traversal permissions
 * checking.
 *
 * Entries returned by a single call can reflect any combination of
 * racing creation and removal of entries.  Each entry existed at the
 * time it was read though it may have changed in the time it took to
 * return from the call.  The set of entries returned may no longer
 * reflect the current set of entries and may not have existed at the
 * same time.
 *
 * This has no knowledge of the life cycle of the inode.  It can return
 * 0 when there are no referring entries because either the target inode
 * doesn't exist, it is in the process of being deleted, or because it
 * is still open while being unlinked.
 *
 * On success this returns the number of entries filled in the buffer.
 * A return of 0 indicates that no entries referred to the inode.
 *
 * EINVAL is returned when there is a problem with the buffer.  Either
 * it was not aligned or it was not large enough for the first entry.
 *
 * Many other errnos indicate hard failure to find the next entry.
 */
struct scoutfs_ioctl_get_referring_entries {
	__u64 ino;
	__u64 dir_ino;
	__u64 dir_pos;
	__u64 entries_ptr;
	__u64 entries_bytes;
};

/*
 * @dir_ino: The inode of the directory containing the entry.
 *
 * @dir_pos: The readdir f_pos position of the entry within the
 * directory.
 *
 * @ino: The inode number of the target of the entry.
 *
 * @flags: Flags associated with this entry.
 *
 * @d_type: Inode type as specified with DT_ enum values in readdir(3).
 *
 * @entry_bytes: The total bytes taken by the entry in memory, including
 * the name and any alignment padding.  The start of a following entry
 * will be found after this number of bytes.
 *
 * @name_len: The number of bytes in the name not including the trailing
 * null, ala strlen(3).
 *
 * @name: The null terminated name of the referring entry.  In the
 * struct definition this array is sized to naturally align the struct.
 * That number of padded bytes are not necessarily found in the buffer
 * returned by _get_referring_entries;
 */
struct scoutfs_ioctl_dirent {
	__u64 dir_ino;
	__u64 dir_pos;
	__u64 ino;
	__u16 entry_bytes;
	__u8  flags;
	__u8  d_type;
	__u8  name_len;
	__u8  name[3];
};

#define SCOUTFS_IOCTL_DIRENT_FLAG_LAST (1 << 0)

#define SCOUTFS_IOC_GET_REFERRING_ENTRIES \
	_IOW(SCOUTFS_IOCTL_MAGIC, 17, struct scoutfs_ioctl_get_referring_entries)

struct scoutfs_ioctl_inode_attr_x {
	__u64 x_mask;
	__u64 x_flags;
	__u64 meta_seq;
	__u64 data_seq;
	__u64 data_version;
	__u64 online_blocks;
	__u64 offline_blocks;
	__u64 ctime_sec;
	__u32 ctime_nsec;
	__u32 crtime_nsec;
	__u64 crtime_sec;
	__u64 size;
	__u64 bits;
	__u64 project_id;
};

/*
 * Behavioral flags set in the x_flags field.  These flags don't
 * necessarily correspond to specific attributes, but instead change the
 * behaviour of a _get_ or _set_ operation.
 *
 * @SCOUTFS_IOC_IAX_F_SIZE_OFFLINE: When setting i_size, also create
 * extents which are marked offline for the region of the file from
 * offset 0 to the new set size.  This can only be set when setting the
 * size and has no effect if setting the size fails.
 */
#define SCOUTFS_IOC_IAX_F_SIZE_OFFLINE	(1ULL << 0)
#define SCOUTFS_IOC_IAX_F__UNKNOWN	(U64_MAX << 1)

/*
 * Single-bit values stored in the @bits field.  These indicate whether
 * the bit is set, or not.  The main _IAX_ bits set in the mask indicate
 * whether this value bit is populated by _get or stored by _set. 
 */
#define SCOUTFS_IOC_IAX_B_RETENTION	(1ULL << 0)

/*
 * x_mask bits which indicate which attributes of the inode to populate
 * on return for _get or to set on the inode for _set.  Each mask bit
 * corresponds to the matching named field in the attr_x struct passed
 * to the _get_ and _set_ calls.
 *
 * Each field can have different permissions or other attribute
 * requirements which can cause calls to fail.  If _set_ fails then no
 * other attribute changes will have been made by the same call.
 *
 * @SCOUTFS_IOC_IAX_RETENTION: Mark a file for retention.  When marked,
 * no modification can be made to the file other than changing extended
 * attributes outside the "user." prefix and clearing the retention
 * mark.  This can only be set on regular files and requires root (the
 * CAP_SYS_ADMIN capability).  Other attributes can be set with a
 * set_attr_x call on a retention inode as long as that call also
 * successfully clears the retention mark.
 */
#define SCOUTFS_IOC_IAX_META_SEQ	(1ULL << 0)
#define SCOUTFS_IOC_IAX_DATA_SEQ	(1ULL << 1)
#define SCOUTFS_IOC_IAX_DATA_VERSION	(1ULL << 2)
#define SCOUTFS_IOC_IAX_ONLINE_BLOCKS	(1ULL << 3)
#define SCOUTFS_IOC_IAX_OFFLINE_BLOCKS	(1ULL << 4)
#define SCOUTFS_IOC_IAX_CTIME		(1ULL << 5)
#define SCOUTFS_IOC_IAX_CRTIME		(1ULL << 6)
#define SCOUTFS_IOC_IAX_SIZE		(1ULL << 7)
#define SCOUTFS_IOC_IAX_RETENTION	(1ULL << 8)
#define SCOUTFS_IOC_IAX_PROJECT_ID	(1ULL << 9)

/* single bit attributes that are packed in the bits field as _B_ */
#define SCOUTFS_IOC_IAX__BITS		(SCOUTFS_IOC_IAX_RETENTION)
/* inverse of all the bits we understand */
#define SCOUTFS_IOC_IAX__UNKNOWN	(U64_MAX << 10)

#define SCOUTFS_IOC_GET_ATTR_X \
	_IOW(SCOUTFS_IOCTL_MAGIC, 18, struct scoutfs_ioctl_inode_attr_x)

#define SCOUTFS_IOC_SET_ATTR_X \
	_IOW(SCOUTFS_IOCTL_MAGIC, 19, struct scoutfs_ioctl_inode_attr_x)

/*
 * (These fields are documented in the order that they're displayed by
 * the scoutfs cli utility which matches the sort order of the rules.)
 *
 * @prio: The priority of the rule.  Rules are sorted by their fields
 * with prio at the highest magnitude.  When multiple rules match the
 * rule with the highest sort order is enforced.  The priority field
 * lets rules override the default field sort order.
 *
 * @name_val[3]: The three 64bit values that make up the name of the
 * totl xattr whose total will be checked against the rule's limit to
 * see if the quota rule has been exceeded.  The behavior of the values
 * can be changed by their corresponding name_source and name_flags.
 *
 * @name_source[3]: The SQ_NS_ enums that control where the value comes
 * from.  _LITERAL uses the value from name_val.  Inode attribute
 * sources (_PROJ, _UID, _GID) are taken from the inode of the operation
 * that is being checked against the rule.
 *
 * @name_flags[3]: The SQ_NF_ enums that alter the name values.  _SELECT
 * makes the rule only match if the inode attribute of the operation
 * matches the attribute value stored in name_val.  This lets rules
 * match a specific value of an attribute rather than mapping all
 * attribute values of to totl names.
 *
 * @op: The SQ_OP_ enums which specify the operation that can't exceed
 * the rule's limit.  _INODE checks inode creation and the inode
 * attributes are taken from the inode that would be created.  _DATA
 * checks file data block allocation and the inode fields come from the
 * inode that is allocating the blocks.
 *
 * @limit: The 64bit value that is checked against the totl value
 * described by the rule.  If the totl value is greater than or equal to
 * this value of the matching rule then the operation will return
 * -EDQUOT.
 *
 * @rule_flags: SQ_RF_TOTL_COUNT indicates that the rule's limit should
 * be checked against the number of xattrs contributing to a totl value
 * instead of the sum of the xattrs.
 */
struct scoutfs_ioctl_quota_rule {
	__u64 name_val[3];
	__u64 limit;
	__u8 prio;
	__u8 op;
	__u8 rule_flags;
	__u8 name_source[3];
	__u8 name_flags[3];
	__u8 _pad[7];
};

struct scoutfs_ioctl_get_quota_rules {
	__u64 iterator[2];
	__u64 rules_ptr;
	__u64 rules_nr;
};

/*
 * Rules are uniquely identified by their non-padded fields.  Addition will fail
 * with -EEXIST if the specified rule already exists and deletion must find a rule
 * with all matching fields to delete.
 */
#define SCOUTFS_IOC_GET_QUOTA_RULES \
	_IOR(SCOUTFS_IOCTL_MAGIC, 20, struct scoutfs_ioctl_get_quota_rules)
#define SCOUTFS_IOC_ADD_QUOTA_RULE \
	_IOW(SCOUTFS_IOCTL_MAGIC, 21, struct scoutfs_ioctl_quota_rule)
#define SCOUTFS_IOC_DEL_QUOTA_RULE \
	_IOW(SCOUTFS_IOCTL_MAGIC, 22, struct scoutfs_ioctl_quota_rule)

/*
 * Inodes can be indexed in a global key space at a position determined
 * by a .indx. tagged xattr.  The xattr name specifies the two index
 * position values, with major having the more significant comparison
 * order.
 */
struct scoutfs_ioctl_xattr_index_entry {
	__u64 minor;
	__u64 ino;
	__u8 major;
	__u8 _pad[7];
};

struct scoutfs_ioctl_read_xattr_index {
	__u64 flags;
	struct scoutfs_ioctl_xattr_index_entry first;
	struct scoutfs_ioctl_xattr_index_entry last;
	__u64 entries_ptr;
	__u64 entries_nr;
};

#define SCOUTFS_IOC_READ_XATTR_INDEX \
	_IOR(SCOUTFS_IOCTL_MAGIC, 23, struct scoutfs_ioctl_read_xattr_index)

#endif
