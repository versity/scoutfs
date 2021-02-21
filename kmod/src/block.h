#ifndef _SCOUTFS_BLOCK_H_
#define _SCOUTFS_BLOCK_H_

struct scoutfs_block_writer {
	spinlock_t lock;
	struct list_head dirty_list;
	u64 nr_dirty_blocks;
};

struct scoutfs_block {
	u64 blkno;
	void *data;
	void *priv;
};

struct scoutfs_block *scoutfs_block_create(struct super_block *sb, u64 blkno);
int scoutfs_block_read_ref(struct super_block *sb, struct scoutfs_block_ref *ref, u32 magic,
			   struct scoutfs_block **bl_ret);
void scoutfs_block_put(struct super_block *sb, struct scoutfs_block *bl);

void scoutfs_block_writer_init(struct super_block *sb,
			       struct scoutfs_block_writer *wri);
int scoutfs_block_dirty_ref(struct super_block *sb, struct scoutfs_alloc *alloc,
			    struct scoutfs_block_writer *wri, struct scoutfs_block_ref *ref,
			    u32 magic, struct scoutfs_block **bl_ret,
			    u64 dirty_blkno, u64 *ref_blkno);
int scoutfs_block_writer_write(struct super_block *sb,
			       struct scoutfs_block_writer *wri);
void scoutfs_block_writer_forget_all(struct super_block *sb,
				     struct scoutfs_block_writer *wri);
void scoutfs_block_writer_forget(struct super_block *sb,
			         struct scoutfs_block_writer *wri,
				 struct scoutfs_block *bl);
bool scoutfs_block_writer_has_dirty(struct super_block *sb,
				    struct scoutfs_block_writer *wri);
u64 scoutfs_block_writer_dirty_bytes(struct super_block *sb,
				     struct scoutfs_block_writer *wri);

int scoutfs_block_read_sm(struct super_block *sb,
			  struct block_device *bdev, u64 blkno,
			  struct scoutfs_block_header *hdr, size_t len,
			  __le32 *blk_crc);
int scoutfs_block_write_sm(struct super_block *sb,
			   struct block_device *bdev, u64 blkno,
			   struct scoutfs_block_header *hdr, size_t len);

int scoutfs_block_setup(struct super_block *sb);
void scoutfs_block_destroy(struct super_block *sb);

#endif
