#ifndef _SCOUTFS_KERNELCOMPAT_H_
#define _SCOUTFS_KERNELCOMPAT_H_

#ifndef KC_ITERATE_DIR_CONTEXT
#include <linux/fs.h>
typedef filldir_t kc_readdir_ctx_t;
#define KC_DECLARE_READDIR(name, file, dirent, ctx) name(file, dirent, ctx)
#define KC_FOP_READDIR readdir
#define kc_readdir_pos(filp, ctx) (filp)->f_pos
#define kc_dir_emit_dots(file, dirent, ctx) dir_emit_dots(file, dirent, ctx)
#define kc_dir_emit(ctx, dirent, name, name_len, pos, ino, dt) \
	(ctx(dirent, name, name_len, pos, ino, dt) == 0)
#else
typedef struct dir_context * kc_readdir_ctx_t;
#define KC_DECLARE_READDIR(name, file, dirent, ctx) name(file, ctx)
#define KC_FOP_READDIR iterate
#define kc_readdir_pos(filp, ctx) (ctx)->pos
#define kc_dir_emit_dots(file, dirent, ctx) dir_emit_dots(file, ctx)
#define kc_dir_emit(ctx, dirent, name, name_len, pos, ino, dt) \
	dir_emit(ctx, name, name_len, ino, dt)
#endif

#ifndef KC_DIR_EMIT_DOTS
/*
 * Kernels before ->iterate and don't have dir_emit_dots so we give them
 * one that works with the ->readdir() filldir() method.
 */
static inline int dir_emit_dots(struct file *file, void *dirent,
				filldir_t filldir)
{
	if (file->f_pos == 0) {
		if (filldir(dirent, ".", 1, 1,
			    file->f_path.dentry->d_inode->i_ino, DT_DIR))
			return 0;
		file->f_pos = 1;
	}

	if (file->f_pos == 1) {
		if (filldir(dirent, "..", 2, 1,
			    parent_ino(file->f_path.dentry), DT_DIR))
			return 0;
		file->f_pos = 2;
	}

	return 1;
}
#endif

#ifndef KC_DIR_EMIT_DOTS
#define percpu_counter_add_batch __percpu_counter_add
#endif

#ifndef KC_MEMALLOC_NOFS_SAVE
#define memalloc_nofs_save memalloc_noio_save
#define memalloc_nofs_restore memalloc_noio_restore
#endif

#ifdef KC_BIO_BI_OPF
#define kc_bio_get_opf(bio)		\
({					\
	(bio)->bi_opf;			\
})
#define kc_bio_set_opf(bio, opf)	\
do {					\
	(bio)->bi_opf = opf;		\
} while (0)
#define kc_bio_set_sector(bio, sect)	\
do {					\
	(bio)->bi_iter.bi_sector = sect;\
} while (0)
#else
#define kc_bio_get_opf(bio)		\
({					\
	(bio)->bi_rw;			\
})
#define kc_bio_set_opf(bio, opf)	\
do {					\
	(bio)->bio_rw = opf;		\
} while (0)
#define kc_bio_set_sector(bio, sect)	\
do {					\
	(bio)->bi_sector = sect;	\
} while (0)
#endif

#ifdef KC_BIO_BI_STATUS
#define KC_DECLARE_BIO_END_IO(name, bio)	name(bio)
#define kc_bio_get_errno(bio)			({ blk_status_to_errno((bio)->bi_status); })
#else
#define KC_DECLARE_BIO_END_IO(name, bio)	name(bio, int _error_arg)
#define kc_bio_get_errno(bio)			({ (int)((void)(bio), _error_arg); })
#endif

#endif
