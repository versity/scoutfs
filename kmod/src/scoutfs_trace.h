/*
 * Copyright (C) 2016 Versity Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
/*
 * This has a crazy name because it's in an external module build at
 * the moment.  When it's merged upstream it'll move to
 * include/trace/events/scoutfs.h
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM scoutfs

#if !defined(_TRACE_SCOUTFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SCOUTFS_H

#include <linux/tracepoint.h>
#include <linux/in.h>

#include "key.h"
#include "format.h"
#include "lock.h"
#include "super.h"
#include "ioctl.h"
#include "export.h"
#include "dir.h"
#include "server.h"
#include "net.h"
#include "data.h"
#include "ext.h"
#include "quota.h"

#include "trace/quota.h"
#include "trace/wkic.h"

struct lock_info;

#define STE_FMT "[%llu %llu %llu 0x%x]"
#define STE_ARGS(te) (te)->start, (te)->len, (te)->map, (te)->flags
#define STE_FIELDS(pref)			\
	__field(__u64, pref##_start)		\
	__field(__u64, pref##_len)		\
	__field(__u64, pref##_map)		\
	__field(__u8, pref##_flags)
#define STE_ASSIGN(pref, te)			\
	__entry->pref##_start = (te)->start;	\
	__entry->pref##_len = (te)->len;	\
	__entry->pref##_map = (te)->map;	\
	__entry->pref##_flags = (te)->flags;
#define STE_ENTRY_ARGS(pref)			\
	__entry->pref##_start,			\
	__entry->pref##_len,			\
	__entry->pref##_map,			\
	__entry->pref##_flags

DECLARE_EVENT_CLASS(scoutfs_ino_ret_class,
	TP_PROTO(struct super_block *sb, u64 ino, int ret),

	TP_ARGS(sb, ino, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->ret)
);

TRACE_EVENT(scoutfs_setattr,
	TP_PROTO(struct dentry *dentry, struct iattr *attr),

	TP_ARGS(dentry, attr),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, d_len)
		__string(d_name, dentry->d_name.name)
		__field(__u64, i_size)
		__field(__u64, ia_size)
		__field(unsigned int, ia_valid)
		__field(int, size_change)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(dentry->d_inode->i_sb);
		__entry->ino = scoutfs_ino(dentry->d_inode);
		__entry->d_len = dentry->d_name.len;
		__assign_str(d_name, dentry->d_name.name);
		__entry->ia_valid = attr->ia_valid;
		__entry->size_change = !!(attr->ia_valid & ATTR_SIZE);
		__entry->ia_size = attr->ia_size;
		__entry->i_size = i_size_read(dentry->d_inode);
	),

	TP_printk(SCSBF" %s ino %llu ia_valid 0x%x size change %d ia_size "
		  "%llu i_size %llu", SCSB_TRACE_ARGS, __get_str(d_name),
		  __entry->ino, __entry->ia_valid, __entry->size_change,
		  __entry->ia_size, __entry->i_size)
);

TRACE_EVENT(scoutfs_complete_truncate,
	TP_PROTO(struct inode *inode, __u32 flags),

	TP_ARGS(inode, flags),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, i_size)
		__field(__u32, flags)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(inode->i_sb);
		__entry->ino = scoutfs_ino(inode);
		__entry->i_size = i_size_read(inode);
		__entry->flags = flags;
	),

	TP_printk(SCSBF" ino %llu i_size %llu flags 0x%x",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->i_size,
		  __entry->flags)
);

TRACE_EVENT(scoutfs_data_fallocate,
	TP_PROTO(struct super_block *sb, u64 ino, int mode, loff_t offset,
		 loff_t len, int ret),

	TP_ARGS(sb, ino, mode, offset, len, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, mode)
		__field(__u64, offset)
		__field(__u64, len)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->mode = mode;
		__entry->offset = offset;
		__entry->len = len;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu mode 0x%x offset %llu len %llu ret %d",
		SCSB_TRACE_ARGS, __entry->ino, __entry->mode, __entry->offset,
		__entry->len, __entry->ret)
);

TRACE_EVENT(scoutfs_data_move_blocks,
	TP_PROTO(struct super_block *sb, u64 from_ino, u64 from_start, u64 len,
		 u64 map, u8 flags, u64 to_ino, u64 to_start),

	TP_ARGS(sb, from_ino, from_start, len, map, flags, to_ino, to_start),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, from_ino)
		__field(__u64, from_start)
		__field(__u64, len)
		__field(__u64, map)
		__field(__u8, flags)
		__field(__u64, to_ino)
		__field(__u64, to_start)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->from_ino = from_ino;
		__entry->from_start = from_start;
		__entry->len = len;
		__entry->map = map;
		__entry->flags = flags;
		__entry->to_ino = to_ino;
		__entry->to_start = to_start;
	),

	TP_printk(SCSBF" from_ino %llu from_start %llu len %llu map %llu flags 0x%x to_ino %llu to_start %llu\n",
		SCSB_TRACE_ARGS, __entry->from_ino, __entry->from_start,
		__entry->len, __entry->map, __entry->flags, __entry->to_ino,
		__entry->to_start)
);

TRACE_EVENT(scoutfs_data_fiemap,
	TP_PROTO(struct super_block *sb, __u64 start, __u64 len, int ret),


	TP_ARGS(sb, start, len, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, start)
		__field(__u64, len)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->start = start;
		__entry->len = len;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" start %llu len %llu ret %d", SCSB_TRACE_ARGS,
		  __entry->start, __entry->len, __entry->ret)
);

TRACE_EVENT(scoutfs_get_block,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 iblock,
		 int create, struct scoutfs_extent *ext,
		 int ret, __u64 blkno, size_t size),

	TP_ARGS(sb, ino, iblock, create, ext, ret, blkno, size),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, iblock)
		__field(int, create)
		STE_FIELDS(ext)
		__field(int, ret)
		__field(__u64, blkno)
		__field(size_t, size)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->iblock = iblock;
		__entry->create = create;
		STE_ASSIGN(ext, ext)
		__entry->ret = ret;
		__entry->blkno = blkno;
		__entry->size = size;
	),

	TP_printk(SCSBF" ino %llu iblock %llu create %d ext "STE_FMT" ret %d bnr %llu size %zu",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->iblock,
		  __entry->create, STE_ENTRY_ARGS(ext), __entry->ret,
		  __entry->blkno, __entry->size)
);

TRACE_EVENT(scoutfs_data_alloc_block_enter,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 iblock,
		 struct scoutfs_extent *ext),

	TP_ARGS(sb, ino, iblock, ext),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, iblock)
		STE_FIELDS(ext)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->iblock = iblock;
		STE_ASSIGN(ext, ext)
	),

	TP_printk(SCSBF" ino %llu iblock %llu ext "STE_FMT,
		  SCSB_TRACE_ARGS, __entry->ino, __entry->iblock,
		  STE_ENTRY_ARGS(ext))
);

TRACE_EVENT(scoutfs_data_page_mkwrite,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 pos, __u32 ret),

	TP_ARGS(sb, ino, pos, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, pos)
		__field(__u32, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->pos = pos;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu pos %llu ret %u ",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->pos, __entry->ret)
);

TRACE_EVENT(scoutfs_data_filemap_fault,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 pos, __u32 ret),

	TP_ARGS(sb, ino, pos, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, pos)
		__field(__u32, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->pos = pos;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu pos %llu ret %u ",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->pos, __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_data_file_extent_class,
	TP_PROTO(struct super_block *sb, __u64 ino, struct scoutfs_extent *ext),

	TP_ARGS(sb, ino, ext),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		STE_FIELDS(ext)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		STE_ASSIGN(ext, ext)
	),

	TP_printk(SCSBF" ino %llu ext "STE_FMT,
		  SCSB_TRACE_ARGS, __entry->ino, STE_ENTRY_ARGS(ext))
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_alloc,
	TP_PROTO(struct super_block *sb, __u64 ino, struct scoutfs_extent *ext),
	TP_ARGS(sb, ino, ext)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_prealloc,
	TP_PROTO(struct super_block *sb, __u64 ino, struct scoutfs_extent *ext),
	TP_ARGS(sb, ino, ext)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_get_block_found,
	TP_PROTO(struct super_block *sb, __u64 ino, struct scoutfs_extent *ext),
	TP_ARGS(sb, ino, ext)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_get_block_mapped,
	TP_PROTO(struct super_block *sb, __u64 ino, struct scoutfs_extent *ext),
	TP_ARGS(sb, ino, ext)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_extent_truncated,
	TP_PROTO(struct super_block *sb, __u64 ino, struct scoutfs_extent *ext),
	TP_ARGS(sb, ino, ext)
);
DEFINE_EVENT(scoutfs_data_file_extent_class, scoutfs_data_fiemap_extent,
	TP_PROTO(struct super_block *sb, __u64 ino, struct scoutfs_extent *ext),
	TP_ARGS(sb, ino, ext)
);

TRACE_EVENT(scoutfs_data_truncate_items,
	TP_PROTO(struct super_block *sb, __u64 iblock, __u64 last, int offline),

	TP_ARGS(sb, iblock, last, offline),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, iblock)
		__field(__u64, last)
		__field(int, offline)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->iblock = iblock;
		__entry->last = last;
		__entry->offline = offline;
	),

	TP_printk(SCSBF" iblock %llu last %llu offline %u", SCSB_TRACE_ARGS,
		  __entry->iblock, __entry->last, __entry->offline)
);

TRACE_EVENT(scoutfs_data_wait_check,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 pos, __u64 len,
		 __u8 sef, __u8 op, struct scoutfs_extent *ext, int ret),

	TP_ARGS(sb, ino, pos, len, sef, op, ext, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, pos)
		__field(__u64, len)
		__field(__u8, sef)
		__field(__u8, op)
		STE_FIELDS(ext)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->pos = pos;
		__entry->len = len;
		__entry->sef = sef;
		__entry->op = op;
		STE_ASSIGN(ext, ext)
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu pos %llu len %llu sef 0x%x op 0x%x ext "STE_FMT" ret %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->pos, __entry->len,
		  __entry->sef, __entry->op, STE_ENTRY_ARGS(ext), __entry->ret)
);

TRACE_EVENT(scoutfs_sync_fs,
	TP_PROTO(struct super_block *sb, int wait),

	TP_ARGS(sb, wait),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, wait)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->wait = wait;
	),

	TP_printk(SCSBF" wait %d", SCSB_TRACE_ARGS, __entry->wait)
);

TRACE_EVENT(scoutfs_trans_write_func,
	TP_PROTO(struct super_block *sb, u64 dirty_block_bytes, u64 dirty_item_pages),

	TP_ARGS(sb, dirty_block_bytes, dirty_item_pages),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, dirty_block_bytes)
		__field(__u64, dirty_item_pages)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->dirty_block_bytes = dirty_block_bytes;
		__entry->dirty_item_pages = dirty_item_pages;
	),

	TP_printk(SCSBF" dirty_block_bytes %llu dirty_item_pages %llu",
		  SCSB_TRACE_ARGS, __entry->dirty_block_bytes, __entry->dirty_item_pages)
);

DECLARE_EVENT_CLASS(scoutfs_trans_hold_release_class,
	TP_PROTO(struct super_block *sb, void *journal_info, int holders, int ret),

	TP_ARGS(sb, journal_info, holders, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(unsigned long, journal_info)
		__field(int, holders)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->journal_info = (unsigned long)journal_info;
		__entry->holders = holders;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" journal_info 0x%0lx holders %d ret %d",
		  SCSB_TRACE_ARGS, __entry->journal_info, __entry->holders, __entry->ret)
);

DEFINE_EVENT(scoutfs_trans_hold_release_class, scoutfs_hold_trans,
	TP_PROTO(struct super_block *sb, void *journal_info, int holders, int ret),
	TP_ARGS(sb, journal_info, holders, ret)
);
DEFINE_EVENT(scoutfs_trans_hold_release_class, scoutfs_release_trans,
	TP_PROTO(struct super_block *sb, void *journal_info, int holders, int ret),
	TP_ARGS(sb, journal_info, holders, ret)
);

TRACE_EVENT(scoutfs_ioc_release,
	TP_PROTO(struct super_block *sb, u64 ino,
		 struct scoutfs_ioctl_release *args),

	TP_ARGS(sb, ino, args),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, offset)
		__field(__u64, length)
		__field(__u64, vers)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->offset = args->offset;
		__entry->length = args->length;
		__entry->vers = args->data_version;
	),

	TP_printk(SCSBF" ino %llu offset %llu length %llu vers %llu",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->offset,
		  __entry->length, __entry->vers)
);

DEFINE_EVENT(scoutfs_ino_ret_class, scoutfs_ioc_release_ret,
	TP_PROTO(struct super_block *sb, u64 ino, int ret),
	TP_ARGS(sb, ino, ret)
);

TRACE_EVENT(scoutfs_ioc_stage,
	TP_PROTO(struct super_block *sb, u64 ino,
		 struct scoutfs_ioctl_stage *args),

	TP_ARGS(sb, ino, args),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, vers)
		__field(__u64, offset)
		__field(__s32, length)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->vers = args->data_version;
		__entry->offset = args->offset;
		__entry->length = args->length;
	),

	TP_printk(SCSBF" ino %llu vers %llu offset %llu length %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->vers,
		  __entry->offset, __entry->length)
);

TRACE_EVENT(scoutfs_ioc_data_wait_err,
	TP_PROTO(struct super_block *sb,
		 struct scoutfs_ioctl_data_wait_err *args),

	TP_ARGS(sb, args),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, vers)
		__field(__u64, offset)
		__field(__u64, count)
		__field(__u64, op)
		__field(__s64, err)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = args->ino;
		__entry->vers = args->data_version;
		__entry->offset = args->offset;
		__entry->count = args->count;
		__entry->op = args->op;
		__entry->err = args->err;
	),

	TP_printk(SCSBF" ino %llu vers %llu offset %llu count %llu op %llx err %lld",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->vers,
		  __entry->offset, __entry->count, __entry->op, __entry->err)
);

DEFINE_EVENT(scoutfs_ino_ret_class, scoutfs_ioc_stage_ret,
	TP_PROTO(struct super_block *sb, u64 ino, int ret),
	TP_ARGS(sb, ino, ret)
);

TRACE_EVENT(scoutfs_ioc_walk_inodes,
	TP_PROTO(struct super_block *sb, struct scoutfs_ioctl_walk_inodes *walk),

	TP_ARGS(sb, walk),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, index)
		__field(__u64, first_major)
		__field(__u32, first_minor)
		__field(__u64, first_ino)
		__field(__u64, last_major)
		__field(__u32, last_minor)
		__field(__u64, last_ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->index = walk->index;
		__entry->first_major = walk->first.major;
		__entry->first_minor = walk->first.minor;
		__entry->first_ino = walk->first.ino;
		__entry->last_major = walk->last.major;
		__entry->last_minor = walk->last.minor;
		__entry->last_ino = walk->last.ino;
	),

	TP_printk(SCSBF" index %u first %llu.%u.%llu last %llu.%u.%llu",
		  SCSB_TRACE_ARGS, __entry->index, __entry->first_major,
		  __entry->first_minor, __entry->first_ino, __entry->last_major,
		  __entry->last_minor, __entry->last_ino)
);

TRACE_EVENT(scoutfs_i_callback,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(struct inode *, inode)
	),

	TP_fast_assign(
		__entry->inode = inode;
	),

	/* don't print fsid as we may not have our sb private available */
	TP_printk("freeing inode %p", __entry->inode)
);

DECLARE_EVENT_CLASS(scoutfs_index_item_class,
	TP_PROTO(struct super_block *sb, __u8 type, __u64 major, __u32 minor,
		 __u64 ino),

	TP_ARGS(sb, type, major, minor, ino),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u8, type)
		__field(__u64, major)
		__field(__u32, minor)
		__field(__u64, ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->type = type;
		__entry->major = major;
		__entry->minor = minor;
		__entry->ino = ino;
	),

	TP_printk(SCSBF" type %u major %llu minor %u ino %llu",
		  SCSB_TRACE_ARGS, __entry->type, __entry->major,
		  __entry->minor, __entry->ino)
);

DEFINE_EVENT(scoutfs_index_item_class, scoutfs_create_index_item,
	TP_PROTO(struct super_block *sb, __u8 type, __u64 major, __u32 minor,
		 __u64 ino),
	TP_ARGS(sb, type, major, minor, ino)
);

DEFINE_EVENT(scoutfs_index_item_class, scoutfs_delete_index_item,
	TP_PROTO(struct super_block *sb, __u8 type, __u64 major, __u32 minor,
		 __u64 ino),
	TP_ARGS(sb, type, major, minor, ino)
);

TRACE_EVENT(scoutfs_alloc_ino,
	TP_PROTO(struct super_block *sb, int ret, __u64 ino, __u64 next_ino,
		 __u64 next_nr),

	TP_ARGS(sb, ret, ino, next_ino, next_nr),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, ret)
		__field(__u64, ino)
		__field(__u64, next_ino)
		__field(__u64, next_nr)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ret = ret;
		__entry->ino = ino;
		__entry->next_ino = next_ino;
		__entry->next_nr = next_nr;
	),

	TP_printk(SCSBF" ret %d ino %llu next_ino %llu next_nr %llu",
		  SCSB_TRACE_ARGS, __entry->ret, __entry->ino,
		  __entry->next_ino, __entry->next_nr)
);

TRACE_EVENT(scoutfs_evict_inode,
	TP_PROTO(struct super_block *sb, __u64 ino, unsigned int nlink,
		 unsigned int is_bad_ino),

	TP_ARGS(sb, ino, nlink, is_bad_ino),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, nlink)
		__field(unsigned int, is_bad_ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
		__entry->is_bad_ino = is_bad_ino;
	),

	TP_printk(SCSBF" ino %llu nlink %u bad %d", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->nlink, __entry->is_bad_ino)
);

TRACE_EVENT(scoutfs_drop_inode,
	TP_PROTO(struct super_block *sb, __u64 ino, unsigned int nlink,
		 unsigned int unhashed, bool lock_covered),

	TP_ARGS(sb, ino, nlink, unhashed, lock_covered),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, nlink)
		__field(unsigned int, unhashed)
		__field(unsigned int, lock_covered)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
		__entry->unhashed = unhashed;
		__entry->lock_covered = !!lock_covered;
	),

	TP_printk(SCSBF" ino %llu nlink %u unhashed %d lock_covered %u", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->nlink, __entry->unhashed,
		  __entry->lock_covered)
);

TRACE_EVENT(scoutfs_inode_walk_writeback,
	TP_PROTO(struct super_block *sb, __u64 ino, int write, int ret),

	TP_ARGS(sb, ino, write, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, write)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->write = write;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu write %d ret %d", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->write, __entry->ret)
);

TRACE_EVENT(scoutfs_orphan_scan_start,
	TP_PROTO(struct super_block *sb),

	TP_ARGS(sb),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
	),

	TP_printk(SCSBF, SCSB_TRACE_ARGS)
);

TRACE_EVENT(scoutfs_orphan_scan_stop,
	TP_PROTO(struct super_block *sb, bool work_todo),

	TP_ARGS(sb, work_todo),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(bool, work_todo)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->work_todo = work_todo;
	),

	TP_printk(SCSBF" work_todo %d", SCSB_TRACE_ARGS, __entry->work_todo)
);

TRACE_EVENT(scoutfs_orphan_scan_work,
	TP_PROTO(struct super_block *sb, __u64 ino),

	TP_ARGS(sb, ino),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
	),

	TP_printk(SCSBF" ino %llu", SCSB_TRACE_ARGS,
		  __entry->ino)
);

TRACE_EVENT(scoutfs_orphan_scan_end,
	TP_PROTO(struct super_block *sb, __u64 ino, int ret),

	TP_ARGS(sb, ino, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu ret %d", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_lock_info_class,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),

	TP_ARGS(sb, linfo),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(struct lock_info *, linfo)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->linfo = linfo;
	),

	TP_printk(SCSBF" linfo %p", SCSB_TRACE_ARGS, __entry->linfo)
);

DEFINE_EVENT(scoutfs_lock_info_class, scoutfs_lock_setup,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),
	TP_ARGS(sb, linfo)
);

DEFINE_EVENT(scoutfs_lock_info_class, scoutfs_lock_shutdown,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),
	TP_ARGS(sb, linfo)
);

DEFINE_EVENT(scoutfs_lock_info_class, scoutfs_lock_destroy,
	TP_PROTO(struct super_block *sb, struct lock_info *linfo),
	TP_ARGS(sb, linfo)
);

TRACE_EVENT(scoutfs_xattr_set,
	TP_PROTO(struct super_block *sb, __u64 ino, size_t name_len,
		 const void *value, size_t size, int flags),

	TP_ARGS(sb, ino, name_len, value, size, flags),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(size_t, name_len)
		__field(const void *, value)
		__field(size_t, size)
		__field(int, flags)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->name_len = name_len;
		__entry->value = value;
		__entry->size = size;
		__entry->flags = flags;
	),

	TP_printk(SCSBF" ino %llu name_len %zu value %p size %zu flags 0x%x",
		  SCSB_TRACE_ARGS, __entry->ino,  __entry->name_len,
		  __entry->value, __entry->size, __entry->flags)
);

TRACE_EVENT(scoutfs_advance_dirty_super,
	TP_PROTO(struct super_block *sb, __u64 seq),

	TP_ARGS(sb, seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->seq = seq;
	),

	TP_printk(SCSBF" super seq now %llu", SCSB_TRACE_ARGS, __entry->seq)
);

TRACE_EVENT(scoutfs_dir_add_next_linkref_found,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 dir_ino,
		 __u64 dir_pos, unsigned int name_len),

	TP_ARGS(sb, ino, dir_ino, dir_pos, name_len),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, dir_ino)
		__field(__u64, dir_pos)
		__field(unsigned int, name_len)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->dir_ino = dir_ino;
		__entry->dir_pos = dir_pos;
		__entry->name_len = name_len;
	),

	TP_printk(SCSBF" ino %llu dir_ino %llu dir_pos %llu name_len %u",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->dir_ino,
		  __entry->dir_pos, __entry->name_len)
);

TRACE_EVENT(scoutfs_dir_add_next_linkrefs,
	TP_PROTO(struct super_block *sb, __u64 ino, __u64 dir_ino,
		 __u64 dir_pos, int count, int nr, int ret),

	TP_ARGS(sb, ino, dir_ino, dir_pos, count, nr, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, dir_ino)
		__field(__u64, dir_pos)
		__field(int, count)
		__field(int, nr)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->dir_ino = dir_ino;
		__entry->dir_pos = dir_pos;
		__entry->count = count;
		__entry->nr = nr;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu dir_ino %llu dir_pos %llu count %d nr %d ret %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->dir_ino,
		  __entry->dir_pos, __entry->count, __entry->nr, __entry->ret)
);

TRACE_EVENT(scoutfs_write_begin,
	TP_PROTO(struct super_block *sb, u64 ino, loff_t pos, unsigned len),

	TP_ARGS(sb, ino, pos, len),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, inode)
		__field(__u64, pos)
		__field(__u32, len)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->inode = ino;
		__entry->pos = pos;
		__entry->len = len;
	),

	TP_printk(SCSBF" ino %llu pos %llu len %u", SCSB_TRACE_ARGS,
		  __entry->inode, __entry->pos, __entry->len)
);

TRACE_EVENT(scoutfs_write_end,
	TP_PROTO(struct super_block *sb, u64 ino, unsigned long idx, u64 pos,
		 unsigned len, unsigned copied),

	TP_ARGS(sb, ino, idx, pos, len, copied),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned long, idx)
		__field(__u64, pos)
		__field(__u32, len)
		__field(__u32, copied)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->idx = idx;
		__entry->pos = pos;
		__entry->len = len;
		__entry->copied = copied;
	),

	TP_printk(SCSBF" ino %llu pgind %lu pos %llu len %u copied %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->idx, __entry->pos,
		  __entry->len, __entry->copied)
);

TRACE_EVENT(scoutfs_dirty_inode,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(__u64, ino)
		__field(__u64, size)
	),

	TP_fast_assign(
		__entry->ino = scoutfs_ino(inode);
		__entry->size = inode->i_size;
	),

	TP_printk("ino %llu size %llu",
		__entry->ino, __entry->size)
);

TRACE_EVENT(scoutfs_update_inode,
	TP_PROTO(struct inode *inode),

	TP_ARGS(inode),

	TP_STRUCT__entry(
		__field(__u64, ino)
		__field(__u64, size)
	),

	TP_fast_assign(
		__entry->ino = scoutfs_ino(inode);
		__entry->size = inode->i_size;
	),

	TP_printk("ino %llu size %llu",
		__entry->ino, __entry->size)
);

TRACE_EVENT(scoutfs_orphan_inode,
	TP_PROTO(struct super_block *sb, struct inode *inode),

	TP_ARGS(sb, inode),

	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(__u64, ino)
	),

	TP_fast_assign(
		__entry->dev = sb->s_dev;
		__entry->ino = scoutfs_ino(inode);
	),

	TP_printk("dev %d,%d ino %llu", MAJOR(__entry->dev),
		  MINOR(__entry->dev), __entry->ino)
);

DECLARE_EVENT_CLASS(scoutfs_try_delete_class,
        TP_PROTO(struct super_block *sb, u64 ino),
        TP_ARGS(sb, ino),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
        ),
	TP_printk(SCSBF" ino %llu", SCSB_TRACE_ARGS, __entry->ino)
);

DEFINE_EVENT(scoutfs_try_delete_class, scoutfs_try_delete,
        TP_PROTO(struct super_block *sb, u64 ino),
        TP_ARGS(sb, ino)
);

DEFINE_EVENT(scoutfs_try_delete_class, scoutfs_try_delete_local_busy,
        TP_PROTO(struct super_block *sb, u64 ino),
        TP_ARGS(sb, ino)
);

DEFINE_EVENT(scoutfs_try_delete_class, scoutfs_try_delete_cached,
        TP_PROTO(struct super_block *sb, u64 ino),
        TP_ARGS(sb, ino)
);

DEFINE_EVENT(scoutfs_try_delete_class, scoutfs_try_delete_no_item,
        TP_PROTO(struct super_block *sb, u64 ino),
        TP_ARGS(sb, ino)
);

TRACE_EVENT(scoutfs_try_delete_has_links,
	TP_PROTO(struct super_block *sb, u64 ino, unsigned int nlink),

	TP_ARGS(sb, ino, nlink),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, nlink)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
	),

	TP_printk(SCSBF" ino %llu nlink %u", SCSB_TRACE_ARGS, __entry->ino,
		  __entry->nlink)
);

TRACE_EVENT(scoutfs_inode_orphan_delete,
	TP_PROTO(struct super_block *sb, u64 ino, int ret),

	TP_ARGS(sb, ino, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu ret %d", SCSB_TRACE_ARGS, __entry->ino,
		__entry->ret)
);

TRACE_EVENT(scoutfs_delete_inode,
	TP_PROTO(struct super_block *sb, u64 ino, umode_t mode, u64 size),

	TP_ARGS(sb, ino, mode, size),

	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(__u64, ino)
		__field(umode_t, mode)
		__field(__u64, size)
	),

	TP_fast_assign(
		__entry->dev = sb->s_dev;
		__entry->ino = ino;
		__entry->mode = mode;
		__entry->size = size;
	),

	TP_printk("dev %d,%d ino %llu, mode 0x%x size %llu",
		  MAJOR(__entry->dev), MINOR(__entry->dev), __entry->ino,
		  __entry->mode, __entry->size)
);

TRACE_EVENT(scoutfs_delete_inode_end,
	TP_PROTO(struct super_block *sb, u64 ino, umode_t mode, u64 size, int ret),

	TP_ARGS(sb, ino, mode, size, ret),

	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(__u64, ino)
		__field(umode_t, mode)
		__field(__u64, size)
		__field(int, ret)
	),

	TP_fast_assign(
		__entry->dev = sb->s_dev;
		__entry->ino = ino;
		__entry->mode = mode;
		__entry->size = size;
		__entry->ret = ret;
	),

	TP_printk("dev %d,%d ino %llu, mode 0x%x size %llu, ret %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev), __entry->ino,
		  __entry->mode, __entry->size, __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_key_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
        ),
	TP_printk(SCSBF" key "SK_FMT, SCSB_TRACE_ARGS, sk_trace_args(key))
);

DEFINE_EVENT(scoutfs_key_class, scoutfs_xattr_get_next_key,
        TP_PROTO(struct super_block *sb, struct scoutfs_key *key),
        TP_ARGS(sb, key)
);

#define lock_mode(mode)						\
	__print_symbolic(mode,					\
		{ SCOUTFS_LOCK_NULL,		"NULL" },	\
		{ SCOUTFS_LOCK_READ,		"READ" },	\
		{ SCOUTFS_LOCK_WRITE,		"WRITE" },	\
		{ SCOUTFS_LOCK_WRITE_ONLY,	"WRITE_ONLY" })

DECLARE_EVENT_CLASS(scoutfs_lock_class,
        TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
        TP_ARGS(sb, lck),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(start)
		sk_trace_define(end)
		__field(u64, refresh_gen)
		__field(u64, write_seq)
		__field(u64, dirty_trans_seq)
		__field(unsigned char, request_pending)
		__field(unsigned char, invalidate_pending)
		__field(int, mode)
		__field(int, invalidating_mode)
		__field(unsigned int, waiters_cw)
		__field(unsigned int, waiters_pr)
		__field(unsigned int, waiters_ex)
		__field(unsigned int, users_cw)
		__field(unsigned int, users_pr)
		__field(unsigned int, users_ex)
	),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(start, &lck->start);
		sk_trace_assign(end, &lck->end);
		__entry->refresh_gen = lck->refresh_gen;
		__entry->write_seq = lck->write_seq;
		__entry->dirty_trans_seq = lck->dirty_trans_seq;
		__entry->request_pending = lck->request_pending;
		__entry->invalidate_pending = lck->invalidate_pending;
		__entry->mode = lck->mode;
		__entry->invalidating_mode = lck->invalidating_mode;
		__entry->waiters_pr = lck->waiters[SCOUTFS_LOCK_READ];
		__entry->waiters_ex = lck->waiters[SCOUTFS_LOCK_WRITE];
		__entry->waiters_cw = lck->waiters[SCOUTFS_LOCK_WRITE_ONLY];
		__entry->users_pr = lck->users[SCOUTFS_LOCK_READ];
		__entry->users_ex = lck->users[SCOUTFS_LOCK_WRITE];
		__entry->users_cw = lck->users[SCOUTFS_LOCK_WRITE_ONLY];
        ),
        TP_printk(SCSBF" start "SK_FMT" end "SK_FMT" mode %u invmd %u reqp %u invp %u refg %llu wris %llu dts %llu waiters: pr %u ex %u cw %u users: pr %u ex %u cw %u",
		  SCSB_TRACE_ARGS, sk_trace_args(start), sk_trace_args(end),
		  __entry->mode, __entry->invalidating_mode, __entry->request_pending,
		  __entry->invalidate_pending, __entry->refresh_gen, __entry->write_seq,
		  __entry->dirty_trans_seq,
		  __entry->waiters_pr, __entry->waiters_ex, __entry->waiters_cw,
		  __entry->users_pr, __entry->users_ex, __entry->users_cw)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidate,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_free,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_alloc,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_grant_response,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_granted,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidate_request,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_invalidated,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_locked,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_wait,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_unlock,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);
DEFINE_EVENT(scoutfs_lock_class, scoutfs_lock_shrink,
       TP_PROTO(struct super_block *sb, struct scoutfs_lock *lck),
       TP_ARGS(sb, lck)
);

DECLARE_EVENT_CLASS(scoutfs_net_class,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		si4_trace_define(name)
		si4_trace_define(peer)
		snh_trace_define(nh)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		si4_trace_assign(name, name);
		si4_trace_assign(peer, peer);
		snh_trace_assign(nh, nh);
        ),
        TP_printk(SCSBF" name "SI4_FMT" peer "SI4_FMT" nh "SNH_FMT,
		  SCSB_TRACE_ARGS, si4_trace_args(name), si4_trace_args(peer),
		  snh_trace_args(nh))
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_net_send_message,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

DEFINE_EVENT(scoutfs_net_class, scoutfs_net_recv_message,
        TP_PROTO(struct super_block *sb, struct sockaddr_in *name,
		 struct sockaddr_in *peer, struct scoutfs_net_header *nh),
        TP_ARGS(sb, name, peer, nh)
);

#define conn_flag_entry(which) \
	CONN_FL_##which, __stringify(which)

#define print_conn_flags(flags) __print_flags(flags, "|",	\
	{ conn_flag_entry(valid_greeting) },			\
	{ conn_flag_entry(established) },			\
	{ conn_flag_entry(shutting_down) },			\
	{ conn_flag_entry(saw_greeting) },			\
	{ conn_flag_entry(saw_farewell) },			\
	{ conn_flag_entry(reconn_wait) },			\
	{ conn_flag_entry(reconn_freeing) })

/*
 * This is called from alloc and free when the caller only has safe
 * access to the struct itself, be very careful not to follow any
 * indirection out of the storage for the conn struct.
 */
DECLARE_EVENT_CLASS(scoutfs_net_conn_class,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn),

        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(unsigned long, flags)
		__field(unsigned long, reconn_deadline)
		__field(unsigned long, connect_timeout_ms)
		__field(void *, sock)
		__field(__u64, c_rid)
		__field(__u64, greeting_id)
		si4_trace_define(sockname)
		si4_trace_define(peername)
		__field(unsigned char, e_accepted_head)
		__field(void *, listening_conn)
		__field(unsigned char, e_accepted_list)
		__field(__u64, next_send_seq)
		__field(__u64, next_send_id)
		__field(unsigned char, e_send_queue)
		__field(unsigned char, e_resend_queue)
		__field(__u64, recv_seq)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(conn->sb);
		__entry->flags = conn->flags;
		__entry->reconn_deadline = conn->reconn_deadline;
		__entry->connect_timeout_ms = conn->connect_timeout_ms;
		__entry->sock = conn->sock;
		__entry->c_rid = conn->rid;
		__entry->greeting_id = conn->greeting_id;
		si4_trace_assign(sockname, &conn->sockname);
		si4_trace_assign(peername, &conn->peername);
		__entry->e_accepted_head = !!list_empty(&conn->accepted_head);
		__entry->listening_conn = conn->listening_conn;
		__entry->e_accepted_list = !!list_empty(&conn->accepted_list);
		__entry->next_send_seq = conn->next_send_seq;
		__entry->next_send_id = conn->next_send_id;
		__entry->e_send_queue = !!list_empty(&conn->send_queue);
		__entry->e_resend_queue = !!list_empty(&conn->resend_queue);
		__entry->recv_seq = atomic64_read(&conn->recv_seq);
        ),
        TP_printk(SCSBF" flags %s rc_dl %lu cto %lu sk %p rid %llu grid %llu sn "SI4_FMT" pn "SI4_FMT" eah %u lc %p eal %u nss %llu nsi %llu esq %u erq %u rs %llu",
		  SCSB_TRACE_ARGS,
		  print_conn_flags(__entry->flags),
		  __entry->reconn_deadline,
		  __entry->connect_timeout_ms,
		  __entry->sock,
		  __entry->c_rid,
		  __entry->greeting_id,
		  si4_trace_args(sockname),
		  si4_trace_args(peername),
		  __entry->e_accepted_head,
		  __entry->listening_conn,
		  __entry->e_accepted_list,
		  __entry->next_send_seq,
		  __entry->next_send_id,
		  __entry->e_send_queue,
		  __entry->e_resend_queue,
		  __entry->recv_seq)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_alloc,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_connect_start,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_connect_result,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_connect_complete,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_accept,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_reconn_migrate,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_shutdown_queued,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_shutdown_start,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_shutdown_complete,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_destroy_start,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);
DEFINE_EVENT(scoutfs_net_conn_class, scoutfs_conn_destroy_free,
        TP_PROTO(struct scoutfs_net_connection *conn),
        TP_ARGS(conn)
);

DECLARE_EVENT_CLASS(scoutfs_work_class,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, data)
		__field(int, ret)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->data = data;
		__entry->ret = ret;
        ),
	TP_printk(SCSBF" data %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->data, __entry->ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_commit_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_commit_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_proc_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_proc_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_listen_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_listen_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_connect_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_connect_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_shutdown_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_shutdown_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_destroy_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_destroy_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_reconn_free_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_reconn_free_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_send_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_send_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_recv_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_net_recv_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_work_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_work_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_server_workqueue_destroy,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_data_return_server_extents_enter,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);
DEFINE_EVENT(scoutfs_work_class, scoutfs_data_return_server_extents_exit,
        TP_PROTO(struct super_block *sb, u64 data, int ret),
        TP_ARGS(sb, data, ret)
);

TRACE_EVENT(scoutfs_rename,
	TP_PROTO(struct super_block *sb, struct inode *old_dir,
		 struct dentry *old_dentry, struct inode *new_dir,
		 struct dentry *new_dentry),

	TP_ARGS(sb, old_dir, old_dentry, new_dir, new_dentry),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, old_dir_ino)
		__string(old_name, old_dentry->d_name.name)
		__field(__u64, new_dir_ino)
		__string(new_name, new_dentry->d_name.name)
		__field(__u64, new_inode_ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->old_dir_ino = scoutfs_ino(old_dir);
		__assign_str(old_name, old_dentry->d_name.name)
		__entry->new_dir_ino = scoutfs_ino(new_dir);
		__assign_str(new_name, new_dentry->d_name.name)
		__entry->new_inode_ino = new_dentry->d_inode ?
					 scoutfs_ino(new_dentry->d_inode) : 0;
	),

	TP_printk(SCSBF" old_dir_ino %llu old_name %s new_dir_ino %llu new_name %s new_inode_ino %llu",
		  SCSB_TRACE_ARGS, __entry->old_dir_ino, __get_str(old_name),
		  __entry->new_dir_ino, __get_str(new_name),
		  __entry->new_inode_ino)
);

TRACE_EVENT(scoutfs_d_revalidate,
	TP_PROTO(struct super_block *sb, struct dentry *dentry, int flags, u64 dir_ino, int ret),

	TP_ARGS(sb, dentry, flags, dir_ino, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, dentry)
		__string(name, dentry->d_name.name)
		__field(__u64, ino)
		__field(__u64, dir_ino)
		__field(int, flags)
		__field(int, is_root)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->dentry = dentry;
		__assign_str(name, dentry->d_name.name)
		__entry->ino = dentry->d_inode ? scoutfs_ino(dentry->d_inode) : 0;
		__entry->dir_ino = dir_ino;
		__entry->flags = flags;
		__entry->is_root = IS_ROOT(dentry);
		__entry->ret = ret;
	),

	TP_printk(SCSBF" dentry %p name %s ino %llu dir_ino %llu flags 0x%x s_root %u ret %d",
		  SCSB_TRACE_ARGS, __entry->dentry, __get_str(name), __entry->ino, __entry->dir_ino,
		  __entry->flags, __entry->is_root, __entry->ret)
);

TRACE_EVENT(scoutfs_validate_dentry,
	TP_PROTO(struct super_block *sb, struct dentry *dentry, u64 dir_ino, u64 dentry_ino,
		 u64 dent_ino, u64 refresh_gen, int ret),

	TP_ARGS(sb, dentry, dir_ino, dentry_ino, dent_ino, refresh_gen, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, dentry)
		__field(__u64, dir_ino)
		__string(name, dentry->d_name.name)
		__field(__u64, dentry_ino)
		__field(__u64, dent_ino)
		__field(__u64, fsdata_gen)
		__field(__u64, refresh_gen)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->dentry = dentry;
		__entry->dir_ino = dir_ino;
		__assign_str(name, dentry->d_name.name)
		__entry->dentry_ino = dentry_ino;
		__entry->dent_ino = dent_ino;
		__entry->fsdata_gen = (unsigned long long)dentry->d_fsdata;
		__entry->refresh_gen = refresh_gen;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" dentry %p dir %llu name %s dentry_ino %llu dent_ino %llu fsdata_gen %llu refresh_gen %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->dentry, __entry->dir_ino, __get_str(name),
		  __entry->dentry_ino, __entry->dent_ino, __entry->fsdata_gen,
		  __entry->refresh_gen, __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_super_lifecycle_class,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, sb)
		__field(void *, sbi)
		__field(void *, s_root)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->sb = sb;
		__entry->sbi = SCOUTFS_SB(sb);
		__entry->s_root = sb->s_root;
        ),
	TP_printk(SCSBF" sb %p sbi %p s_root %p",
		  SCSB_TRACE_ARGS, __entry->sb, __entry->sbi, __entry->s_root)
);

DEFINE_EVENT(scoutfs_super_lifecycle_class, scoutfs_fill_super,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb)
);

DEFINE_EVENT(scoutfs_super_lifecycle_class, scoutfs_put_super,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb)
);

DEFINE_EVENT(scoutfs_super_lifecycle_class, scoutfs_kill_sb,
        TP_PROTO(struct super_block *sb),
        TP_ARGS(sb)
);

DECLARE_EVENT_CLASS(scoutfs_fileid_class,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, fh_type)
		__field(u64, ino)
		__field(u64, parent_ino)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->fh_type = fh_type;
		__entry->ino = le64_to_cpu(fid->ino);
		__entry->parent_ino = fh_type == FILEID_SCOUTFS_WITH_PARENT ?
				le64_to_cpu(fid->parent_ino) : 0ULL;
	),
	TP_printk(SCSBF" type %d ino %llu parent %llu",
		  SCSB_TRACE_ARGS, __entry->fh_type, __entry->ino,
		  __entry->parent_ino)
);

DEFINE_EVENT(scoutfs_fileid_class, scoutfs_encode_fh,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid)
);

DEFINE_EVENT(scoutfs_fileid_class, scoutfs_fh_to_dentry,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid)
);

DEFINE_EVENT(scoutfs_fileid_class, scoutfs_fh_to_parent,
	TP_PROTO(struct super_block *sb, int fh_type, struct scoutfs_fid *fid),
	TP_ARGS(sb, fh_type, fid)
);

TRACE_EVENT(scoutfs_get_parent,
	TP_PROTO(struct super_block *sb, struct inode *inode, u64 parent),

	TP_ARGS(sb, inode, parent),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(__u64, parent)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = scoutfs_ino(inode);
		__entry->parent = parent;
	),

	TP_printk(SCSBF" child %llu parent %llu",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->parent)
);

TRACE_EVENT(scoutfs_get_name,
	TP_PROTO(struct super_block *sb, struct inode *parent,
		 struct inode *child, char *name),

	TP_ARGS(sb, parent, child, name),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, parent_ino)
		__field(__u64, child_ino)
		__string(name, name)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->parent_ino = scoutfs_ino(parent);
		__entry->child_ino = scoutfs_ino(child);
		__assign_str(name, name);
	),

	TP_printk(SCSBF" parent %llu child %llu name: %s",
		  SCSB_TRACE_ARGS, __entry->parent_ino, __entry->child_ino,
		  __get_str(name))
);

TRACE_EVENT(scoutfs_btree_read_error,
	TP_PROTO(struct super_block *sb, struct scoutfs_block_ref *ref),

	TP_ARGS(sb, ref),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(__u64, seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = le64_to_cpu(ref->blkno);
		__entry->seq = le64_to_cpu(ref->seq);
	),

	TP_printk(SCSBF" blkno %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->seq)
);

TRACE_EVENT(scoutfs_btree_walk,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *root,
		 struct scoutfs_key *key, int flags, int level,
		 struct scoutfs_block_ref *ref),

	TP_ARGS(sb, root, key, flags, level, ref),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, root_blkno)
		__field(__u64, root_seq)
		__field(__u8, root_height)
		sk_trace_define(key)
		__field(int, flags)
		__field(int, level)
		__field(__u64, ref_blkno)
		__field(__u64, ref_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->root_seq = le64_to_cpu(root->ref.seq);
		__entry->root_height = root->height;
		sk_trace_assign(key, key);
		__entry->flags = flags;
		__entry->level = level;
		__entry->ref_blkno = le64_to_cpu(ref->blkno);
		__entry->ref_seq = le64_to_cpu(ref->seq);
	),

	TP_printk(SCSBF" root blkno %llu seq %llu height %u key "SK_FMT" flags 0x%x level %d ref blkno %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->root_blkno, __entry->root_seq,
		  __entry->root_height, sk_trace_args(key), __entry->flags,
		  __entry->level, __entry->ref_blkno, __entry->ref_seq)
);

TRACE_EVENT(scoutfs_btree_set_parent,
	TP_PROTO(struct super_block *sb,
		 struct scoutfs_btree_root *root, struct scoutfs_key *key,
		 struct scoutfs_btree_root *par_root),

	TP_ARGS(sb, root, key, par_root),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, root_blkno)
		__field(__u64, root_seq)
		__field(__u8, root_height)
		sk_trace_define(key)
		__field(__u64, par_root_blkno)
		__field(__u64, par_root_seq)
		__field(__u8, par_root_height)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->root_seq = le64_to_cpu(root->ref.seq);
		__entry->root_height = root->height;
		sk_trace_assign(key, key);
		__entry->par_root_blkno = le64_to_cpu(par_root->ref.blkno);
		__entry->par_root_seq = le64_to_cpu(par_root->ref.seq);
		__entry->par_root_height = par_root->height;
	),

	TP_printk(SCSBF" root blkno %llu seq %llu height %u, key "SK_FMT", par_root blkno %llu seq %llu height %u",
		  SCSB_TRACE_ARGS, __entry->root_blkno, __entry->root_seq,
		  __entry->root_height, sk_trace_args(key),
		  __entry->par_root_blkno, __entry->par_root_seq,
		  __entry->par_root_height)
);

TRACE_EVENT(scoutfs_btree_merge,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *root,
		 struct scoutfs_key *start, struct scoutfs_key *end),

	TP_ARGS(sb, root, start, end),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, root_blkno)
		__field(__u64, root_seq)
		__field(__u8, root_height)
		sk_trace_define(start)
		sk_trace_define(end)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->root_seq = le64_to_cpu(root->ref.seq);
		__entry->root_height = root->height;
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
	),

	TP_printk(SCSBF" root blkno %llu seq %llu height %u start "SK_FMT" end "SK_FMT,
		  SCSB_TRACE_ARGS, __entry->root_blkno, __entry->root_seq,
		  __entry->root_height, sk_trace_args(start),
		  sk_trace_args(end))
);

TRACE_EVENT(scoutfs_btree_merge_read_range,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *start, struct scoutfs_key *end,
		 int size),

	TP_ARGS(sb, start, end, size),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(start)
		sk_trace_define(end)
		__field(int, size)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
		__entry->size = size;
	),

	TP_printk(SCSBF" start "SK_FMT" end "SK_FMT" size %d",
		  SCSB_TRACE_ARGS, sk_trace_args(start), sk_trace_args(end), __entry->size)
);

TRACE_EVENT(scoutfs_btree_merge_items,
	TP_PROTO(struct super_block *sb,
		 struct scoutfs_key *m_key, int m_val_len,
		 struct scoutfs_btree_root *f_root,
		 struct scoutfs_key *f_key, int f_val_len,
		 int is_del),

	TP_ARGS(sb, m_key, m_val_len, f_root, f_key, f_val_len, is_del),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(m_key)
		__field(int, m_val_len)
		__field(__u64, f_root_blkno)
		__field(__u64, f_root_seq)
		__field(__u8, f_root_height)
		sk_trace_define(f_key)
		__field(int, f_val_len)
		__field(int, is_del)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(m_key, m_key);
		__entry->m_val_len = m_val_len;
		__entry->f_root_blkno = f_root ?
					le64_to_cpu(f_root->ref.blkno) : 0;
		__entry->f_root_seq = f_root ? le64_to_cpu(f_root->ref.seq) : 0;
		__entry->f_root_height = f_root ? f_root->height : 0;
		sk_trace_assign(f_key, f_key);
		__entry->f_val_len = f_val_len;
		__entry->is_del = !!is_del;
	),

	TP_printk(SCSBF" merge item key "SK_FMT" val_len %d, fs item root blkno %llu seq %llu height %u key "SK_FMT" val_len %d, is_del %d",
		  SCSB_TRACE_ARGS, sk_trace_args(m_key), __entry->m_val_len,
		  __entry->f_root_blkno, __entry->f_root_seq, __entry->f_root_height,
		  sk_trace_args(f_key), __entry->f_val_len, __entry->is_del)
);

DECLARE_EVENT_CLASS(scoutfs_btree_free_blocks,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *root,
		 u64 blkno),

	TP_ARGS(sb, root, blkno),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, root_blkno)
		__field(__u64, root_seq)
		__field(__u8, root_height)
		__field(__u64, blkno)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->root_seq = le64_to_cpu(root->ref.seq);
		__entry->root_height = root->height;
		__entry->blkno = blkno;
	),

	TP_printk(SCSBF" root blkno %llu seq %llu height %u, free blkno %llu",
		  SCSB_TRACE_ARGS, __entry->root_blkno, __entry->root_seq,
		  __entry->root_height, __entry->blkno)
);
DEFINE_EVENT(scoutfs_btree_free_blocks, scoutfs_btree_free_blocks_single,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *root,
		 u64 blkno),
	TP_ARGS(sb, root, blkno)
);
DEFINE_EVENT(scoutfs_btree_free_blocks, scoutfs_btree_free_blocks_leaf,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *root,
		 u64 blkno),
	TP_ARGS(sb, root, blkno)
);
DEFINE_EVENT(scoutfs_btree_free_blocks, scoutfs_btree_free_blocks_parent,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *root,
		 u64 blkno),
	TP_ARGS(sb, root, blkno)
);

TRACE_EVENT(scoutfs_online_offline_blocks,
	TP_PROTO(struct inode *inode, s64 on_delta, s64 off_delta,
		 u64 on_now, u64 off_now),

	TP_ARGS(inode, on_delta, off_delta, on_now, off_now),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__s64, on_delta)
		__field(__s64, off_delta)
		__field(__u64, on_now)
		__field(__u64, off_now)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(inode->i_sb);
		__entry->on_delta = on_delta;
		__entry->off_delta = off_delta;
		__entry->on_now = on_now;
		__entry->off_now = off_now;
	),

	TP_printk(SCSBF" on_delta %lld off_delta %lld on_now %llu off_now %llu ",
		  SCSB_TRACE_ARGS, __entry->on_delta, __entry->off_delta,
		  __entry->on_now, __entry->off_now)
);

DECLARE_EVENT_CLASS(scoutfs_server_client_count_class,
	TP_PROTO(struct super_block *sb, u64 rid, unsigned long nr_clients),

	TP_ARGS(sb, rid, nr_clients),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__s64, c_rid)
		__field(unsigned long, nr_clients)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->c_rid = rid;
		__entry->nr_clients = nr_clients;
	),

	TP_printk(SCSBF" rid %016llx nr_clients %lu",
		  SCSB_TRACE_ARGS, __entry->c_rid, __entry->nr_clients)
);
DEFINE_EVENT(scoutfs_server_client_count_class, scoutfs_server_client_up,
	TP_PROTO(struct super_block *sb, u64 rid, unsigned long nr_clients),
	TP_ARGS(sb, rid, nr_clients)
);
DEFINE_EVENT(scoutfs_server_client_count_class, scoutfs_server_client_down,
	TP_PROTO(struct super_block *sb, u64 rid, unsigned long nr_clients),
	TP_ARGS(sb, rid, nr_clients)
);

DECLARE_EVENT_CLASS(scoutfs_server_commit_users_class,
        TP_PROTO(struct super_block *sb, int holding, int applying,
		 int nr_holders, u32 budget,
		 u32 avail_before, u32 freed_before,
		 int committing, int exceeded),
        TP_ARGS(sb, holding, applying, nr_holders, budget, avail_before, freed_before, committing, exceeded),
        TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, holding)
		__field(int, applying)
		__field(int, nr_holders)
		__field(u32, budget)
		__field(__u32, avail_before)
		__field(__u32, freed_before)
		__field(int, committing)
		__field(int, exceeded)
        ),
        TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->holding = !!holding;
		__entry->applying = !!applying;
		__entry->nr_holders = nr_holders;
		__entry->budget = budget;
		__entry->avail_before = avail_before;
		__entry->freed_before = freed_before;
		__entry->committing = !!committing;
		__entry->exceeded = !!exceeded;
        ),
	TP_printk(SCSBF" holding %u applying %u nr %u budget %u avail_before %u freed_before %u committing %u exceeded %u",
		  SCSB_TRACE_ARGS, __entry->holding, __entry->applying,
		  __entry->nr_holders, __entry->budget,
		  __entry->avail_before, __entry->freed_before,
		  __entry->committing, __entry->exceeded)
);
DEFINE_EVENT(scoutfs_server_commit_users_class, scoutfs_server_commit_hold,
        TP_PROTO(struct super_block *sb, int holding, int applying,
		 int nr_holders, u32 budget,
		 u32 avail_before, u32 freed_before,
		 int committing, int exceeded),
        TP_ARGS(sb, holding, applying, nr_holders, budget, avail_before, freed_before, committing, exceeded)
);
DEFINE_EVENT(scoutfs_server_commit_users_class, scoutfs_server_commit_apply,
        TP_PROTO(struct super_block *sb, int holding, int applying,
		 int nr_holders, u32 budget,
		 u32 avail_before, u32 freed_before,
		 int committing, int exceeded),
        TP_ARGS(sb, holding, applying, nr_holders, budget, avail_before, freed_before, committing, exceeded)
);
DEFINE_EVENT(scoutfs_server_commit_users_class, scoutfs_server_commit_start,
        TP_PROTO(struct super_block *sb, int holding, int applying,
		 int nr_holders, u32 budget,
		 u32 avail_before, u32 freed_before,
		 int committing, int exceeded),
        TP_ARGS(sb, holding, applying, nr_holders, budget, avail_before, freed_before, committing, exceeded)
);
DEFINE_EVENT(scoutfs_server_commit_users_class, scoutfs_server_commit_end,
        TP_PROTO(struct super_block *sb, int holding, int applying,
		 int nr_holders, u32 budget,
		 u32 avail_before, u32 freed_before,
		 int committing, int exceeded),
        TP_ARGS(sb, holding, applying, nr_holders, budget, avail_before, freed_before, committing, exceeded)
);

#define slt_symbolic(mode)						\
	__print_symbolic(mode,					\
		{ SLT_CLIENT,		"client" },	\
		{ SLT_SERVER,		"server" },	\
		{ SLT_GRANT,		"grant" },	\
		{ SLT_INVALIDATE,	"invalidate" },	\
		{ SLT_REQUEST,		"request" },	\
		{ SLT_RESPONSE,		"response" })

TRACE_EVENT(scoutfs_lock_message,
	TP_PROTO(struct super_block *sb, int who, int what, int dir,
		 u64 rid, u64 net_id, struct scoutfs_net_lock *nl),

	TP_ARGS(sb, who, what, dir, rid, net_id, nl),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(int, who)
		__field(int, what)
		__field(int, dir)
		__field(__u64, m_rid)
		__field(__u64, net_id)
		sk_trace_define(key)
		__field(__u8, old_mode)
		__field(__u8, new_mode)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->who = who;
		__entry->what = what;
		__entry->dir = dir;
		__entry->m_rid = rid;
		__entry->net_id = net_id;
		sk_trace_assign(key, &nl->key);
		__entry->old_mode = nl->old_mode;
		__entry->new_mode = nl->new_mode;
	),

	TP_printk(SCSBF" %s %s %s rid %016llx net_id %llu key "SK_FMT" old_mode %u new_mode %u",
		  SCSB_TRACE_ARGS, slt_symbolic(__entry->who),
		  slt_symbolic(__entry->what), slt_symbolic(__entry->dir),
		  __entry->m_rid, __entry->net_id, sk_trace_args(key),
		  __entry->old_mode, __entry->new_mode)
);

DECLARE_EVENT_CLASS(scoutfs_quorum_message_class,
	TP_PROTO(struct super_block *sb, u64 term, u8 type, int nr),

	TP_ARGS(sb, term, type, nr),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, term)
		__field(__u8, type)
		__field(int, nr)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->term = term;
		__entry->type = type;
		__entry->nr = nr;
	),

	TP_printk(SCSBF" term %llu type %u nr %d",
		  SCSB_TRACE_ARGS, __entry->term, __entry->type, __entry->nr)
);
DEFINE_EVENT(scoutfs_quorum_message_class, scoutfs_quorum_send_message,
	TP_PROTO(struct super_block *sb, u64 term, u8 type, int nr),
	TP_ARGS(sb, term, type, nr)
);
DEFINE_EVENT(scoutfs_quorum_message_class, scoutfs_quorum_recv_message,
	TP_PROTO(struct super_block *sb, u64 term, u8 type, int nr),
	TP_ARGS(sb, term, type, nr)
);

TRACE_EVENT(scoutfs_quorum_loop,
	TP_PROTO(struct super_block *sb, int role, u64 term, int vote_for,
		 unsigned long vote_bits, unsigned long long nsecs),

	TP_ARGS(sb, role, term, vote_for, vote_bits, nsecs),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, term)
		__field(int, role)
		__field(int, vote_for)
		__field(unsigned long, vote_bits)
		__field(unsigned long, vote_count)
		__field(unsigned long long, nsecs)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->term = term;
		__entry->role = role;
		__entry->vote_for = vote_for;
		__entry->vote_bits = vote_bits;
		__entry->vote_count = hweight_long(vote_bits);
		__entry->nsecs = nsecs;
	),

	TP_printk(SCSBF" term %llu role %d vote_for %d vote_bits 0x%lx vote_count %lu timeout %llu",
		  SCSB_TRACE_ARGS, __entry->term, __entry->role,
		  __entry->vote_for, __entry->vote_bits, __entry->vote_count,
		  __entry->nsecs)
);

TRACE_EVENT(scoutfs_trans_seq_last,
	TP_PROTO(struct super_block *sb, u64 rid, u64 trans_seq),

	TP_ARGS(sb, rid, trans_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, s_rid)
		__field(__u64, trans_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->s_rid = rid;
		__entry->trans_seq = trans_seq;
	),

	TP_printk(SCSBF" rid %016llx trans_seq %llu",
		  SCSB_TRACE_ARGS, __entry->s_rid, __entry->trans_seq)
);

TRACE_EVENT(scoutfs_server_finalize_items,
	TP_PROTO(struct super_block *sb, u64 rid, u64 item_rid, u64 item_nr, u64 item_flags,
		 u64 item_get_trans_seq),

	TP_ARGS(sb, rid, item_rid, item_nr, item_flags, item_get_trans_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, c_rid)
		__field(__u64, item_rid)
		__field(__u64, item_nr)
		__field(__u64, item_flags)
		__field(__u64, item_get_trans_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->c_rid = rid;
		__entry->item_rid = item_rid;
		__entry->item_nr = item_nr;
		__entry->item_flags = item_flags;
		__entry->item_get_trans_seq = item_get_trans_seq;
	),

	TP_printk(SCSBF" rid %016llx item_rid %016llx item_nr %llu item_flags 0x%llx item_get_trans_seq %llu",
		  SCSB_TRACE_ARGS, __entry->c_rid, __entry->item_rid, __entry->item_nr,
		  __entry->item_flags, __entry->item_get_trans_seq)
);

TRACE_EVENT(scoutfs_server_finalize_decision,
	TP_PROTO(struct super_block *sb, u64 rid, bool saw_finalized, bool others_active,
		 bool ours_visible, bool finalize_ours, unsigned int delay_ms,
		 u64 finalize_sent_seq),

	TP_ARGS(sb, rid, saw_finalized, others_active, ours_visible, finalize_ours, delay_ms,
		finalize_sent_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, c_rid)
		__field(bool, saw_finalized)
		__field(bool, others_active)
		__field(bool, ours_visible)
		__field(bool, finalize_ours)
		__field(unsigned int, delay_ms)
		__field(__u64, finalize_sent_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->c_rid = rid;
		__entry->saw_finalized = saw_finalized;
		__entry->others_active = others_active;
		__entry->ours_visible = ours_visible;
		__entry->finalize_ours = finalize_ours;
		__entry->delay_ms = delay_ms;
		__entry->finalize_sent_seq = finalize_sent_seq;
	),

	TP_printk(SCSBF" rid %016llx saw_finalized %u others_active %u ours_visible %u finalize_ours %u delay_ms %u finalize_sent_seq %llu",
		  SCSB_TRACE_ARGS, __entry->c_rid, __entry->saw_finalized, __entry->others_active,
		  __entry->ours_visible, __entry->finalize_ours, __entry->delay_ms,
		  __entry->finalize_sent_seq)
);

TRACE_EVENT(scoutfs_get_log_merge_status,
	TP_PROTO(struct super_block *sb, u64 rid, struct scoutfs_key *next_range_key,
		 u64 nr_requests, u64 nr_complete, u64 seq),

	TP_ARGS(sb, rid, next_range_key, nr_requests, nr_complete, seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, s_rid)
		sk_trace_define(next_range_key)
		__field(__u64, nr_requests)
		__field(__u64, nr_complete)
		__field(__u64, seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->s_rid = rid;
		sk_trace_assign(next_range_key, next_range_key);
		__entry->nr_requests = nr_requests;
		__entry->nr_complete = nr_complete;
		__entry->seq = seq;
	),

	TP_printk(SCSBF" rid %016llx next_range_key "SK_FMT" nr_requests %llu nr_complete %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->s_rid, sk_trace_args(next_range_key),
		  __entry->nr_requests, __entry->nr_complete, __entry->seq)
);

TRACE_EVENT(scoutfs_get_log_merge_request,
	TP_PROTO(struct super_block *sb, u64 rid,
		 struct scoutfs_btree_root *root, struct scoutfs_key *start,
		 struct scoutfs_key *end, u64 input_seq, u64 seq),

	TP_ARGS(sb, rid, root, start, end, input_seq, seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, s_rid)
		__field(__u64, root_blkno)
		__field(__u64, root_seq)
		__field(__u8, root_height)
		sk_trace_define(start)
		sk_trace_define(end)
		__field(__u64, input_seq)
		__field(__u64, seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->s_rid = rid;
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->root_seq = le64_to_cpu(root->ref.seq);
		__entry->root_height = root->height;
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
		__entry->input_seq = input_seq;
		__entry->seq = seq;
	),

	TP_printk(SCSBF" rid %016llx root blkno %llu seq %llu height %u start "SK_FMT" end "SK_FMT" input_seq %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->s_rid, __entry->root_blkno,
		  __entry->root_seq, __entry->root_height,
		  sk_trace_args(start), sk_trace_args(end), __entry->input_seq,
		  __entry->seq)
);

TRACE_EVENT(scoutfs_get_log_merge_complete,
	TP_PROTO(struct super_block *sb, u64 rid,
		 struct scoutfs_btree_root *root, struct scoutfs_key *start,
		 struct scoutfs_key *end, struct scoutfs_key *remain,
		 u64 seq, u64 flags),

	TP_ARGS(sb, rid, root, start, end, remain, seq, flags),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, s_rid)
		__field(__u64, root_blkno)
		__field(__u64, root_seq)
		__field(__u8, root_height)
		sk_trace_define(start)
		sk_trace_define(end)
		sk_trace_define(remain)
		__field(__u64, seq)
		__field(__u64, flags)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->s_rid = rid;
		__entry->root_blkno = le64_to_cpu(root->ref.blkno);
		__entry->root_seq = le64_to_cpu(root->ref.seq);
		__entry->root_height = root->height;
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
		sk_trace_assign(remain, remain);
		__entry->seq = seq;
		__entry->flags = flags;
	),

	TP_printk(SCSBF" rid %016llx root blkno %llu seq %llu height %u start "SK_FMT" end "SK_FMT" remain "SK_FMT" seq %llu flags 0x%llx",
		  SCSB_TRACE_ARGS, __entry->s_rid, __entry->root_blkno,
		  __entry->root_seq, __entry->root_height,
		  sk_trace_args(start), sk_trace_args(end),
		  sk_trace_args(remain), __entry->seq, __entry->flags)
);

DECLARE_EVENT_CLASS(scoutfs_forest_bloom_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 u64 rid, u64 nr, u64 blkno, u64 seq, unsigned int count),
	TP_ARGS(sb, key, rid, nr, blkno, seq, count),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		__field(__u64, b_rid)
		__field(__u64, nr)
		__field(__u64, blkno)
		__field(__u64, seq)
		__field(unsigned int, count)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
		__entry->b_rid = rid;
		__entry->nr = nr;
		__entry->blkno = blkno;
		__entry->seq = seq;
		__entry->count = count;
	),
	TP_printk(SCSBF" key "SK_FMT" rid %016llx nr %llu blkno %llu seq %llx count %u",
		  SCSB_TRACE_ARGS, sk_trace_args(key), __entry->b_rid,
		  __entry->nr, __entry->blkno, __entry->seq, __entry->count)
);
DEFINE_EVENT(scoutfs_forest_bloom_class, scoutfs_forest_bloom_set,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 u64 rid, u64 nr, u64 blkno, u64 seq, unsigned int count),
	TP_ARGS(sb, key, rid, nr, blkno, seq, count)
);
DEFINE_EVENT(scoutfs_forest_bloom_class, scoutfs_forest_bloom_search,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 u64 rid, u64 nr, u64 blkno, u64 seq, unsigned int count),
	TP_ARGS(sb, key, rid, nr, blkno, seq, count)
);

TRACE_EVENT(scoutfs_forest_prepare_commit,
	TP_PROTO(struct super_block *sb, struct scoutfs_block_ref *item_ref,
		 struct scoutfs_block_ref *bloom_ref),
	TP_ARGS(sb, item_ref, bloom_ref),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, item_blkno)
		__field(__u64, item_seq)
		__field(__u64, bloom_blkno)
		__field(__u64, bloom_seq)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->item_blkno = le64_to_cpu(item_ref->blkno);
		__entry->item_seq = le64_to_cpu(item_ref->seq);
		__entry->bloom_blkno = le64_to_cpu(bloom_ref->blkno);
		__entry->bloom_seq = le64_to_cpu(bloom_ref->seq);
	),
	TP_printk(SCSBF" item blkno %llu seq %llu bloom blkno %llu seq %llu",
		  SCSB_TRACE_ARGS,  __entry->item_blkno, __entry->item_seq,
		  __entry->bloom_blkno, __entry->bloom_seq)
);

TRACE_EVENT(scoutfs_forest_using_roots,
	TP_PROTO(struct super_block *sb, struct scoutfs_btree_root *fs_root,
		 struct scoutfs_btree_root *logs_root),
	TP_ARGS(sb, fs_root, logs_root),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, fs_blkno)
		__field(__u64, fs_seq)
		__field(__u64, logs_blkno)
		__field(__u64, logs_seq)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->fs_blkno = le64_to_cpu(fs_root->ref.blkno);
		__entry->fs_seq = le64_to_cpu(fs_root->ref.seq);
		__entry->logs_blkno = le64_to_cpu(logs_root->ref.blkno);
		__entry->logs_seq = le64_to_cpu(logs_root->ref.seq);
	),
	TP_printk(SCSBF" fs blkno %llu seq %llu logs blkno %llu seq %llu",
		  SCSB_TRACE_ARGS, __entry->fs_blkno, __entry->fs_seq,
		  __entry->logs_blkno, __entry->logs_seq)
);

TRACE_EVENT(scoutfs_forest_init_our_log,
	TP_PROTO(struct super_block *sb, u64 rid, u64 nr, u64 blkno, u64 seq),
	TP_ARGS(sb, rid, nr, blkno, seq),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, b_rid)
		__field(__u64, nr)
		__field(__u64, blkno)
		__field(__u64, seq)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->b_rid = rid;
		__entry->nr = nr;
		__entry->blkno = blkno;
		__entry->seq = seq;
	),
	TP_printk(SCSBF" rid %016llx nr %llu blkno %llu seq %llx",
		  SCSB_TRACE_ARGS, __entry->b_rid, __entry->nr,
		  __entry->blkno, __entry->seq)
);

TRACE_EVENT(scoutfs_block_dirty_ref,
	TP_PROTO(struct super_block *sb, u64 ref_blkno, u64 ref_seq,
		 u64 block_blkno, u64 block_seq),

	TP_ARGS(sb, ref_blkno, ref_seq, block_blkno, block_seq),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ref_blkno)
		__field(__u64, ref_seq)
		__field(__u64, block_blkno)
		__field(__u64, block_seq)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ref_blkno = ref_blkno;
		__entry->ref_seq = ref_seq;
		__entry->block_blkno = block_blkno;
		__entry->block_seq = block_seq;
	),

	TP_printk(SCSBF" ref_blkno %llu ref_seq %llu block_blkno %llu block_seq %llu",
		  SCSB_TRACE_ARGS, __entry->ref_blkno, __entry->ref_seq,
		  __entry->block_blkno, __entry->block_seq)
);

TRACE_EVENT(scoutfs_get_file_block,
	TP_PROTO(struct super_block *sb, u64 blkno, int flags,
		 struct scoutfs_srch_block *srb),

	TP_ARGS(sb, blkno, flags, srb),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(int, flags)
		__field(__u64, first_hash)
		__field(__u64, first_ino)
		__field(__u64, first_id)
		__field(__u64, last_hash)
		__field(__u64, last_ino)
		__field(__u64, last_id)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = blkno;
		__entry->flags = flags;
		__entry->first_hash = __le64_to_cpu(srb->first.hash);
		__entry->first_ino = __le64_to_cpu(srb->first.ino);
		__entry->first_id = __le64_to_cpu(srb->first.id);
		__entry->last_hash = __le64_to_cpu(srb->last.hash);
		__entry->last_ino = __le64_to_cpu(srb->last.ino);
		__entry->last_id = __le64_to_cpu(srb->last.id);
	),

	TP_printk(SCSBF" blkno %llu flags 0x%x first_hash 0x%llx first_ino %llu fist_id 0x%llx last_hash 0x%llx last_ino %llu last_id 0x%llx",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->flags,
		  __entry->first_hash, __entry->first_ino, __entry->first_id,
		  __entry->last_hash, __entry->last_ino, __entry->last_id)
);

TRACE_EVENT(scoutfs_block_stale,
	TP_PROTO(struct super_block *sb, struct scoutfs_block_ref *ref,
		 struct scoutfs_block_header *hdr, u32 magic, u32 crc),

	TP_ARGS(sb, ref, hdr, magic, crc),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ref_blkno)
		__field(__u64, ref_seq)
		__field(__u32, hdr_crc)
		__field(__u32, hdr_magic)
		__field(__u64, hdr_fsid)
		__field(__u64, hdr_seq)
		__field(__u64, hdr_blkno)
		__field(__u32, magic)
		__field(__u32, crc)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ref_blkno = le64_to_cpu(ref->blkno);
		__entry->ref_seq = le64_to_cpu(ref->seq);
		__entry->hdr_crc = le32_to_cpu(hdr->crc);
		__entry->hdr_magic = le32_to_cpu(hdr->magic);
		__entry->hdr_fsid = le64_to_cpu(hdr->fsid);
		__entry->hdr_seq = le64_to_cpu(hdr->seq);
		__entry->hdr_blkno = le64_to_cpu(hdr->blkno);
		__entry->magic = magic;
		__entry->crc = crc;
	),

	TP_printk(SCSBF" ref_blkno %llu ref_seq %016llx hdr_crc %08x hdr_magic %08x hdr_fsid %016llx hdr_seq %016llx hdr_blkno %llu magic %08x crc %08x",
		  SCSB_TRACE_ARGS, __entry->ref_blkno, __entry->ref_seq, __entry->hdr_crc,
		  __entry->hdr_magic, __entry->hdr_fsid, __entry->hdr_seq, __entry->hdr_blkno,
		  __entry->magic, __entry->crc)
);

DECLARE_EVENT_CLASS(scoutfs_block_class,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno, int refcount, int io_count,
		 unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, bp)
		__field(__u64, blkno)
		__field(int, refcount)
		__field(int, io_count)
		__field(long, bits)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->bp = bp;
		__entry->blkno = blkno;
		__entry->refcount = refcount;
		__entry->io_count = io_count;
		__entry->bits = bits;
	),
	TP_printk(SCSBF" bp %p blkno %llu refcount %x io_count %d bits 0x%lx",
		  SCSB_TRACE_ARGS, __entry->bp, __entry->blkno, __entry->refcount,
		  __entry->io_count, __entry->bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_allocate,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_free,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_insert,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_remove,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_end_io,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_submit,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_invalidate,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_mark_dirty,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_forget,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_shrink,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);
DEFINE_EVENT(scoutfs_block_class, scoutfs_block_isolate,
	TP_PROTO(struct super_block *sb, void *bp, u64 blkno,
		 int refcount, int io_count, unsigned long bits),
	TP_ARGS(sb, bp, blkno, refcount, io_count, bits)
);

DECLARE_EVENT_CLASS(scoutfs_ext_next_class,
	TP_PROTO(struct super_block *sb, u64 start, u64 len,
		 struct scoutfs_extent *ext, int ret),

	TP_ARGS(sb, start, len, ext, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, start)
		__field(__u64, len)
		STE_FIELDS(ext)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->start = start;
		__entry->len = len;
		STE_ASSIGN(ext, ext)
		__entry->ret = ret;
	),

	TP_printk(SCSBF" start %llu len %llu ext "STE_FMT" ret %d",
		  SCSB_TRACE_ARGS, __entry->start, __entry->len,
		  STE_ENTRY_ARGS(ext), __entry->ret)
);

DEFINE_EVENT(scoutfs_ext_next_class, scoutfs_ext_op_next,
	TP_PROTO(struct super_block *sb, u64 start, u64 len,
		 struct scoutfs_extent *ext, int ret),
	TP_ARGS(sb, start, len, ext, ret)
);
DEFINE_EVENT(scoutfs_ext_next_class, scoutfs_ext_next,
	TP_PROTO(struct super_block *sb, u64 start, u64 len,
		 struct scoutfs_extent *ext, int ret),
	TP_ARGS(sb, start, len, ext, ret)
);

DECLARE_EVENT_CLASS(scoutfs_ext_typical_class,
	TP_PROTO(struct super_block *sb, u64 start, u64 len, u64 map, u8 flags,
		 int ret),

	TP_ARGS(sb, start, len, map, flags, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, start)
		__field(__u64, len)
		__field(__u64, map)
		__field(__u8, flags)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->start = start;
		__entry->len = len;
		__entry->map = map;
		__entry->flags = flags;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" start %llu len %llu map %llu flags %u ret %d",
		  SCSB_TRACE_ARGS, __entry->start, __entry->len, __entry->map,
		  __entry->flags, __entry->ret)
);

DEFINE_EVENT(scoutfs_ext_typical_class, scoutfs_ext_op_insert,
	TP_PROTO(struct super_block *sb, u64 start, u64 len, u64 map, u8 flags,
		 int ret),
	TP_ARGS(sb, start, len, map, flags, ret)
);
DEFINE_EVENT(scoutfs_ext_typical_class, scoutfs_ext_insert,
	TP_PROTO(struct super_block *sb, u64 start, u64 len, u64 map, u8 flags,
		 int ret),
	TP_ARGS(sb, start, len, map, flags, ret)
);
DEFINE_EVENT(scoutfs_ext_typical_class, scoutfs_ext_op_remove,
	TP_PROTO(struct super_block *sb, u64 start, u64 len, u64 map, u8 flags,
		 int ret),
	TP_ARGS(sb, start, len, map, flags, ret)
);
DEFINE_EVENT(scoutfs_ext_typical_class, scoutfs_ext_remove,
	TP_PROTO(struct super_block *sb, u64 start, u64 len, u64 map, u8 flags,
		 int ret),
	TP_ARGS(sb, start, len, map, flags, ret)
);
DEFINE_EVENT(scoutfs_ext_typical_class, scoutfs_ext_set,
	TP_PROTO(struct super_block *sb, u64 start, u64 len, u64 map, u8 flags,
		 int ret),
	TP_ARGS(sb, start, len, map, flags, ret)
);

TRACE_EVENT(scoutfs_ext_alloc,
	TP_PROTO(struct super_block *sb, u64 start, u64 len, u64 count,
		 struct scoutfs_extent *ext, int ret),

	TP_ARGS(sb, start, len, count, ext, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, start)
		__field(__u64, len)
		__field(__u64, count)
		STE_FIELDS(ext)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->start = start;
		__entry->len = len;
		__entry->count = count;
		STE_ASSIGN(ext, ext)
		__entry->ret = ret;
	),

	TP_printk(SCSBF" start %llu len %llu count %llu ext "STE_FMT" ret %d",
		  SCSB_TRACE_ARGS, __entry->start, __entry->len, __entry->count,
		  STE_ENTRY_ARGS(ext), __entry->ret)
);

TRACE_EVENT(scoutfs_alloc_alloc_meta,
	TP_PROTO(struct super_block *sb, u64 blkno, int ret),

	TP_ARGS(sb, blkno, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = blkno;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" blkno %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->ret)
);

TRACE_EVENT(scoutfs_alloc_free_meta,
	TP_PROTO(struct super_block *sb, u64 blkno, int ret),

	TP_ARGS(sb, blkno, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = blkno;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" blkno %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->ret)
);

TRACE_EVENT(scoutfs_alloc_alloc_data,
	TP_PROTO(struct super_block *sb, u64 req, u64 blkno, u64 count,
		 int ret),

	TP_ARGS(sb, req, blkno, count, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, req)
		__field(__u64, blkno)
		__field(__u64, count)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->req = req;
		__entry->blkno = blkno;
		__entry->count = count;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" req %llu blkno %llu count %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->req, __entry->blkno,
		  __entry->count, __entry->ret)
);

TRACE_EVENT(scoutfs_alloc_free_data,
	TP_PROTO(struct super_block *sb, u64 blkno, u64 count, int ret),

	TP_ARGS(sb, blkno, count, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, blkno)
		__field(__u64, count)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->blkno = blkno;
		__entry->count = count;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" blkno %llu count %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->blkno, __entry->count,
		  __entry->ret)
);

TRACE_EVENT(scoutfs_alloc_move,
	TP_PROTO(struct super_block *sb, u64 total, u64 moved, int ret),

	TP_ARGS(sb, total, moved, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, total)
		__field(__u64, moved)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->total = total;
		__entry->moved = moved;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" total %llu moved %llu ret %d",
		  SCSB_TRACE_ARGS, __entry->total, __entry->moved,
		  __entry->ret)
);

DECLARE_EVENT_CLASS(scoutfs_alloc_extent_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),

	TP_ARGS(sb, ext),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		STE_FIELDS(ext)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		STE_ASSIGN(ext, ext);
	),

	TP_printk(SCSBF" ext "STE_FMT, SCSB_TRACE_ARGS, STE_ENTRY_ARGS(ext))
);
DEFINE_EVENT(scoutfs_alloc_extent_class, scoutfs_alloc_move_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_alloc_extent_class, scoutfs_alloc_fill_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);
DEFINE_EVENT(scoutfs_alloc_extent_class, scoutfs_alloc_empty_extent,
	TP_PROTO(struct super_block *sb, struct scoutfs_extent *ext),
	TP_ARGS(sb, ext)
);

TRACE_EVENT(scoutfs_item_read_page,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *key,
		 struct scoutfs_key *pg_start, struct scoutfs_key *pg_end),
	TP_ARGS(sb, key, pg_start, pg_end),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(key)
		sk_trace_define(pg_start)
		sk_trace_define(pg_end)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(key, key);
		sk_trace_assign(pg_start, pg_start);
		sk_trace_assign(pg_end, pg_end);
	),
	TP_printk(SCSBF" key "SK_FMT" pg_start "SK_FMT" pg_end "SK_FMT,
		  SCSB_TRACE_ARGS, sk_trace_args(key), sk_trace_args(pg_start),
		  sk_trace_args(pg_end))
);

TRACE_EVENT(scoutfs_item_invalidate_page,
	TP_PROTO(struct super_block *sb, struct scoutfs_key *start,
		 struct scoutfs_key *end, struct scoutfs_key *pg_start,
		 struct scoutfs_key *pg_end, int pgi),
	TP_ARGS(sb, start, end, pg_start, pg_end, pgi),
	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		sk_trace_define(start)
		sk_trace_define(end)
		sk_trace_define(pg_start)
		sk_trace_define(pg_end)
		__field(int, pgi)
	),
	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		sk_trace_assign(start, start);
		sk_trace_assign(end, end);
		sk_trace_assign(pg_start, pg_start);
		sk_trace_assign(pg_end, pg_end);
		__entry->pgi = pgi;
	),
	TP_printk(SCSBF" start "SK_FMT" end "SK_FMT" pg_start "SK_FMT" pg_end "SK_FMT" pgi %d",
		  SCSB_TRACE_ARGS, sk_trace_args(start), sk_trace_args(end),
		  sk_trace_args(pg_start), sk_trace_args(pg_end), __entry->pgi)
);

DECLARE_EVENT_CLASS(scoutfs_omap_group_class,
	TP_PROTO(struct super_block *sb, void *grp, u64 group_nr, unsigned int group_total,
		 int bit_nr),

	TP_ARGS(sb, grp, group_nr, group_total, bit_nr),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(void *, grp)
		__field(__u64, group_nr)
		__field(unsigned int, group_total)
		__field(int, bit_nr)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->grp = grp;
		__entry->group_nr = group_nr;
		__entry->group_total = group_total;
		__entry->bit_nr = bit_nr;
	),

	TP_printk(SCSBF" grp %p group_nr %llu group_total %u bit_nr %d",
		  SCSB_TRACE_ARGS, __entry->grp, __entry->group_nr, __entry->group_total,
		  __entry->bit_nr)
);

DEFINE_EVENT(scoutfs_omap_group_class, scoutfs_omap_group_alloc,
	TP_PROTO(struct super_block *sb, void *grp, u64 group_nr, unsigned int group_total,
		 int bit_nr),
	TP_ARGS(sb, grp, group_nr, group_total, bit_nr)
);
DEFINE_EVENT(scoutfs_omap_group_class, scoutfs_omap_group_free,
	TP_PROTO(struct super_block *sb, void *grp, u64 group_nr, unsigned int group_total,
		 int bit_nr),
	TP_ARGS(sb, grp, group_nr, group_total, bit_nr)
);
DEFINE_EVENT(scoutfs_omap_group_class, scoutfs_omap_group_inc,
	TP_PROTO(struct super_block *sb, void *grp, u64 group_nr, unsigned int group_total,
		 int bit_nr),
	TP_ARGS(sb, grp, group_nr, group_total, bit_nr)
);
DEFINE_EVENT(scoutfs_omap_group_class, scoutfs_omap_group_dec,
	TP_PROTO(struct super_block *sb, void *grp, u64 group_nr, unsigned int group_total,
		 int bit_nr),
	TP_ARGS(sb, grp, group_nr, group_total, bit_nr)
);
DEFINE_EVENT(scoutfs_omap_group_class, scoutfs_omap_group_request,
	TP_PROTO(struct super_block *sb, void *grp, u64 group_nr, unsigned int group_total,
		 int bit_nr),
	TP_ARGS(sb, grp, group_nr, group_total, bit_nr)
);
DEFINE_EVENT(scoutfs_omap_group_class, scoutfs_omap_group_destroy,
	TP_PROTO(struct super_block *sb, void *grp, u64 group_nr, unsigned int group_total,
		 int bit_nr),
	TP_ARGS(sb, grp, group_nr, group_total, bit_nr)
);

TRACE_EVENT(scoutfs_omap_should_delete,
	TP_PROTO(struct super_block *sb, u64 ino, unsigned int nlink, int ret),

	TP_ARGS(sb, ino, nlink, ret),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, ino)
		__field(unsigned int, nlink)
		__field(int, ret)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->nlink = nlink;
		__entry->ret = ret;
	),

	TP_printk(SCSBF" ino %llu nlink %u ret %d",
		  SCSB_TRACE_ARGS, __entry->ino, __entry->nlink, __entry->ret)
);

#define SSCF_FMT "[bo %llu bs %llu es %llu]"
#define SSCF_FIELDS(pref)					\
	__field(__u64, pref##_blkno)				\
	__field(__u64, pref##_blocks)				\
	__field(__u64, pref##_entries)
#define SSCF_ASSIGN(pref, sfl)					\
	__entry->pref##_blkno = le64_to_cpu((sfl)->ref.blkno);	\
	__entry->pref##_blocks = le64_to_cpu((sfl)->blocks);	\
	__entry->pref##_entries = le64_to_cpu((sfl)->entries);
#define SSCF_ENTRY_ARGS(pref)					\
	__entry->pref##_blkno,					\
	__entry->pref##_blocks,					\
	__entry->pref##_entries

DECLARE_EVENT_CLASS(scoutfs_srch_compact_class,
	TP_PROTO(struct super_block *sb, struct scoutfs_srch_compact *sc),

	TP_ARGS(sb, sc),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(__u64, id)
		__field(__u8, nr)
		__field(__u8, flags)
		SSCF_FIELDS(out)
		__field(__u64, in0_blk)
		__field(__u64, in0_pos)
		SSCF_FIELDS(in0)
		__field(__u64, in1_blk)
		__field(__u64, in1_pos)
		SSCF_FIELDS(in1)
		__field(__u64, in2_blk)
		__field(__u64, in2_pos)
		SSCF_FIELDS(in2)
		__field(__u64, in3_blk)
		__field(__u64, in3_pos)
		SSCF_FIELDS(in3)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->id = le64_to_cpu(sc->id);
		__entry->nr = sc->nr;
		__entry->flags = sc->flags;
		SSCF_ASSIGN(out, &sc->out)
		__entry->in0_blk = le64_to_cpu(sc->in[0].blk);
		__entry->in0_pos = le64_to_cpu(sc->in[0].pos);
		SSCF_ASSIGN(in0, &sc->in[0].sfl)
		__entry->in1_blk = le64_to_cpu(sc->in[0].blk);
		__entry->in1_pos = le64_to_cpu(sc->in[0].pos);
		SSCF_ASSIGN(in1, &sc->in[1].sfl)
		__entry->in2_blk = le64_to_cpu(sc->in[0].blk);
		__entry->in2_pos = le64_to_cpu(sc->in[0].pos);
		SSCF_ASSIGN(in2, &sc->in[2].sfl)
		__entry->in3_blk = le64_to_cpu(sc->in[0].blk);
		__entry->in3_pos = le64_to_cpu(sc->in[0].pos);
		SSCF_ASSIGN(in3, &sc->in[3].sfl)
	),

	TP_printk(SCSBF" id %llu nr %u flags 0x%x out "SSCF_FMT" in0 b %llu p %llu "SSCF_FMT" in1 b %llu p %llu "SSCF_FMT" in2 b %llu p %llu "SSCF_FMT" in3 b %llu p %llu "SSCF_FMT,
		  SCSB_TRACE_ARGS, __entry->id, __entry->nr, __entry->flags, SSCF_ENTRY_ARGS(out),
		  __entry->in0_blk, __entry->in0_pos, SSCF_ENTRY_ARGS(in0),
		  __entry->in1_blk, __entry->in1_pos, SSCF_ENTRY_ARGS(in1),
		  __entry->in2_blk, __entry->in2_pos, SSCF_ENTRY_ARGS(in2),
		  __entry->in3_blk, __entry->in3_pos, SSCF_ENTRY_ARGS(in3))
);
DEFINE_EVENT(scoutfs_srch_compact_class, scoutfs_srch_compact_client_send,
	TP_PROTO(struct super_block *sb, struct scoutfs_srch_compact *sc),
	TP_ARGS(sb, sc)
);
DEFINE_EVENT(scoutfs_srch_compact_class, scoutfs_srch_compact_client_recv,
	TP_PROTO(struct super_block *sb, struct scoutfs_srch_compact *sc),
	TP_ARGS(sb, sc)
);

TRACE_EVENT(scoutfs_ioc_search_xattrs,
	TP_PROTO(struct super_block *sb, u64 ino, u64 last_ino),

	TP_ARGS(sb, ino, last_ino),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(u64, ino)
		__field(u64, last_ino)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->ino = ino;
		__entry->last_ino = last_ino;
	),

	TP_printk(SCSBF" ino %llu last_ino %llu", SCSB_TRACE_ARGS,
		  __entry->ino, __entry->last_ino)
);

TRACE_EVENT(scoutfs_trigger_fired,
	TP_PROTO(struct super_block *sb, const char *name),

	TP_ARGS(sb, name),

	TP_STRUCT__entry(
		SCSB_TRACE_FIELDS
		__field(const char *, name)
	),

	TP_fast_assign(
		SCSB_TRACE_ASSIGN(sb);
		__entry->name = name;
	),

	TP_printk(SCSBF" %s", SCSB_TRACE_ARGS, __entry->name)
);

#endif /* _TRACE_SCOUTFS_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scoutfs_trace
#include <trace/define_trace.h>
