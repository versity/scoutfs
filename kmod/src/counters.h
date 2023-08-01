#ifndef _SCOUTFS_COUNTERS_H_
#define _SCOUTFS_COUNTERS_H_

#include <linux/kobject.h>
#include <linux/completion.h>
#include <linux/percpu_counter.h>

#include "super.h"

/*
 * We only have to define each counter here and it'll be enumerated in
 * other places by this macro.  Don't forget to update LAST_COUNTER.
 */
#define EXPAND_EACH_COUNTER					\
	EXPAND_COUNTER(alloc_alloc_data)			\
	EXPAND_COUNTER(alloc_alloc_meta)			\
	EXPAND_COUNTER(alloc_free_data)				\
	EXPAND_COUNTER(alloc_free_meta)				\
	EXPAND_COUNTER(alloc_list_avail_lo)			\
	EXPAND_COUNTER(alloc_list_freed_hi)			\
	EXPAND_COUNTER(alloc_move)				\
	EXPAND_COUNTER(alloc_moved_extent)			\
	EXPAND_COUNTER(alloc_stale_list_block)			\
	EXPAND_COUNTER(block_cache_access_update)		\
	EXPAND_COUNTER(block_cache_alloc_failure)		\
	EXPAND_COUNTER(block_cache_alloc_page_order)		\
	EXPAND_COUNTER(block_cache_alloc_virt)			\
	EXPAND_COUNTER(block_cache_end_io_error)		\
	EXPAND_COUNTER(block_cache_forget)			\
	EXPAND_COUNTER(block_cache_free)			\
	EXPAND_COUNTER(block_cache_free_work)			\
	EXPAND_COUNTER(block_cache_remove_stale)		\
	EXPAND_COUNTER(block_cache_count_objects)		\
	EXPAND_COUNTER(block_cache_scan_objects)		\
	EXPAND_COUNTER(block_cache_shrink)			\
	EXPAND_COUNTER(block_cache_shrink_next)			\
	EXPAND_COUNTER(block_cache_shrink_recent)		\
	EXPAND_COUNTER(block_cache_shrink_remove)		\
	EXPAND_COUNTER(block_cache_shrink_stop)			\
	EXPAND_COUNTER(btree_compact_values)			\
	EXPAND_COUNTER(btree_compact_values_enomem)		\
	EXPAND_COUNTER(btree_delete)				\
	EXPAND_COUNTER(btree_dirty)				\
	EXPAND_COUNTER(btree_force)				\
	EXPAND_COUNTER(btree_join)				\
	EXPAND_COUNTER(btree_insert)				\
	EXPAND_COUNTER(btree_leaf_item_hash_search)		\
	EXPAND_COUNTER(btree_lookup)				\
	EXPAND_COUNTER(btree_merge)				\
	EXPAND_COUNTER(btree_merge_alloc_low)			\
	EXPAND_COUNTER(btree_merge_delete)			\
	EXPAND_COUNTER(btree_merge_delta_combined)		\
	EXPAND_COUNTER(btree_merge_delta_null)			\
	EXPAND_COUNTER(btree_merge_dirty_limit)			\
	EXPAND_COUNTER(btree_merge_drop_old)			\
	EXPAND_COUNTER(btree_merge_insert)			\
	EXPAND_COUNTER(btree_merge_update)			\
	EXPAND_COUNTER(btree_merge_walk)			\
	EXPAND_COUNTER(btree_next)				\
	EXPAND_COUNTER(btree_prev)				\
	EXPAND_COUNTER(btree_split)				\
	EXPAND_COUNTER(btree_stale_read)			\
	EXPAND_COUNTER(btree_update)				\
	EXPAND_COUNTER(btree_walk)				\
	EXPAND_COUNTER(btree_walk_restart)			\
	EXPAND_COUNTER(client_farewell_error)			\
	EXPAND_COUNTER(corrupt_btree_block_level)		\
	EXPAND_COUNTER(corrupt_btree_no_child_ref)		\
	EXPAND_COUNTER(corrupt_dirent_backref_name_len)		\
	EXPAND_COUNTER(corrupt_dirent_name_len)			\
	EXPAND_COUNTER(corrupt_dirent_readdir_name_len)		\
	EXPAND_COUNTER(corrupt_inode_block_counts)		\
	EXPAND_COUNTER(corrupt_symlink_inode_size)		\
	EXPAND_COUNTER(corrupt_symlink_missing_item)		\
	EXPAND_COUNTER(corrupt_symlink_not_null_term)		\
	EXPAND_COUNTER(data_fallocate_enobufs_retry)		\
	EXPAND_COUNTER(data_write_begin_enobufs_retry)		\
	EXPAND_COUNTER(dentry_revalidate_error)			\
	EXPAND_COUNTER(dentry_revalidate_invalid)		\
	EXPAND_COUNTER(dentry_revalidate_rcu)			\
	EXPAND_COUNTER(dentry_revalidate_root)			\
	EXPAND_COUNTER(dentry_revalidate_valid)			\
	EXPAND_COUNTER(dir_backref_excessive_retries)		\
	EXPAND_COUNTER(ext_op_insert)				\
	EXPAND_COUNTER(ext_op_next)				\
	EXPAND_COUNTER(ext_op_remove)				\
	EXPAND_COUNTER(forest_bloom_fail)			\
	EXPAND_COUNTER(forest_bloom_pass)			\
	EXPAND_COUNTER(forest_bloom_stale)			\
	EXPAND_COUNTER(forest_read_items)			\
	EXPAND_COUNTER(forest_roots_next_hint)			\
	EXPAND_COUNTER(forest_set_bloom_bits)			\
	EXPAND_COUNTER(item_cache_count_objects)		\
	EXPAND_COUNTER(item_cache_scan_objects)			\
	EXPAND_COUNTER(item_clear_dirty)			\
	EXPAND_COUNTER(item_create)				\
	EXPAND_COUNTER(item_delete)				\
	EXPAND_COUNTER(item_delta)				\
	EXPAND_COUNTER(item_delta_written)			\
	EXPAND_COUNTER(item_dirty)				\
	EXPAND_COUNTER(item_invalidate)				\
	EXPAND_COUNTER(item_invalidate_page)			\
	EXPAND_COUNTER(item_lookup)				\
	EXPAND_COUNTER(item_mark_dirty)				\
	EXPAND_COUNTER(item_next)				\
	EXPAND_COUNTER(item_page_accessed)			\
	EXPAND_COUNTER(item_page_alloc)				\
	EXPAND_COUNTER(item_page_clear_dirty)			\
	EXPAND_COUNTER(item_page_compact)			\
	EXPAND_COUNTER(item_page_free)				\
	EXPAND_COUNTER(item_page_lru_add)			\
	EXPAND_COUNTER(item_page_lru_remove)			\
	EXPAND_COUNTER(item_page_mark_dirty)			\
	EXPAND_COUNTER(item_page_rbtree_walk)			\
	EXPAND_COUNTER(item_page_split)				\
	EXPAND_COUNTER(item_pcpu_add_replaced)			\
	EXPAND_COUNTER(item_pcpu_page_hit)			\
	EXPAND_COUNTER(item_pcpu_page_miss)			\
	EXPAND_COUNTER(item_pcpu_page_miss_keys)		\
	EXPAND_COUNTER(item_read_pages_split)			\
	EXPAND_COUNTER(item_shrink_page)			\
	EXPAND_COUNTER(item_shrink_page_dirty)			\
	EXPAND_COUNTER(item_shrink_page_reader)			\
	EXPAND_COUNTER(item_shrink_page_trylock)		\
	EXPAND_COUNTER(item_update)				\
	EXPAND_COUNTER(item_write_dirty)			\
	EXPAND_COUNTER(lock_alloc)				\
	EXPAND_COUNTER(lock_count_objects)			\
	EXPAND_COUNTER(lock_free)				\
	EXPAND_COUNTER(lock_grant_request)			\
	EXPAND_COUNTER(lock_grant_response)			\
	EXPAND_COUNTER(lock_invalidate_coverage)		\
	EXPAND_COUNTER(lock_invalidate_inode)			\
	EXPAND_COUNTER(lock_invalidate_request)			\
	EXPAND_COUNTER(lock_invalidate_response)		\
	EXPAND_COUNTER(lock_invalidate_sync)			\
	EXPAND_COUNTER(lock_invalidate_work)			\
	EXPAND_COUNTER(lock_lock)				\
	EXPAND_COUNTER(lock_lock_error)				\
	EXPAND_COUNTER(lock_nonblock_eagain)			\
	EXPAND_COUNTER(lock_recover_request)			\
	EXPAND_COUNTER(lock_scan_objects)			\
	EXPAND_COUNTER(lock_shrink_attempted)			\
	EXPAND_COUNTER(lock_shrink_aborted)			\
	EXPAND_COUNTER(lock_shrink_work)			\
	EXPAND_COUNTER(lock_unlock)				\
	EXPAND_COUNTER(lock_wait)				\
	EXPAND_COUNTER(net_dropped_response)			\
	EXPAND_COUNTER(net_send_bytes)				\
	EXPAND_COUNTER(net_send_error)				\
	EXPAND_COUNTER(net_send_messages)			\
	EXPAND_COUNTER(net_recv_bytes)				\
	EXPAND_COUNTER(net_recv_dropped_duplicate)		\
	EXPAND_COUNTER(net_recv_error)				\
	EXPAND_COUNTER(net_recv_invalid_message)		\
	EXPAND_COUNTER(net_recv_messages)			\
	EXPAND_COUNTER(net_unknown_request)			\
	EXPAND_COUNTER(orphan_scan)				\
	EXPAND_COUNTER(orphan_scan_attempts)			\
	EXPAND_COUNTER(orphan_scan_cached)			\
	EXPAND_COUNTER(orphan_scan_error)			\
	EXPAND_COUNTER(orphan_scan_item)			\
	EXPAND_COUNTER(orphan_scan_omap_set)			\
	EXPAND_COUNTER(quorum_candidate_server_stopping)	\
	EXPAND_COUNTER(quorum_elected)				\
	EXPAND_COUNTER(quorum_fence_error)			\
	EXPAND_COUNTER(quorum_fence_leader)			\
	EXPAND_COUNTER(quorum_read_invalid_block)		\
	EXPAND_COUNTER(quorum_recv_error)			\
	EXPAND_COUNTER(quorum_recv_heartbeat)			\
	EXPAND_COUNTER(quorum_recv_invalid)			\
	EXPAND_COUNTER(quorum_recv_resignation)			\
	EXPAND_COUNTER(quorum_recv_vote)			\
	EXPAND_COUNTER(quorum_send_heartbeat)			\
	EXPAND_COUNTER(quorum_send_heartbeat_dropped)		\
	EXPAND_COUNTER(quorum_send_resignation)			\
	EXPAND_COUNTER(quorum_send_request)			\
	EXPAND_COUNTER(quorum_send_vote)			\
	EXPAND_COUNTER(quorum_server_shutdown)			\
	EXPAND_COUNTER(quorum_term_follower)			\
	EXPAND_COUNTER(server_commit_hold)			\
	EXPAND_COUNTER(server_commit_queue)			\
	EXPAND_COUNTER(server_commit_worker)			\
	EXPAND_COUNTER(srch_add_entry)				\
	EXPAND_COUNTER(srch_compact_dirty_block)		\
	EXPAND_COUNTER(srch_compact_entry)			\
	EXPAND_COUNTER(srch_compact_error)			\
	EXPAND_COUNTER(srch_compact_flush)			\
	EXPAND_COUNTER(srch_compact_log_page)			\
	EXPAND_COUNTER(srch_compact_removed_entry)		\
	EXPAND_COUNTER(srch_rotate_log)				\
	EXPAND_COUNTER(srch_search_log)				\
	EXPAND_COUNTER(srch_search_log_block)			\
	EXPAND_COUNTER(srch_search_retry_empty)			\
	EXPAND_COUNTER(srch_search_sorted)			\
	EXPAND_COUNTER(srch_search_sorted_block)		\
	EXPAND_COUNTER(srch_search_xattrs)			\
	EXPAND_COUNTER(srch_read_stale)				\
	EXPAND_COUNTER(statfs)					\
	EXPAND_COUNTER(totl_read_copied)			\
	EXPAND_COUNTER(totl_read_finalized)			\
	EXPAND_COUNTER(totl_read_fs)				\
	EXPAND_COUNTER(totl_read_item)				\
	EXPAND_COUNTER(totl_read_logged)			\
	EXPAND_COUNTER(trans_commit_data_alloc_low)		\
	EXPAND_COUNTER(trans_commit_dirty_meta_full)		\
	EXPAND_COUNTER(trans_commit_fsync)			\
	EXPAND_COUNTER(trans_commit_meta_alloc_low)		\
	EXPAND_COUNTER(trans_commit_sync_fs)			\
	EXPAND_COUNTER(trans_commit_timer)			\
	EXPAND_COUNTER(trans_commit_written)

#define FIRST_COUNTER	alloc_alloc_data
#define LAST_COUNTER	trans_commit_written

#undef EXPAND_COUNTER
#define EXPAND_COUNTER(which) struct percpu_counter which;

struct scoutfs_counters {
	/* $sysfs/fs/scoutfs/$id/counters/ */
	struct kobject kobj;
	struct completion comp;

	EXPAND_EACH_COUNTER
};

#define scoutfs_foreach_counter(sb, pcpu) 			\
	for (pcpu = &SCOUTFS_SB(sb)->counters->FIRST_COUNTER;	\
	     pcpu <= &SCOUTFS_SB(sb)->counters->LAST_COUNTER;	\
	     pcpu++)

/*
 * We always read with _sum, we have no use for the shared count and
 * certainly don't want to pay the cost of a shared lock to update it.
 * The default batch of 32 make counter increments show up significantly
 * in profiles.
 */
#define SCOUTFS_PCPU_COUNTER_BATCH (1 << 30)

#define scoutfs_inc_counter(sb, which)					\
	percpu_counter_add_batch(&SCOUTFS_SB(sb)->counters->which, 1,	\
				 SCOUTFS_PCPU_COUNTER_BATCH)

#define scoutfs_add_counter(sb, which, cnt)				\
	percpu_counter_add_batch(&SCOUTFS_SB(sb)->counters->which, cnt,	\
				 SCOUTFS_PCPU_COUNTER_BATCH)

void __init scoutfs_init_counters(void);
int scoutfs_setup_counters(struct super_block *sb);
void scoutfs_destroy_counters(struct super_block *sb);

#endif
