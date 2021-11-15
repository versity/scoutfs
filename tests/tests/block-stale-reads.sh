#
# Exercise stale block reading.
#
# It would be very difficult to manipulate the allocators, cache, and
# persistent blocks to create stable block reading scenarios.    Instead
# we use triggers to exercise how readers encounter stale blocks.
#
# Trigger retries in the block cache by calling scoutfs df
# which in turn will call scoutfs_ioctl_alloc_detail. This
# is guaranteed to exist, which will force block cache reads.

echo "== Issue scoutfs df to force block reads to trigger stale invalidation/retry"
nr=0

old=$(t_counter block_cache_remove_stale $nr)
t_trigger_arm_silent block_remove_stale $nr

scoutfs df -p "$T_M0" > /dev/null

t_counter_diff_changed block_cache_remove_stale $old $nr

t_pass
