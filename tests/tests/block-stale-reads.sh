#
# Exercise stale block reading.
#
# It would be very difficult to manipulate the allocators, cache, and
# persistent blocks to create stable block reading scenarios.    Instead
# we use triggers to exercise how readers encounter stale blocks.
#

t_require_commands touch setfattr getfattr

inc_wrap_fs_nr()
{
	local nr="$(($1 + 1))"

	if [ "$nr" == "$T_NR_MOUNTS" ]; then
		nr=0
	fi

	echo $nr
}

GETFATTR="getfattr --absolute-names"
SETFATTR="setfattr"

echo "== create shared test file"
touch "$T_D0/file"
$SETFATTR -n user.xat -v 0 "$T_D0/file"

#
# Trigger retries in the block cache as we bounce xattr values around
# between sequential pairs of mounts.  This is a little silly because if
# either of the mounts are the server then they'll almost certaily have
# their trigger fired prematurely by message handling btree calls while
# working with the t_ helpers long before we work with the xattrs.  But
# the block cache stale retry path is still being exercised.
#
echo "== set and get xattrs between mount pairs while retrying"
set_nr=0
get_nr=$(inc_wrap_fs_nr $set_nr)

for i in $(seq 1 10); do
	eval set_file="\$T_D${set_nr}/file"
	eval get_file="\$T_D${get_nr}/file"

	old_set=$(t_counter block_cache_remove_stale $set_nr)
	old_get=$(t_counter block_cache_remove_stale $get_nr)

	t_trigger_arm_silent block_remove_stale $set_nr
	t_trigger_arm_silent block_remove_stale $get_nr

	$SETFATTR -n user.xat -v $i "$set_file"
	$GETFATTR -n user.xat "$get_file" 2>&1 | t_filter_fs

	t_counter_diff_changed block_cache_remove_stale $old_set $set_nr
	t_counter_diff_changed block_cache_remove_stale $old_get $get_nr

	set_nr="$get_nr"
	get_nr=$(inc_wrap_fs_nr $set_nr)
done

t_pass
