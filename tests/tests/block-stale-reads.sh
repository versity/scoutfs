#
# exercise stale block reading.
#
# It would be very difficult to manipulate the allocators, cache, and
# persistent blocks to create stable block reading scenarios.    Instead
# we use triggers to exercise how readers encounter stale blocks.
#

t_require_commands touch setfattr getfattr
t_require_mounts 2

GETFATTR="getfattr --absolute-names"
SETFATTR="setfattr"

#
# force re-reading forest btree blocks as each mount reads the items
# written by the other.
#
set_file="$T_D0/file"
get_file="$T_D1/file"
echo "== create file for xattr ping pong"
touch "$set_file"
$SETFATTR -n user.xat -v initial "$set_file"
$GETFATTR -n user.xat "$get_file" 2>&1 | t_filter_fs

echo "== retry btree forest reads between mounts" 
for i in $(seq 1 4); do
	tmp="$set_file"
	set_file="$get_file"
	get_file="$tmp"

	$SETFATTR -n user.xat -v $i "$set_file"
	t_trigger_arm block_remove_stale $cl
	old=$(t_counter btree_stale_read $cl)
	$GETFATTR -n user.xat "$get_file" 2>&1 | t_filter_fs
	t_trigger_show block_remove_stale "after" $cl
	t_counter_diff block_cache_remove_stale $old $cl
done

t_pass
