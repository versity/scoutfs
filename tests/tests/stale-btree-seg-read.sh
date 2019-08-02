#
# verify stale btree and segment reading
#

t_require_commands touch stat setfattr getfattr createmany
t_require_mounts 2

GETFATTR="getfattr --absolute-names"
SETFATTR="setfattr"

#
# This exercises the soft retry of btree blocks and segment reads when
# inconsistent cached versions are found.  It ensures that basic hard
# error returning turns into EIO in the case where the persistent reread
# blocks and segments really are inconsistent.
#
# The triggers apply across all execution in the file system.  So to
# trigger btree block retries in the client we make sure that the server
# is running on the other node.
#
# We need to quiesce compaction before arming stale segment triggers
# because we don't want them to hit compaction.. they're not expected
# there because the server protects compaction input segments.
# 

cl=$(t_first_client_nr)
sv=$(t_server_nr)
eval cl_dir="\$T_D${cl}"
eval sv_dir="\$T_D${sv}"

echo "== create file for xattr ping pong"
touch "$sv_dir/file"
$SETFATTR -n user.xat -v initial "$sv_dir/file"
$GETFATTR -n user.xat "$sv_dir/file" 2>&1 | t_filter_fs

echo "== retry btree block read"
$SETFATTR -n user.xat -v btree "$sv_dir/file"
t_trigger_arm btree_stale_read $cl
old=$(t_counter btree_stale_read $cl)
$GETFATTR -n user.xat "$cl_dir/file" 2>&1 | t_filter_fs
t_trigger_show btree_stale_read "after" $cl
t_counter_diff btree_stale_read $old $cl

echo "== retry segment read"
$SETFATTR -n user.xat -v segment "$sv_dir/file"
sync; sleep .5 # hopefully compaction finishes
t_trigger_arm seg_stale_read $cl
old=$(t_counter seg_stale_read $cl)
$GETFATTR -n user.xat "$cl_dir/file" 2>&1 | t_filter_fs
t_trigger_show seg_stale_read "after" $cl
t_counter_diff seg_stale_read $old $cl

echo "== get a hard error, then have it work"
$SETFATTR -n user.xat -v err "$sv_dir/file"
t_trigger_arm hard_stale_error $cl
old=$(t_counter manifest_hard_stale_error $cl)
$GETFATTR -n user.xat "$cl_dir/file" 2>&1 | t_filter_fs
t_trigger_show hard_stale_error "after" $cl
t_counter_diff manifest_hard_stale_error $old $cl
$GETFATTR -n user.xat "$cl_dir/file" 2>&1 | t_filter_fs

#
# we had bugs trying to read the manifest and segments when multiple
# segments and btree blocks were stale in memory but fine on disk.
#
# We can ensure stale cached blocks by reading on one node while
# aggressively advancing the btree ring on another.  And we can ensure
# that there are lots of stale btree blocks to walk through by using
# tiny blocks which results in a huge tree.
#

LOTS=500000
INC=1000

stat_lots() {
	local top="$1"
	local out="$2"
	local i

	for i in $(seq 1 $INC $LOTS); do
		stat "$top/dir/file_$i" | t_filter_fs
	done > "$out"
}

advance_next_half() {
	local nr="$1"
	local which="btree_advance_ring_half"

	t_trigger_arm $which $nr
	while [ "$(t_trigger_get $which $nr)" == "1" ]; do
		touch -a "$T_D0"
		sync
		sleep .1
	done
	t_trigger_show $which "after" $nr
}

echo "== read through multiple stale cached btree blocks"
# make sure we create a ton of blocks
echo 1 > "$(t_debugfs_path $sv)/options/btree_force_tiny_blocks"
cat "$(t_debugfs_path $sv)/options/btree_force_tiny_blocks"
# make enough items to create a tall tree
mkdir "$sv_dir/dir"
createmany -o "$sv_dir/dir/file_$i" $LOTS >> $T_TMP.log
# get our good stat output
stat_lots "$sv_dir" "$T_TMP.good"
# advance next block to half X
advance_next_half "$sv"
# densely fill half X with migration and start to write to half X+1
advance_next_half "$sv"
# read and cache a bunch of blocks in half X
stat_lots "$cl_dir" "$T_TMP.1"
# fill half X+1 with migration, then half X+2 (X!) with migration
advance_next_half "$sv"
advance_next_half "$sv"
# drop item cache by purging locks, forcing manifest reads
t_trigger_arm statfs_lock_purge $cl
stat -f "$cl_dir" > /dev/null
t_trigger_show statfs_lock_purge "after" $cl
# then attempt to read X+2 blocks through stale cached X blocks
stat_lots "$cl_dir" "$T_TMP.2"
# everyone needs to match
diff -u "$T_TMP.good" "$T_TMP.1"
diff -u "$T_TMP.good" "$T_TMP.2"
echo 0 > "$(t_debugfs_path $sv)/options/btree_force_tiny_blocks"
cat "$(t_debugfs_path $sv)/options/btree_force_tiny_blocks"
rm -rf "$sv_dir/dir"

t_pass
