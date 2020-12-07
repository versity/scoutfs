#
# verify stale btree block reading
#

t_require_commands touch stat setfattr getfattr createmany
t_require_mounts 2

GETFATTR="getfattr --absolute-names"
SETFATTR="setfattr"

#
# This exercises the soft retry of btree blocks when
# inconsistent cached versions are found.  It ensures that basic hard
# error returning turns into EIO in the case where the persistent reread
# blocks and segments really are inconsistent.
#
# The triggers apply across all execution in the file system.  So to
# trigger btree block retries in the client we make sure that the server
# is running on the other node.
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

t_pass
