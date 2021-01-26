#
# Test basic correctness of inode deletion behavior across nodes
#

t_require_mounts 2

echo "== open a file and delete it cross-mount"
# write some file contents on mount 0
echo "hellothere" > "$T_D0/file"
# hold a read file descriptor open on mount 0
exec 42< "$T_D0/file"
# unlink the file on mount 1
rm -f "$T_D1/file"
t_sync_seq_index

# verify inode is not yet deletable
echo "orphan list present $(cat $(t_sysfs_path 1)/forest/orphan_list_present_hint)"

# make sure we can still read through fd on mount 0
# This actually doesn't seem to close fd.
cat <&42
# close it for real
exec 42>&-

# now deletable but we don't know it until the orphans are processed again
echo "orphan list present $(cat $(t_sysfs_path 1)/forest/orphan_list_present_hint)"

t_sync_seq_index
sleep 1

# verify inode is now off the orphan list and actually deleted
echo "orphan list present $(cat $(t_sysfs_path 1)/forest/orphan_list_present_hint)"

t_pass
