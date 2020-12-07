#
# test inode item updating
#
# Our inode updating pattern involves updating in-memory inode
# structures and then explicitly migrating those to dirty persistent
# items.  If we forget to update the persistent items then modifications
# to the in-memory inode can be lost as the inode is evicted.
#
# We test this by modifying inodes, unmounting, and comparing the
# mounted inodes to the inodes before the unmount.
#

t_require_commands mkdir stat touch find setfattr mv dd scoutfs

DIR="$T_D0/dir"

stat_paths()
{
	while read path; do
		echo "=== $path ==="
		# XXX atime isn't consistent :/
		stat "$path" 2>&1 | grep -v "Access: "
		scoutfs stat "$path" 2>&1
	done
}

t_quiet mkdir -p "$DIR"

echo "== create files and sync"
dd if=/dev/zero of="$DIR/truncate" bs=4096 count=1 status=none
dd if=/dev/zero of="$DIR/stage" bs=4096 count=1 status=none
vers=$(scoutfs stat -s data_version "$DIR/stage")
scoutfs release "$DIR/stage" $vers 0 1
dd if=/dev/zero of="$DIR/release" bs=4096 count=1 status=none
touch "$DIR/write_end"
mkdir "$DIR"/{mknod_dir,link_dir,unlink_dir,symlink_dir,rename_dir}
touch $DIR/setattr
touch $DIR/xattr_set
sync; sync

echo "== modify files" 
truncate -s 0 "$DIR/truncate"
vers=$(scoutfs stat -s data_version "$DIR/stage")
scoutfs stage "$DIR/stage" $vers 0 4096 /dev/zero
vers=$(scoutfs stat -s data_version "$DIR/release")
scoutfs release "$DIR/release" $vers 0 1
dd if=/dev/zero of="$DIR/write_end" bs=4096 count=1 status=none conv=notrunc
touch $DIR/mknod_dir/mknod_file
touch $DIR/link_dir/link_targ
ln $DIR/link_dir/link_targ $DIR/link_dir/link_file
touch $DIR/unlink_dir/unlink_file
rm -f $DIR/unlink_dir/unlink_file
touch $DIR/symlink_dir/symlink_targ
ln -s $DIR/symlink_dir/symlink_targ $DIR/symlink_dir/symlink_file
touch $DIR/rename_dir/rename_from
mv $DIR/rename_dir/rename_from $DIR/rename_dir/rename_to
touch -m --date=@1234 $DIR/setattr
setfattr -n user.test -v val $DIR/xattr_set

find "$DIR"/* > $T_TMP.paths
echo $DIR/unlink_dir/unlink_file >> $T_TMP.paths
echo $DIR/rename_dir/rename_from >> $T_TMP.paths
stat_paths < $T_TMP.paths > $T_TMP.before

echo "== mount and unmount"
t_umount_all
t_mount_all

echo "== verify files"
stat_paths < $T_TMP.paths > $T_TMP.after
diff -u $T_TMP.before $T_TMP.after

t_pass
