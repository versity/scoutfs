#
# Test basic clustered posix consistency.  We perform a bunch of
# operations in one mount and verify the results in another.
#

t_require_commands getfattr setfattr dd filefrag diff touch stat scoutfs
t_require_mounts 2

GETFATTR="getfattr --absolute-names"
SETFATTR="setfattr"
DD="dd status=none"
FILEFRAG="filefrag -v -b4096"

echo "== root inode updates flow back and forth"
sleep 1
touch "$T_M1"
stat "$T_M0" 2>&1 | t_filter_fs > "$T_TMP.0"
stat "$T_M1" 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
sleep 1
touch "$T_M0"
stat "$T_M0" 2>&1 | t_filter_fs > "$T_TMP.0"
stat "$T_M1" 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== stat of created file matches"
touch "$T_D0/file"
stat "$T_D0/file" 2>&1 | t_filter_fs > "$T_TMP.0"
stat "$T_D1/file" 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== written file contents match"
$DD if=/dev/urandom of="$T_D0/file" bs=4K count=1024
od -x "$T_D0/file" > "$T_TMP.0"
od -x "$T_D1/file" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== overwritten file contents match"
$DD if=/dev/urandom of="$T_D0/file" bs=4K count=1024 conv=notrunc
od -x "$T_D0/file" > "$T_TMP.0"
od -x "$T_D1/file" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== appended file contents match"
$DD if=/dev/urandom of="$T_D0/file" bs=1 count=1 conv=notrunc oflag=append
od -x "$T_D0/file" > "$T_TMP.0"
od -x "$T_D1/file" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== fiemap matches after racey appends"
for i in $(seq 1 10); do
	$DD if=/dev/urandom of="$T_D0/file" bs=4096 count=1 \
		conv=notrunc oflag=append &
	$DD if=/dev/urandom of="$T_D1/file" bs=4096 count=1 \
		conv=notrunc oflag=append &
	wait
done
$FILEFRAG "$T_D0/file" | t_filter_fs > "$T_TMP.0"
$FILEFRAG "$T_D1/file" | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== unlinked file isn't found"
rm -f "$T_D0/file"
stat "$T_D0/file" 2>&1 | t_filter_fs > "$T_TMP.0"
stat "$T_D1/file" 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== symlink targets match"
ln -s "$T_D0/file.targ" "$T_D0/file"
readlink "$T_D0/file" | t_filter_fs
readlink "$T_D1/file" | t_filter_fs
rm -f "$T_D1/file"
ln -s "$T_D0/file.targ2" "$T_D0/file"
readlink "$T_D0/file" | t_filter_fs
readlink "$T_D1/file" | t_filter_fs
rm -f "$T_D1/file"

echo "== new xattrs are visible"
touch "$T_D0/file"
$SETFATTR -n user.xat -v 1 "$T_D0/file"
$GETFATTR -n user.xat "$T_D0/file" 2>&1 | t_filter_fs
$GETFATTR -n user.xat "$T_D1/file" 2>&1 | t_filter_fs

echo "== modified xattrs are updated"
$SETFATTR -n user.xat -v 2 "$T_D1/file"
$GETFATTR -n user.xat "$T_D0/file" 2>&1 | t_filter_fs
$GETFATTR -n user.xat "$T_D1/file" 2>&1 | t_filter_fs

echo "== deleted xattrs"
$SETFATTR -x user.xat "$T_D0/file"
$GETFATTR -n user.xat "$T_D0/file" 2>&1 | t_filter_fs
$GETFATTR -n user.xat "$T_D1/file" 2>&1 | t_filter_fs
rm -f "$T_D1/file"

echo "== readdir after modification"
mkdir "$T_D0/dir"
ls -UA "$T_D0/dir"
ls -UA "$T_D1/dir"
touch "$T_D1/dir"/{one,two,three,four}
ls -UA "$T_D0/dir"
ls -UA "$T_D1/dir"
rm -f "$T_D0/dir"/{one,three}
ls -UA "$T_D0/dir"
ls -UA "$T_D1/dir"
rm -f "$T_D0/dir"/{two,four}
ls -UA "$T_D0/dir"
ls -UA "$T_D1/dir"

echo "== can delete empty dir"
rmdir "$T_D1/dir"

echo "== some easy rename cases"
echo "--- file between dirs"
mkdir -p "$T_D0/dir/a"
mkdir -p "$T_D0/dir/b"
touch "$T_D0/dir/a/file"
mv "$T_D1/dir/a/file" "$T_D1/dir/b/file"
find "$T_D0/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.0"
find "$T_D1/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
echo "--- file within dir"
mv "$T_D1/dir/b/file" "$T_D1/dir/b/file2"
find "$T_D0/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.0"
find "$T_D1/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
echo "--- dir within dir"
mv "$T_D0/dir/b" "$T_D0/dir/c"
find "$T_D0/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.0"
find "$T_D1/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
echo "--- overwrite file"
touch "$T_D1/dir/c/file"
mv "$T_D0/dir/c/file2" "$T_D0/dir/c/file"
find "$T_D0/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.0"
find "$T_D1/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
echo "--- can't overwrite non-empty dir"
mkdir "$T_D0/dir/a/dir"
touch "$T_D0/dir/a/dir/nope"
mkdir "$T_D1/dir/c/clobber"
mv -T "$T_D1/dir/c/clobber" "$T_D1/dir/a/dir" 2>&1 | t_filter_fs
find "$T_D0/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.0"
find "$T_D1/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
echo "--- can overwrite empty dir"
rm "$T_D0/dir/a/dir/nope"
mv -T "$T_D1/dir/c/clobber" "$T_D1/dir/a/dir"
find "$T_D0/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.0"
find "$T_D1/dir" -ls 2>&1 | t_filter_fs > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
rm -rf "$T_D0/dir"

echo "== path resoluion"
touch "$T_D0/file"
ino=$(stat -c '%i' $T_D0/file)
for i in $(seq 1 1); do
	for j in $(seq 1 4); do
		lnk="$T_D0/dir/$RANDOM/$RANDOM/$RANDOM/$RANDOM"

		mkdir -p $(dirname $lnk)
		ln "$T_D0/file" $lnk

		scoutfs ino-path $ino "$T_M0" > "$T_TMP.0"
		scoutfs ino-path $ino "$T_M1" > "$T_TMP.1"
		diff -u "$T_TMP.0" "$T_TMP.1"
	done
done
rm -rf "$T_D0/dir"

echo "== inode indexes match after syncing existing"
t_sync_seq_index
scoutfs walk-inodes meta_seq 0 -1 "$T_M0" > "$T_TMP.0"
scoutfs walk-inodes meta_seq 0 -1 "$T_M1" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
scoutfs walk-inodes data_seq 0 -1 "$T_M0" > "$T_TMP.0"
scoutfs walk-inodes data_seq 0 -1 "$T_M1" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== inode indexes match after copying and syncing"
mkdir "$T_D0/dir"
cp -ar /boot/conf* "$T_D0/dir"
t_sync_seq_index
scoutfs walk-inodes meta_seq 0 -1 "$T_M0" > "$T_TMP.0"
scoutfs walk-inodes meta_seq 0 -1 "$T_M1" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
scoutfs walk-inodes data_seq 0 -1 "$T_M0" > "$T_TMP.0"
scoutfs walk-inodes data_seq 0 -1 "$T_M1" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

echo "== inode indexes match after removing and syncing"
rm -f "$T_D1/dir/conf*"
t_sync_seq_index
scoutfs walk-inodes meta_seq 0 -1 "$T_M0" > "$T_TMP.0"
scoutfs walk-inodes meta_seq 0 -1 "$T_M1" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"
scoutfs walk-inodes data_seq 0 -1 "$T_M0" > "$T_TMP.0"
scoutfs walk-inodes data_seq 0 -1 "$T_M1" > "$T_TMP.1"
diff -u "$T_TMP.0" "$T_TMP.1"

t_pass
