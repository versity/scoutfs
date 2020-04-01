#
# Test correctness of the setattr_more ioctl.
#

t_require_commands filefrag scoutfs touch mkdir rm stat mknod

FILE="$T_D0/file"

echo "== 0 data_version arg fails"
touch "$FILE"
scoutfs setattr -d 0 -s 1 -f "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== args must specify size and offline"
touch "$FILE"
scoutfs setattr -d 1 -o -s 0 -f "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== only works on regular files"
mkdir "$T_D0/dir"
scoutfs setattr -d 1 -s 1 -f "$T_D0/dir" 2>&1 | t_filter_fs
rmdir "$T_D0/dir"
mknod "$T_D0/char" c 1 3
scoutfs setattr -d 1 -s 1 -f "$T_D0/char" 2>&1 | t_filter_fs
rm "$T_D0/char"

echo "== non-zero file size fails"
echo contents > "$FILE"
scoutfs setattr -d 1 -s 1 -f "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== non-zero file data_version fails"
touch "$FILE"
truncate -s 1M "$FILE"
truncate -s 0 "$FILE"
scoutfs setattr -d 1 -o -s 1 -f "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== large size is set"
touch "$FILE"
scoutfs setattr -d 1 -s 578437695752307201 -f "$FILE" 2>&1 | t_filter_fs
stat -c "%s" "$FILE"
rm "$FILE"

echo "== large data_version is set"
touch "$FILE"
scoutfs setattr -d 578437695752307201 -s 1 -f "$FILE" 2>&1 | t_filter_fs
scoutfs stat -s data_version "$FILE"
rm "$FILE"

echo "== large ctime is set"
touch "$FILE"
# only doing 32bit sec 'cause stat gets confused
scoutfs setattr -c 67305985.999999999 -d 1 -s 1 -f "$FILE" 2>&1 | t_filter_fs
TZ=GMT stat -c "%z" "$FILE"
rm "$FILE"

echo "== large offline extents are created"
touch "$FILE"
scoutfs setattr -d 1 -o -s $((10007 * 4096)) -f "$FILE" 2>&1 | t_filter_fs
filefrag -v -b4096 "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

# had a bug where we were creating extents that were too long
echo "== correct offline extent length"
touch "$FILE"
scoutfs setattr -d 1 -o -s 4000000000 -f "$FILE" 2>&1 | t_filter_fs
scoutfs stat -s offline_blocks "$FILE"
rm "$FILE"

t_pass
