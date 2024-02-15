#
# Test correctness of the setattr_more ioctl.
#

t_require_commands filefrag-gc57857a5 scoutfs touch mkdir rm stat mknod

FILE="$T_D0/file"

echo "== 0 data_version arg fails"
touch "$FILE"
scoutfs setattr -V 0 -s 1 "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== args must specify size and offline"
touch "$FILE"
scoutfs setattr -V 1 -o -s 0 "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== only works on regular files"
mkdir "$T_D0/dir"
scoutfs setattr -V 1 -s 1 "$T_D0/dir" 2>&1 | t_filter_fs
rmdir "$T_D0/dir"
mknod "$T_D0/char" c 1 3
scoutfs setattr -V 1 -s 1 "$T_D0/char" 2>&1 | t_filter_fs
rm "$T_D0/char"

echo "== non-zero file size fails"
echo contents > "$FILE"
scoutfs setattr -V 1 -s 1 "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== non-zero file data_version fails"
touch "$FILE"
truncate -s 1M "$FILE"
truncate -s 0 "$FILE"
scoutfs setattr -V 1 -o -s 1 "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

echo "== large size is set"
touch "$FILE"
scoutfs setattr -V 1 -s 578437695752307201 "$FILE" 2>&1 | t_filter_fs
stat -c "%s" "$FILE"
rm "$FILE"

echo "== large data_version is set"
touch "$FILE"
scoutfs setattr -V 578437695752307201 -s 1 "$FILE" 2>&1 | t_filter_fs
scoutfs stat -s data_version "$FILE"
rm "$FILE"

echo "== large ctime is set"
touch "$FILE"
# only doing 32bit sec 'cause stat gets confused
scoutfs setattr -t 67305985.999999999 -V 1 -s 1 "$FILE" 2>&1 | t_filter_fs
TZ=GMT stat -c "%z" "$FILE"
rm "$FILE"

#
# With e2fsprogs-v1.42.10-10-g29758d2f, the output of filefrag 'flags' changes
# significantly. First, the _LAST flag is now output. Second, the 'unknown'
# flag is now printed out as 'unknown_loc'. To compensate for this, we check
# and replace the "correct" output for new versions here with the expected
# value.
#
echo "== large offline extents are created"
touch "$FILE"
scoutfs setattr -V 1 -o -s $((10007 * 4096)) "$FILE" 2>&1 | t_filter_fs
filefrag-gc57857a5 -v -b4096 "$FILE" 2>&1 | t_filter_fs
rm "$FILE"

# had a bug where we were creating extents that were too long
echo "== correct offline extent length"
touch "$FILE"
scoutfs setattr -V 1 -o -s 4000000000 "$FILE" 2>&1 | t_filter_fs
scoutfs stat -s offline_blocks "$FILE"
rm "$FILE"

t_pass
