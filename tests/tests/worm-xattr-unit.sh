t_require_commands touch rm setfattr

touch "$T_D0/file-1"
SECS=$(date '+%s')
NSECS=$(date '+%N')
DELAY=10
EXP=$((SECS + DELAY))

echo "== worm xattr creation without .hide. fails"
setfattr -n scoutfs.worm.level1_expire -v $EXP.$NSECS "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== worm xattr creation on dir fails"
setfattr -n scoutfs.hide.worm.level1_expire -v $EXP.$NSECS "$T_D0" 2>&1 | t_filter_fs

echo "== worm xattr creation"
setfattr -n scoutfs.hide.worm.level1_expire -v $EXP.$NSECS "$T_D0/file-1"

echo "== get correct parsed timespec value"
diff -u --ignore-all-space <(echo "$EXP.$NSECS") <(getfattr --absolute-names --only-values -n scoutfs.hide.worm.level1_expire -m - "$T_D0/file-1")

echo "== hidden scoutfs xattrs before expire"
setfattr -n scoutfs.hide.srch.worm_test -v val "$T_D0/file-1"

echo "== user xattr creation before expire fails"
setfattr -n user.worm_test -v val "$T_D0/file-1"

echo "== worm xattr deletion before expire fails"
setfattr -x scoutfs.hide.worm.level1_expire "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== worm xattr update before expire fails"
setfattr -n scoutfs.hide.worm.level1_expire -v $SECS.$NSECS "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== other worm xattr create before expire fails"
setfattr -n scoutfs.hide.worm.other.level1_expire -v 123.456 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== file deletion before expire fails"
rm -f "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== file rename before expire fails"
mv $T_D0/file-1 $T_D0/file-2 2>&1 | t_filter_fs

echo "== file write before expire fails"
date >> $T_D0/file-1

echo "== file truncate before expire fails"
truncate -s 0 $T_D0/file-1 2>&1 | t_filter_fs

echo "== file inode update before expire fails"
touch $T_D0/file-1 2>&1 | t_filter_fs

echo "== wait until expiration"
sleep $((DELAY + 1))

echo "== file write after expire"
date >> $T_D0/file-1

echo "== file rename after expire"
mv $T_D0/file-1 $T_D0/file-2
mv $T_D0/file-2 $T_D0/file-1

echo "== other worm xattr create after expire fails"
setfattr -n scoutfs.hide.worm.other.level1_expire -v 123.456 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== xattr deletion after expire"
setfattr -x scoutfs.hide.worm.level1_expire "$T_D0/file-1"

echo "== invalid all zero expire value"
setfattr -n scoutfs.hide.worm.level1_expire -v 0.0 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== invalid non integer expire value"
setfattr -n scoutfs.hide.worm.level1_expire -v a.a "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== invalid only dots dots expire value"
setfattr -n scoutfs.hide.worm.level1_expire -v . "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v .. "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v ... "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== invalid mixed dots secs expire value"
setfattr -n scoutfs.hide.worm.level1_expire -v 11 "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v .11 "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v 11. "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v .11. "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v .1.1. "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== invalid (u32)(u64) nsecs expire value"
setfattr -n scoutfs.hide.worm.level1_expire -v 1.1000000000 "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v 1.4294967296 "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v 1.18446744073709551615 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== invalid negative (signed)(u64) secs expire value"
setfattr -n scoutfs.hide.worm.level1_expire -v 9223372036854775808.1 "$T_D0/file-1" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.worm.level1_expire -v 18446744073709551615.1 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== cleanup"
rm -f "$T_D0/file-1"

t_pass
