t_require_commands touch rm setfattr

touch "$T_D0/file-1"
SECS=$(date '+%s')
NSECS=$(date '+%N')
DELAY=10
EXP=$(( $SECS + $DELAY ))
EXP_DELAY=$(( $DELAY + 2 ))

echo "== test creation of worm xattr without .hide"
setfattr -n scoutfs.worm.v1_expiration -v $EXP.$NSECS "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation of worm xattr on a directory"
setfattr -n scoutfs.worm.v1_expiration -v $EXP.$NSECS "$T_D0" 2>&1 | t_filter_fs

echo "== test creation of worm xattr"
setfattr -n scoutfs.hide.worm.v1_expiration -v $EXP.$NSECS "$T_D0/file-1"

echo "== test value is set correctly"
diff -u --ignore-all-space <(echo "$EXP.$NSECS") <(getfattr --absolute-names --only-values -n scoutfs.hide.worm.v1_expiration -m - "$T_D0/file-1")

echo "== test deletion of xattr 1 sec after setting"
sleep 1
setfattr -x scoutfs.hide.worm.v1_expiration "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test setting xattr to a previous time after setting"
setfattr -n scoutfs.hide.worm.v1_expiration -v $SECS.$NSECS "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test deletion before expiration"
rm -f "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== Try to move the file prior to expiration"
mv $T_D0/file-1 $T_D0/file-2 2>&1 | t_filter_fs

echo "== Try to write to file before expiration"
date >> $T_D0/file-1

echo "== wait til expiration"
sleep $EXP_DELAY

echo "== Try to write to file after expiration"
date >> $T_D0/file-1

echo "== Try to move the file after expiration"
mv $T_D0/file-1 $T_D0/file-2
mv $T_D0/file-2 $T_D0/file-1

echo "== test deletion after expiration"
setfattr -x scoutfs.hide.worm.v1_expiration "$T_D0/file-1"

echo "== test creation with non integer value of a.a"
setfattr -n scoutfs.hide.worm.v1_expiration -v a.a "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with non integer value of ...."
setfattr -n scoutfs.hide.worm.v1_expiration -v .... "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with non integer value of ..."
setfattr -n scoutfs.hide.worm.v1_expiration -v ... "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with no nsec value of 11."
setfattr -n scoutfs.hide.worm.v1_expiration -v 11. "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with no sec value of .11"
setfattr -n scoutfs.hide.worm.v1_expiration -v .11 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with . at start and end value .11."
setfattr -n scoutfs.hide.worm.v1_expiration -v .11. "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with invalid format of two characters"
setfattr -n scoutfs.hide.worm.v1_expiration -v 11 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with too large of a nsecs value 1.18446744073709551615"
setfattr -n scoutfs.hide.worm.v1_expiration -v 1.18446744073709551615 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with nsecs > NSECS_PER_SEC value 1.1000000000"
setfattr -n scoutfs.hide.worm.v1_expiration -v 1.1000000000 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== test creation with sec > U64_MAX value of 184467440737095516159.1"
setfattr -n scoutfs.hide.worm.v1_expiration -v 184467440737095516159.1 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== removing files after expiration"
rm -f "$T_D0/file-1"

t_pass
