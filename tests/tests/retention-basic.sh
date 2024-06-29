t_require_commands scoutfs touch rm setfattr

touch "$T_D0/file-1"

echo "== setting retention on dir fails"
scoutfs set-attr-x -t 1 "$T_D0" 2>&1 | t_filter_fs

echo "== set retention"
scoutfs set-attr-x -t 1 "$T_D0/file-1"

echo "== get-attr-x shows retention"
scoutfs get-attr-x -t "$T_D0/file-1"

echo "== unpriv can't clear retention"
setpriv --ruid=12345 --euid=12345 scoutfs set-attr-x -t 0 "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== can set hidden scoutfs xattr in retention"
setfattr -n scoutfs.hide.srch.retention_test -v val "$T_D0/file-1"

echo "== setting user. xattr fails in retention"
setfattr -n user.retention_test -v val "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== file deletion fails in retention"
rm -f "$T_D0/file-1" 2>&1 | t_filter_fs

echo "== file rename fails in retention"
mv $T_D0/file-1 $T_D0/file-2 2>&1 | t_filter_fs

echo "== file write fails in retention"
date >> $T_D0/file-1

echo "== file truncate fails in retention"
truncate -s 0 $T_D0/file-1 2>&1 | t_filter_fs

echo "== setattr fails in retention"
touch $T_D0/file-1 2>&1 | t_filter_fs

echo "== clear retention"
scoutfs set-attr-x -t 0 "$T_D0/file-1"

echo "== file write"
date >> $T_D0/file-1

echo "== file rename"
mv $T_D0/file-1 $T_D0/file-2
mv $T_D0/file-2 $T_D0/file-1

echo "== setattr"
touch $T_D0/file-1 2>&1 | t_filter_fs

echo "== xattr deletion"
setfattr -x scoutfs.hide.srch.retention_test "$T_D0/file-1"

echo "== cleanup"
rm -f "$T_D0/file-1"

t_pass
