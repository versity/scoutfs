
TEST_UID=22222
TEST_GID=44444

# sys_setreuid() set fs[uid] to e[ug]id
SET_UID="--ruid=$TEST_UID --euid=$TEST_UID"
SET_GID="--rgid=$TEST_GID --egid=$TEST_GID --clear-groups"

FILE="$T_D0/dir/file"

sync_and_drop()
{
	sync
	echo 1 > $(t_debugfs_path)/drop_weak_item_cache
	echo 1 > $(t_debugfs_path)/drop_quota_check_cache
}

reset_all()
{
	rm -f "$FILE"
	scoutfs quota-wipe -p "$T_M0"
	getfattr --absolute-names -d -m - "$T_D0" | \
		grep "^scoutfs.totl." | \
		cut -d '=' -f 1 | \
		xargs -I'{}'  setfattr -x '{}' "$T_D0"
}

echo "== prepare dir with write perm for test ids"
mkdir "$T_D0/dir"
chown --quiet $TEST_UID "$T_D0/dir"
chgrp --quiet $TEST_GID "$T_D0/dir"

echo "== test assumes starting with no rules, empty list"
scoutfs quota-list -p "$T_M0"

echo "== add rule"
scoutfs quota-add -p "$T_M0" -r "7 13,L,- 15,L,- 17,L,- I 33 -"
scoutfs quota-list -p "$T_M0"

echo "== list is empty again after delete"
scoutfs quota-del -p "$T_M0" -r "7 13,L,- 15,L,- 17,L,- I 33 -"
scoutfs quota-list -p "$T_M0"

echo "== can change limits without deleting"
scoutfs quota-add -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 100 -"
scoutfs quota-list -p "$T_M0"
scoutfs quota-add -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 101 -"
scoutfs quota-del -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 100 -"
scoutfs quota-list -p "$T_M0"
scoutfs quota-add -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 99 -"
scoutfs quota-del -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 101 -"
scoutfs quota-list -p "$T_M0"
scoutfs quota-del -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 99 -"
reset_all

echo "== wipe and restore rules in bulk"
for a in $(seq 10 15); do
	scoutfs quota-add -p "$T_M0" -r "7 $a,L,- 0,L,- 0,L,- I 33 -"
done
scoutfs quota-list -p "$T_M0"
scoutfs quota-list -p "$T_M0" > "$T_TMP.list"
scoutfs quota-wipe -p "$T_M0"
scoutfs quota-list -p "$T_M0"
scoutfs quota-restore -p "$T_M0" < "$T_TMP.list"
scoutfs quota-list -p "$T_M0"
reset_all

echo "== default rule prevents file creation"
scoutfs quota-add -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 1 -"
setfattr -n scoutfs.totl.test.1.1.1 -v 2 "$T_D0"
sync_and_drop
setpriv $SET_UID touch "$FILE" 2>&1 | t_filter_fs

echo "== decreasing totl allows file creation again"
setfattr -x scoutfs.totl.test.1.1.1 "$T_D0"
sync_and_drop
setpriv $SET_UID touch "$FILE"
reset_all

echo "== attr selecting rules prevent creation"
scoutfs quota-add -p "$T_M0" -r "1 $TEST_UID,U,S 1,L,- 1,L,- I 1 -"
scoutfs quota-add -p "$T_M0" -r "1 $TEST_GID,G,S 1,L,- 1,L,- I 1 -"
setfattr -n scoutfs.totl.test.$TEST_UID.1.1 -v 2 "$T_D0"
setfattr -n scoutfs.totl.test.$TEST_GID.1.1 -v 2 "$T_D0"
sync_and_drop
setpriv $SET_UID touch "$FILE" 2>&1 | t_filter_fs
setpriv $SET_GID touch "$FILE" 2>&1 | t_filter_fs
reset_all

echo "== multi attr selecting doesn't prevent partial"
scoutfs quota-add -p "$T_M0" -r "1 $TEST_UID,U,S $TEST_GID,G,S 1,L,- I 1 -"
setfattr -n scoutfs.totl.test.$TEST_UID.$TEST_GID.1 -v 2 "$T_D0"
sync_and_drop
setpriv $SET_UID touch "$FILE"
rm -f "$FILE"
setpriv $SET_GID touch "$FILE"
rm -f "$FILE"
setpriv $SET_UID $SET_GID touch "$FILE" 2>&1 | t_filter_fs
reset_all

echo "== op differentiates"
# inode ops succeed in presence of data rule
scoutfs quota-add -p "$T_M0" -r "1 $TEST_UID,U,S 1,L,- 1,L,- D 1 -"
setfattr -n scoutfs.totl.test.$TEST_UID.1.1 -v 2 "$T_D0"
sync_and_drop
setpriv $SET_UID touch "$FILE" 2>&1 | t_filter_fs
reset_all
# data ops succeed in presence of inode rule
touch "$FILE"
chown --quiet $TEST_UID "$FILE"
scoutfs quota-add -p "$T_M0" -r "1 $TEST_UID,U,S 1,L,- 1,L,- I 1 -"
setfattr -n scoutfs.totl.test.$TEST_UID.1.1 -v 2 "$T_D0"
sync_and_drop
setpriv $SET_UID fallocate -l 4096 "$FILE" 2>&1 | t_filter_fs
reset_all

echo "== higher priority rule applies"
scoutfs quota-add -p "$T_M0" -r "1 $TEST_UID,U,S 1,L,- 1,L,- I 1000 -"
scoutfs quota-add -p "$T_M0" -r "2 $TEST_UID,U,S 1,L,- 1,L,- I 1 -"
setfattr -n scoutfs.totl.test.$TEST_UID.1.1 -v 2 "$T_D0"
sync_and_drop
setpriv $SET_UID touch "$FILE" 2>&1 | t_filter_fs
reset_all

echo "== data rules with total and count prevent write and fallocate" 
touch "$FILE"
scoutfs quota-add -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- D 1 -"
setfattr -n scoutfs.totl.test.1.1.1 -v 2 "$T_D0"
sync_and_drop
dd if=/dev/zero of="$FILE" bs=4096 count=1 conv=notrunc status=none 2>&1 | t_filter_fs
fallocate -l 4096 "$FILE" 2>&1 | t_filter_fs
scoutfs quota-del -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- D 1 -"
scoutfs quota-add -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- D 0 C"
sync_and_drop
dd if=/dev/zero of="$FILE" bs=4096 count=1 conv=notrunc status=none 2>&1 | t_filter_fs
fallocate -l 4096 "$FILE" 2>&1 | t_filter_fs
reset_all

echo "== added rules work after bulk restore"
seq -f "  1 %.0f,U,S 1,L,- 1,L,- I 1 -" 9000050000 -1 9000000000 > "$T_TMP.lots"
scoutfs quota-restore -p "$T_M0" < "$T_TMP.lots"
scoutfs quota-list -p "$T_M0" > "$T_TMP.list"
diff -u "$T_TMP.lots" "$T_TMP.list"
scoutfs quota-add -p "$T_M0" -r "1 $TEST_UID,U,S 1,L,- 1,L,- I 1 -"
setfattr -n scoutfs.totl.test.$TEST_UID.1.1 -v 2 "$T_D0"
sync_and_drop
setpriv $SET_UID touch "$FILE" 2>&1 | t_filter_fs
reset_all

echo "== cleanup"
rm -f "$T_TMP.lots" "$T_TMP.list"

t_pass
