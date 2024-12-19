#
# validate parallel restore library - using restore_copy.c
#

t_require_commands scoutfs restore_copy find xargs

SCR="$T_TMPDIR/mnt.scratch"
mkdir -p "$SCR"

scratch_mkfs() {
	scoutfs mkfs $@ \
		-A -f -Q 0,127.0.0.1,53000 $T_EX_META_DEV $T_EX_DATA_DEV
}

scratch_check() {
	# give ample time for writes to commit
	sleep 1
	sync
	scoutfs check -d ${T_TMPDIR}/check.debug $T_EX_META_DEV $T_EX_DATA_DEV
}

scratch_mount() {
	mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 $T_EX_DATA_DEV $SCR
}

echo "== restore_copy content verification"
mkdir "$T_M0/data"

# create all supported inode types:
mkdir -p "$T_M0/data/d"
touch "$T_M0/data/f"
ln -sf "broken" "$T_M0/data/l"
ln "$T_M0/data/f" "$T_M0/data/h"
ln -sf "f" "$T_M0/data/F"
mknod "$T_M0/data/b" b 1 1
mknod "$T_M0/data/c" c 0 0
mknod "$T_M0/data/u" u 2 2
mknod "$T_M0/data/p" p

# some files with data
dd if=/dev/zero of="$T_M0/data/f4096" bs=4096 count=1 status=none
touch "$T_M0/data/falloc" "$T_M0/data/truncate"
xfs_io -c "falloc 65536 65536" "$T_M0/data/falloc"
xfs_io -c "truncate $((4096 * 4096))" "$T_M0/data/truncate"

# socket (could have used python but avoids python/python2/python3 problem)
perl -e "use IO::Socket; my \$s = IO::Socket::UNIX->new(Type=>SOCK_STREAM,Local=>'$T_M0/data/s') or die 'sock';"
# set all mode_t bits
touch "$T_M0/data/mode_t"
chmod 6777 "$T_M0/data/mode_t"
# uid/gid
touch "$T_M0/data/uidgid"
chown 33333:33333 "$T_M0/data/uidgid"
# set retention bit
touch "$T_M0/data/retention"
scoutfs set-attr-x -t 1 "$T_M0/data/retention"
# set project ID
touch "$T_M0/data/proj"
scoutfs set-attr-x -p 12345 "$T_M0/data/proj"
# quotas
for a in $(seq 10 15); do
	scoutfs quota-add -p "$T_M0" -r "7 $a,L,- 0,L,- 0,L,- I 33 -"
done

scratch_mkfs -V 2 -m 10G -d 10G > $T_TMP.mkfs.out 2>&1 || t_fail "mkfs failed"
restore_copy -m $T_EX_META_DEV -s "$T_M0/data" | t_filter_fs
scratch_check || t_fail "check before mount failed"

scratch_mount

echo "== verify metadata bits on restored fs"
inspect() {
	ls -Alnr --time-style=+""
	scoutfs get-attr-x -t "retention"
	scoutfs get-attr-x -p "proj"
	scoutfs get-fiemap -L "f4096"
	scoutfs get-fiemap -L "falloc"
	scoutfs get-fiemap -L "truncate"
	scoutfs quota-list -p "."
}

( cd "$SCR" ; inspect )

scoutfs df -p "$SCR"

echo "== umount restored fs and check"
umount "$SCR"
scratch_check || t_fail "check after mount failed"

#scoutfs print $T_META_DEVICE
#scoutfs print $T_EX_META_DEV

echo "== cleanup"
rmdir "$SCR"
scoutfs set-attr-x -t 0 "$T_M0/data/retention"
rm -rf "$T_M0/data"
scoutfs quota-wipe -p "$T_M0"

t_pass
