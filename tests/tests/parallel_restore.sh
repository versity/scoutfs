#
# validate parallel restore library
#

t_require_commands scoutfs parallel_restore find xargs

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

echo "== simple mkfs/restore/mount"
# meta device just big enough for reserves and the metadata we'll fill
scratch_mkfs -V 2 -m 10G -d 60G > $T_TMP.mkfs.out 2>&1 || t_fail "mkfs failed"
parallel_restore -m "$T_EX_META_DEV" > /dev/null || t_fail "parallel_restore"
scratch_check || t_fail "check failed"
scratch_mount

scoutfs statfs -p "$SCR" | grep -v -e 'fsid' -e 'rid'
find "$SCR" -exec scoutfs list-hidden-xattrs {} \; | wc
scoutfs search-xattrs -p "$SCR" scoutfs.hide.srch.sam_vol_F01030L6 -p "$SCR" | wc
find "$SCR" -type f -name "file-*" | head -n 4 | xargs -n 1 scoutfs get-fiemap -L
scoutfs df -p "$SCR" | awk '{print $1, $4}'
scoutfs quota-list -p "$SCR"

umount "$SCR"
scratch_check || t_fail "check after mount failed"

echo "== under ENOSPC"
scratch_mkfs -V 2 -m 10G -d 60G > $T_TMP.mkfs.out 2>&1 || t_fail "mkfs failed"
parallel_restore -m "$T_EX_META_DEV" -n 2000000 > /dev/null || t_fail "parallel_restore"
scratch_check || t_fail "check failed"
scratch_mount
scoutfs df -p "$SCR" | awk '{print $1, $4}'
umount "$SCR"
scratch_check || t_fail "check after mount failed"

echo "== ENOSPC"
scratch_mkfs -V 2 -m 10G -d 60G > $T_TMP.mkfs.out 2>&1 || t_fail "mkfs failed"
parallel_restore -m "$T_EX_META_DEV" -d 600:1000 -f 600:1000 -n 4000000 | grep died 2>&1 && t_fail "parallel_restore"

echo "== attempt to restore data device"
scratch_mkfs -V 2 -m 10G -d 60G > $T_TMP.mkfs.out 2>&1 || t_fail "mkfs failed"
parallel_restore -m "$T_EX_DATA_DEV" | grep died 2>&1 && t_fail "parallel_restore"

echo "== attempt format_v1 restore"
scratch_mkfs -V 1 -m 10G -d 60G > $T_TMP.mkfs.out 2>&1 || t_fail "mkfs failed"
parallel_restore -m "$T_EX_META_DEV" | grep died 2>&1 && t_fail "parallel_restore"

echo "== test if previously mounted"
scratch_mkfs -V 2 -m 10G -d 60G > $T_TMP.mkfs.out 2>&1 || t_fail "mkfs failed"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
	"$T_EX_DATA_DEV" "$SCR"
umount "$SCR"
parallel_restore -m "$T_EX_META_DEV" | grep died 2>&1 && t_fail "parallel_restore"

echo "== cleanup"
rmdir "$SCR"

t_pass
