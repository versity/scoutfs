#
# validate parallel restore library
#

t_require_commands scoutfs parallel_restore filefrag-gc57857a5 find xargs

SCR="$T_TMPDIR/mnt.scratch"
mkdir -p "$SCR"

# XXX this is all pretty manual, would be nice to have helpers
echo "== make small meta fs"
# meta device just big enough for reserves and the metadata we'll fill
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 -m 10G -d 60G "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
	t_fail "mkfs failed"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
	"$T_EX_DATA_DEV" "$SCR"
umount "$SCR"

echo "== parallel_restore"
parallel_restore -m "$T_EX_META_DEV" > /dev/null || t_fail "parallel_restore"

echo "== mount restored filesystem"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
	"$T_EX_DATA_DEV" "$SCR"

#
# This is pretty crude...
#
echo "== compare filesystem contents"
scoutfs statfs -p "$SCR" | grep -v -e 'fsid' -e 'rid'
find "$SCR" -exec scoutfs list-hidden-xattrs {} \; | wc
scoutfs search-xattrs -p "$SCR" scoutfs.hide.srch.sam_vol_F01030L6 -p "$SCR" | wc
find "$SCR" -type f -name "file-*" | head -n 4 | xargs -n 1 filefrag-gc57857a5 -b4096 -v | grep -e ext: -e eof
scoutfs df -p "$SCR"

echo "== unmount small meta fs"
umount "$SCR"

echo "== just under ENOSPC"
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 -m 10G -d 60G "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
	t_fail "mkfs failed"

parallel_restore -m "$T_EX_META_DEV" -n 3300000 > /dev/null || t_fail "parallel_restore"

sleep 1
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
	"$T_EX_DATA_DEV" "$SCR"

scoutfs df -p "$SCR"

umount "$SCR"

echo "== just over ENOSPC"
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 -m 10G -d 60G "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
	t_fail "mkfs failed"

parallel_restore -m "$T_EX_META_DEV" -n 3333333 | grep died 2>&1 && t_fail "parallel_restore"

echo "== ENOSPC"
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 -m 10G -d 60G "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
	t_fail "mkfs failed"
parallel_restore -m "$T_EX_META_DEV" -d 600:1000 -f 600:1000 -n 4000000 | grep died 2>&1 && t_fail "parallel_restore"

echo "== cleanup"
rmdir "$SCR"
t_pass
