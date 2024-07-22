#
# test changing devices
#

echo "== make tmp sparse data dev files"
sz=$(blockdev --getsize64 "$T_EX_DATA_DEV")
large_sz=$((sz * 2))
touch "$T_TMP."{small,equal,large}
truncate -s 1MB "$T_TMP.small"
truncate -s $sz "$T_TMP.equal"
truncate -s $large_sz "$T_TMP.large"

echo "== make scratch fs"
t_quiet scoutfs mkfs -f -Q 0,127.0.0.1,53000 "$T_EX_META_DEV" "$T_EX_DATA_DEV"
SCR="$T_TMPDIR/mnt.scratch"
mkdir -p "$SCR"

echo "== small new data device fails"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.small"

echo "== check sees data device errors"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV" "$T_TMP.small"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV"

echo "== preparing while mounted fails"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$SCR"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"
umount "$SCR"

echo "== preparing without recovery fails"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$SCR"
umount -f "$SCR"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"

echo "== check sees metadata errors"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV" "$T_TMP.equal"

echo "== preparing with file data fails"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$SCR"
echo hi > "$SCR"/file
umount "$SCR"
scoutfs print "$T_EX_META_DEV" > "$T_TMP.print"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"

echo "== preparing after emptied"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$SCR"
rm -f "$SCR"/file
umount "$SCR"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"

echo "== checks pass"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV" "$T_TMP.equal"

echo "== using prepared"
scr_loop=$(losetup --find --show "$T_TMP.equal")
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$scr_loop" "$SCR"
touch "$SCR"/equal_prepared
equal_tot=$(scoutfs statfs -s total_data_blocks -p "$SCR")
umount "$SCR"
losetup -d "$scr_loop"

echo "== preparing larger and resizing"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.large"
scr_loop=$(losetup --find --show "$T_TMP.large")
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$scr_loop" "$SCR"
touch "$SCR"/large_prepared
ls "$SCR"
scoutfs resize-devices -p "$SCR" -d $large_sz
large_tot=$(scoutfs statfs -s total_data_blocks -p "$SCR")
test "$large_tot" -gt "$equal_tot" ; echo "resized larger test rc: $?"
umount "$SCR"
losetup -d "$scr_loop"

echo "== cleanup"
rm -f "$T_TMP.small" "$T_TMP.equal" "$T_TMP.large"

t_pass
