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
t_scratch_mkfs
mkdir -p "$T_MSCR"

echo "== small new data device fails"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.small"

echo "== check sees data device errors"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV" "$T_TMP.small"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV"

echo "== preparing while mounted fails"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$T_MSCR"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"
umount "$T_MSCR"

echo "== preparing without recovery fails"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$T_MSCR"
umount -f "$T_MSCR"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"

echo "== check sees metadata errors"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV" "$T_TMP.equal"

echo "== preparing with file data fails"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$T_MSCR"
echo hi > "$T_MSCR"/file
umount "$T_MSCR"
scoutfs print "$T_EX_META_DEV" > "$T_TMP.print"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"

echo "== preparing after emptied"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$T_MSCR"
rm -f "$T_MSCR"/file
umount "$T_MSCR"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.equal"

echo "== checks pass"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV"
t_rc scoutfs prepare-empty-data-device --check "$T_EX_META_DEV" "$T_TMP.equal"

echo "== using prepared"
scr_loop=$(losetup --find --show "$T_TMP.equal")
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$scr_loop" "$T_MSCR"
touch "$T_MSCR"/equal_prepared
equal_tot=$(scoutfs statfs -s total_data_blocks -p "$T_MSCR")
umount "$T_MSCR"
losetup -d "$scr_loop"

echo "== preparing larger and resizing"
t_rc scoutfs prepare-empty-data-device "$T_EX_META_DEV" "$T_TMP.large"
scr_loop=$(losetup --find --show "$T_TMP.large")
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$scr_loop" "$T_MSCR"
touch "$T_MSCR"/large_prepared
ls "$T_MSCR"
scoutfs resize-devices -p "$T_MSCR" -d $large_sz
large_tot=$(scoutfs statfs -s total_data_blocks -p "$T_MSCR")
test "$large_tot" -gt "$equal_tot" ; echo "resized larger test rc: $?"
umount "$T_MSCR"
losetup -d "$scr_loop"

echo "== cleanup"
rm -f "$T_TMP.small" "$T_TMP.equal" "$T_TMP.large"

t_pass
