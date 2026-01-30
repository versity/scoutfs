
mount_fail()
{
	local mnt=${!#}

	echo "mounting $@" >> $T_TMP.mount.out
	mount -t scoutfs "$@" >> $T_TMP.mount.out 2>&1
	if [ $? == 0 ]; then
		umount "$mnt" || t_fail "couldn't unmount"
		t_fail "bad mount succeeded"
	fi
}

echo "== prepare devices, mount point, and logs"
t_scratch_mkfs
> $T_TMP.mount.out

echo "== bad devices, bad options"
mount_fail -o _bad /dev/null /dev/null "$T_MSCR"

echo "== swapped devices"
mount_fail -o metadev_path=$T_EX_DATA_DEV,quorum_slot_nr=0 "$T_EX_META_DEV" "$T_MSCR"

echo "== both meta devices"
mount_fail -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_META_DEV" "$T_MSCR"

echo "== both data devices"
mount_fail -o metadev_path=$T_EX_DATA_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$T_MSCR"

echo "== good volume, bad option and good options"
mount_fail -o _bad,metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$T_MSCR"

t_pass
