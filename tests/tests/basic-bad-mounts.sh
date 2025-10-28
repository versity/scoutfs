
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
SCR="$T_TMPDIR/mnt.scratch"
mkdir -p "$SCR"
> $T_TMP.mount.out
scoutfs mkfs -f -Q 0,127.0.0.1,$T_SCRATCH_PORT "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 \
	|| t_fail "mkfs failed"

echo "== bad devices, bad options"
mount_fail -o _bad /dev/null /dev/null "$SCR"

echo "== swapped devices"
mount_fail -o metadev_path=$T_EX_DATA_DEV,quorum_slot_nr=0 "$T_EX_META_DEV" "$SCR"

echo "== both meta devices"
mount_fail -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_META_DEV" "$SCR"

echo "== both data devices"
mount_fail -o metadev_path=$T_EX_DATA_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$SCR"

echo "== good volume, bad option and good options"
mount_fail -o _bad,metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$SCR" 

t_pass
