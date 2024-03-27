#
# clobber a scoutfs filesystem in a predictable way, then repair
# the damage, and verify that the damage has been repaired.
#

t_require_commands scoutfs

#
# list of clobber functions and data. one string per line. data is optional
# and comes after the function, separated by a comma. see `scoutfs clobber -?`
# for more info on data formats and clobber functions
#
CLOBBERS=(
"PB_SB_HDR_CRC_INVALID,"
"PB_SB_BAD_FLAG,"
)

# test that we can't check/repair mounted filesystems
echo "== cannot check mounted"
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
	t_fail "mkfs failed"
SCR="$T_TMPDIR/mnt.scratch"
mkdir -p "$SCR"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 "$T_EX_DATA_DEV" "$SCR"
scoutfs check "$T_EX_META_DEV" "$T_EX_DATA_DEV" 2>&1 | sed "s|${T_EX_META_DEV}|T_EXT_META_DEV|g"
umount "$SCR"
rmdir "$SCR"
scoutfs check "$T_EX_META_DEV" "$T_EX_DATA_DEV" || \
	t_fail "must check when not mounted"

echo "== clobber to appear mounted"
scoutfs clobber "$T_EX_META_DEV" "$T_EX_DATA_DEV" PB_MOUNTED_CLIENTS_REF_BLKNO
scoutfs check "$T_EX_META_DEV" "$T_EX_DATA_DEV" && \
	t_fail "must fail when appears to be mounted"
scoutfs check --repair "$T_EX_META_DEV" "$T_EX_DATA_DEV" && \
	t_fail "must fail when repairing without force flag"
scoutfs check --repair --force "$T_EX_META_DEV" "$T_EX_DATA_DEV"
test $? -eq 5 || t_fail "a problem should have been found"
scoutfs check "$T_EX_META_DEV" "$T_EX_DATA_DEV"
test $? -eq 0 || t_fail "the problem should have been fixed"

#
# automated clobber testing
#
for n in $(seq 0 $(( ${#CLOBBERS[@]} - 1 )) ) ; do
	CLOBBER_FN="$(echo ${CLOBBERS[$n]} | cut -d, -f1)"
	CLOBBER_DATA="$(echo ${CLOBBERS[$n]} | cut -d, -s -f2-)"

	echo "== mkfs a clean scratch fs"
	scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 "$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
		t_fail "mkfs failed"

	# at a minimum we need to mount it once to have it internally complete
	# the initial setup that the kernel does.
	SCR="$T_TMPDIR/mnt.scratch"
	mkdir -p "$SCR"
	mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
		"$T_EX_DATA_DEV" "$SCR"

	#mkdir -p "$SCR/clobber"
	#touch "$SCR/clobber/file"

	# and unmount it before checking/repairing
	umount "$SCR"
	rmdir "$SCR"

	echo "== clobber [${n}] ${CLOBBER_FN} ${CLOBBER_DATA}"
	if [ -n "${CLOBBER_DATA}" ]; then
		scoutfs clobber --data "${CLOBBER_DATA}" "$T_EX_META_DEV" "$T_EX_DATA_DEV" "$CLOBBER_FN" || \
			t_fail "clobber failed"
	else
		scoutfs clobber "$T_EX_META_DEV" "$T_EX_DATA_DEV" "$CLOBBER_FN" || \
			t_fail "clobber failed"
	fi

	echo "== detect [${n}] ${CLOBBER_FN} ${CLOBBER_DATA} damage"
	scoutfs check "$T_EX_META_DEV" "$T_EX_DATA_DEV"
	test $? -eq 4 || t_fail "a problem should have been found"

	echo "== repair [${n}] ${CLOBBER_FN} ${CLOBBER_DATA} damage"
	scoutfs check --repair "$T_EX_META_DEV" "$T_EX_DATA_DEV"
	test $? -eq 5 || t_fail "a problem should have been found, and repaired"

	echo "== detect [${n}] ${CLOBBER_FN} ${CLOBBER_DATA} damage is repaired"
	scoutfs check "$T_EX_META_DEV" "$T_EX_DATA_DEV"
	test $? -eq 0 || t_fail "no problem should have been found"

done

t_pass
