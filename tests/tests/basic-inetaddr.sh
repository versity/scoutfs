#
# Test that mixed ipv4/6 fails through mkfs/quorum change and that
# users can migrate from ipv4 to v6 and back.
#

t_require_commands dmsetup blockdev cmp

P0=$T_SCRATCH_PORT
P1=$((T_SCRATCH_PORT + 1))
P2=$((T_SCRATCH_PORT + 2))
SIG=$T_TMP.sig
seq 1 4096 > "$SIG"

trap '
	umount $T_TMPDIR/m0 $T_TMPDIR/m1 $T_TMPDIR/m2 2>/dev/null
	dmsetup remove _bia_m0 _bia_m1 _bia_m2 _bia_d0 _bia_d1 _bia_d2 2>/dev/null
' EXIT

mkdir -p "$T_TMPDIR/m0" "$T_TMPDIR/m1" "$T_TMPDIR/m2"
for nv in "m0 $T_EX_META_DEV" "m1 $T_EX_META_DEV" "m2 $T_EX_META_DEV" \
	  "d0 $T_EX_DATA_DEV" "d1 $T_EX_DATA_DEV" "d2 $T_EX_DATA_DEV"; do
	set -- $nv
	t_quiet dmsetup create _bia_$1 --table "0 $(blockdev --getsz $2) linear $2 0"
done

mnt() {
mount -t scoutfs \
	-o metadev_path=/dev/mapper/_bia_m$1,quorum_slot_nr=$1 \
	/dev/mapper/_bia_d$1 "$T_TMPDIR/m$1"
}
mount_all() {
	mnt 0 &
	mnt 1 &
	mnt 2 &
	wait
}
umount_all() {
	umount $T_TMPDIR/m0 &
	umount $T_TMPDIR/m1 &
	umount $T_TMPDIR/m2 &
	wait
}
verify() {
	cmp -s "$SIG" "$T_TMPDIR/m0/sig" &&
	cmp -s "$SIG" "$T_TMPDIR/m1/sig" &&
	cmp -s "$SIG" "$T_TMPDIR/m2/sig" || t_fail "$1"
}

echo "== mkfs rejects mixed v4/v6 quorum"
t_rc scoutfs mkfs -f -Q 0,127.0.0.1,$P0 -Q 1,::1,$P1 -Q 2,127.0.0.1,$P2 /dev/mapper/_bia_m0 /dev/mapper/_bia_d0

echo "== mkfs all-v4, mount three members, cross-mount signature visible"
t_quiet scoutfs mkfs -f -Q 0,127.0.0.1,$P0 -Q 1,127.0.0.1,$P1 -Q 2,127.0.0.1,$P2 /dev/mapper/_bia_m0 /dev/mapper/_bia_d0
mount_all
cp "$SIG" "$T_TMPDIR/m0/sig"
verify "v4 initial"
umount_all

echo "== change-quorum-config rejects mixed v4/v6 quorum"
t_rc scoutfs change-quorum-config --offline -Q 0,127.0.0.1,$P0 -Q 1,::1,$P1 -Q 2,127.0.0.1,$P2 /dev/mapper/_bia_m0

echo "== switch v4 -> v6, signature survives, cross-mount write again"
t_quiet scoutfs change-quorum-config --offline -Q 0,::1,$P0 -Q 1,::1,$P1 -Q 2,::1,$P2 /dev/mapper/_bia_m0
mount_all
verify "after v4->v6"
cp "$SIG" "$T_TMPDIR/m1/sig-v6"
cmp -s "$SIG" "$T_TMPDIR/m0/sig-v6" || t_fail "v6 cross-mount write not visible on m0"
cmp -s "$SIG" "$T_TMPDIR/m2/sig-v6" || t_fail "v6 cross-mount write not visible on m2"
umount_all

echo "== switch v6 -> v4, signatures survive"
t_quiet scoutfs change-quorum-config --offline -Q 0,127.0.0.1,$P0 -Q 1,127.0.0.1,$P1 -Q 2,127.0.0.1,$P2 /dev/mapper/_bia_m0
mount_all
verify "after v6->v4"
cmp -s "$SIG" "$T_TMPDIR/m0/sig-v6" || t_fail "after v6->v4 sig-v6 lost"
umount_all

t_pass
