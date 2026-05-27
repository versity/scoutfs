#
# Test basic scoutfs-nfs interactions:
# - read/write
# - stage/release and data wait
# - nfs setacl/getacl mapping
#

t_require_commands scoutfs setfacl getfacl exportfs mount.nfs umount \
		   stat dd cmp systemctl

systemctl start nfs-server >> "$T_TMPDIR/nfs.log" 2>&1 || \
	t_skip "nfs-server not available"

# Keep file creation modes deterministic for the ACL golden output.
umask 022

EXPORT_OPTS="rw,async,no_root_squash,no_subtree_check,fsid=42"
NFS_MNT="$T_TMP.nfs"
NFS_DIR="$NFS_MNT/test/basic-nfs"

filter() { sed "s@$T_TMPDIR@T_TMPDIR@g" | t_filter_fs; }
gf() { getfacl -n --omit-header "$@" 2>/dev/null; }

teardown_nfs()
{
	(
		umount "$NFS_MNT"
		exportfs -u "127.0.0.1:$T_M0"
		exportfs -f
		systemctl stop nfs-server
		rmdir "$NFS_MNT"
	) >> "$T_TMPDIR/nfs.log" 2>&1
}
trap teardown_nfs EXIT

exportfs -u "127.0.0.1:$T_M0" >> "$T_TMPDIR/nfs.log" 2>&1 || true
t_quiet mkdir -p "$NFS_MNT"
exportfs -o "$EXPORT_OPTS" "127.0.0.1:$T_M0" >> "$T_TMPDIR/nfs.log" 2>&1
mount.nfs -o vers=3,noac,actimeo=0 "127.0.0.1:$T_M0" "$NFS_MNT" >> "$T_TMPDIR/nfs.log" 2>&1

test -d "$NFS_DIR" || t_fail "test dir $NFS_DIR not visible over NFS"

echo "== write via NFS, read both sides"
dd if=/dev/urandom bs=4096 count=1 of="$T_TMP.data" status=none
cp "$T_TMP.data" "$NFS_DIR/file"
cmp "$T_TMP.data" "$T_D0/file"
cmp "$T_TMP.data" "$NFS_DIR/file"

echo "== POSIX ACL set via NFS, read both sides"
setfacl -m u:22222:rw "$NFS_DIR/file" 2>&1 | filter
gf "$NFS_DIR/file"
gf "$T_D0/file"

echo "== POSIX ACL set on scoutfs, read via NFS"
setfacl -m g:44444:r "$T_D0/file" 2>&1 | filter
gf "$NFS_DIR/file"

echo "== default ACL inheritance via NFS"
mkdir "$NFS_DIR/d"
setfacl -d -m u:22222:rwx "$NFS_DIR/d" 2>&1 | filter
touch "$NFS_DIR/d/child"
gf "$NFS_DIR/d/child"

echo "== NFS read demand-stages a released file"
dd if=/dev/urandom bs=4096 count=1 of="$T_TMP.big" status=none
cp "$T_TMP.big" "$T_D0/big"
sync
vers=$(scoutfs stat -s data_version "$T_D0/big")
t_quiet scoutfs release "$T_D0/big" -V "$vers" -o 0 -l 4K

# NFS read against the offline file blocks in scoutfs_read waiting
# for the data to come back online.
cat "$NFS_DIR/big" > "$T_TMP.read" &
read_pid=$!
sleep 1
scoutfs data-waiting -B 0 -I 0 -p "$T_D0" | wc -l

t_quiet scoutfs stage "$T_TMP.big" "$T_D0/big" -V "$vers" -o 0 -l 4096
wait "$read_pid"
cmp "$T_TMP.big" "$T_TMP.read"

echo "== cleanup"
rm -f "$T_D0/file" "$T_D0/big"
rm -rf "$T_D0/d"

t_pass
