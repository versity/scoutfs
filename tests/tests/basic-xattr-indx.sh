#
# Test basic .indx. xattr tag functionality and index entry lifecycle
#

t_require_commands touch rm setfattr scoutfs stat
t_require_mounts 2

# query index from a specific mount, default mount 0
read_xattr_index()
{
	local nr="${1:-0}"
	local mnt="$(eval echo \$T_M$nr)"
	shift

	sync
	echo 1 > $(t_debugfs_path $nr)/drop_weak_item_cache
	scoutfs read-xattr-index -p "$mnt" "$@"
}

MAJOR=5
MINOR=100

echo "== testing invalid read-xattr-index arguments"
scoutfs read-xattr-index -p "$T_M0" bad 2>&1
scoutfs read-xattr-index -p "$T_M0" 1.2 2>&1
scoutfs read-xattr-index -p "$T_M0" 1.2.3 256.0.0 2>&1
scoutfs read-xattr-index -p "$T_M0" 1.2.3 0.0.0 2>&1
scoutfs read-xattr-index -p "$T_M0" 1.2.0 1.1.2 2>&1
scoutfs read-xattr-index -p "$T_M0" 2.2.2 2.2.1 2>&1

echo "== testing invalid names"
touch "$T_D0/invalid"
setfattr -n scoutfs.hide.indx.test.$MAJOR "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.. "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test..$MINOR "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.$MAJOR. "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.256.$MINOR "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.abc.$MINOR "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.$MAJOR.abc "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.-1.$MINOR "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.$MAJOR.-1 "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.18446744073709551616.$MINOR "$T_D0/invalid" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.$(printf 'x%.0s' $(seq 1 240)).$MAJOR.$MINOR "$T_D0/invalid" 2>&1 | t_filter_fs
rm -f "$T_D0/invalid"

echo "== testing boundary values"
touch "$T_D0/boundary"
INO=$(stat -c "%i" "$T_D0/boundary")
setfattr -n scoutfs.hide.indx.test.0.0 "$T_D0/boundary"
read_xattr_index 0 0.0.0 0.0.-1 | awk '($3 == "'$INO'") {print "0.0 found"}'
setfattr -x scoutfs.hide.indx.test.0.0 "$T_D0/boundary"
setfattr -n scoutfs.hide.indx.test.255.18446744073709551615 "$T_D0/boundary"
read_xattr_index 0 255.0.0 255.-1.-1 | awk '($3 == "'$INO'") {print "255.max found"}'
setfattr -x scoutfs.hide.indx.test.255.18446744073709551615 "$T_D0/boundary"
rm -f "$T_D0/boundary"

echo "== indx xattr must have no value"
touch "$T_D0/noval"
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR -v "" "$T_D0/noval" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR -v 0 "$T_D0/noval" 2>&1 | t_filter_fs
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR -v 1 "$T_D0/noval" 2>&1 | t_filter_fs
rm -f "$T_D0/noval"

echo "== set indx xattr and verify index entry"
touch "$T_D0/file"
INO=$(stat -c "%i" "$T_D0/file")
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR "$T_D0/file"
read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "found"}'

echo "== setting same indx xattr again is a no-op"
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR "$T_D0/file"
read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "found"}'

echo "== removing non-existent indx xattr succeeds"
setfattr -x scoutfs.hide.indx.nonexistent.$MAJOR.999 "$T_D0/file" 2>&1 | t_filter_fs
read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "still found"}'

echo "== explicit xattr removal cleans up index entry"
setfattr -x scoutfs.hide.indx.test.$MAJOR.$MINOR "$T_D0/file"
read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "found orphan"}'
rm -f "$T_D0/file"

echo "== file deletion cleans up index entry"
touch "$T_D0/file2"
INO=$(stat -c "%i" "$T_D0/file2")
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR "$T_D0/file2"
read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "found before delete"}'
rm -f "$T_D0/file2"
read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "found orphan after delete"}'

echo "== multiple indx xattrs on one file cleaned up by deletion"
touch "$T_D0/file3"
INO=$(stat -c "%i" "$T_D0/file3")
setfattr -n scoutfs.hide.indx.a.$MAJOR.200 "$T_D0/file3"
setfattr -n scoutfs.hide.indx.b.$MAJOR.300 "$T_D0/file3"
BEFORE=$(read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'")' | wc -l)
echo "entries before delete: $BEFORE"
rm -f "$T_D0/file3"
AFTER=$(read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'")' | wc -l)
echo "entries after delete: $AFTER"

echo "== partial removal leaves other entries"
touch "$T_D0/partial"
INO=$(stat -c "%i" "$T_D0/partial")
setfattr -n scoutfs.hide.indx.a.$MAJOR.200 "$T_D0/partial"
setfattr -n scoutfs.hide.indx.b.$MAJOR.300 "$T_D0/partial"
setfattr -x scoutfs.hide.indx.a.$MAJOR.200 "$T_D0/partial"
read_xattr_index 0 $MAJOR.200.0 $MAJOR.200.-1 | awk '($3 == "'$INO'") {print "200 found"}'
read_xattr_index 0 $MAJOR.300.0 $MAJOR.300.-1 | awk '($3 == "'$INO'") {print "300 found"}'
rm -f "$T_D0/partial"

echo "== multiple files at same index position"
touch "$T_D0/multi_a" "$T_D0/multi_b"
INO_A=$(stat -c "%i" "$T_D0/multi_a")
INO_B=$(stat -c "%i" "$T_D0/multi_b")
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR "$T_D0/multi_a"
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR "$T_D0/multi_b"
COUNT=$(read_xattr_index 0 $MAJOR.$MINOR.0 $MAJOR.$MINOR.-1 | wc -l)
echo "files at same position: $COUNT"
rm -f "$T_D0/multi_a"
read_xattr_index 0 $MAJOR.$MINOR.0 $MAJOR.$MINOR.-1 | awk '($3 == "'$INO_A'") {print "deleted file still found"}'
read_xattr_index 0 $MAJOR.$MINOR.0 $MAJOR.$MINOR.-1 | awk '($3 == "'$INO_B'") {print "surviving file found"}'
rm -f "$T_D0/multi_b"

echo "== cross-mount visibility"
touch "$T_D0/file4"
INO=$(stat -c "%i" "$T_D0/file4")
setfattr -n scoutfs.hide.indx.test.$MAJOR.$MINOR "$T_D0/file4"
read_xattr_index 1 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "found on mount 1"}'
rm -f "$T_D0/file4"
read_xattr_index 1 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'") {print "found orphan on mount 1"}'

echo "== duplicate position deduplication"
touch "$T_D0/file5"
INO=$(stat -c "%i" "$T_D0/file5")
setfattr -n scoutfs.hide.indx.aa.$MAJOR.$MINOR "$T_D0/file5"
setfattr -n scoutfs.hide.indx.bb.$MAJOR.$MINOR "$T_D0/file5"
COUNT=$(read_xattr_index 0 $MAJOR.0.0 $MAJOR.-1.-1 | awk '($3 == "'$INO'")' | wc -l)
echo "entries for same position: $COUNT"
rm -f "$T_D0/file5"

t_pass
