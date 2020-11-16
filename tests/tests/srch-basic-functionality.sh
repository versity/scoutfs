#
# Test basic functionality of searching for file inodes by their
# scoutfs.srch. xattrs.
#

# rough max unsorted entries in a full 1MB log
LOG=340000
# search will remember 1M entries per search
LIM=1000000

SEQF="%.20g"

t_require_commands touch rm setfattr scoutfs find_xattrs

diff_srch_find()
{
	local n="$1"

	sync
	scoutfs search-xattrs -n "$n" -f "$T_M0" > "$T_TMP.srch"
	find_xattrs -d "$T_D0" -m "$T_M0" -n "$n" > "$T_TMP.find"

	diff -u "$T_TMP.srch" "$T_TMP.find"
}

echo "== create new xattrs"
touch "$T_D0/"{create,update}
setfattr -n scoutfs.srch.test -v 1 "$T_D0/"{create,update} 2>&1 | t_filter_fs
diff_srch_find scoutfs.srch.test

echo "== update existing xattr"
setfattr -n scoutfs.srch.test -v 2 "$T_D0/update" 2>&1 | t_filter_fs
diff_srch_find scoutfs.srch.test

echo "== remove an xattr"
setfattr -x scoutfs.srch.test "$T_D0/create" 2>&1 | t_filter_fs
diff_srch_find scoutfs.srch.test

echo "== remove xattr with files"
rm -f "$T_D0/"{create,update}
diff_srch_find scoutfs.srch.test

echo "== create entries in current log"
DIR="$T_D0/dir"
NR=$((LOG / 4))
mkdir -p "$DIR"
seq -f "f-$SEQF" 1 $NR | src/bulk_create_paths -S -d "$DIR" > /dev/null
diff_srch_find scoutfs.srch.scoutfs_bcp

echo "== delete small fraction"
seq -f "$DIR/f-$SEQF" 1 7 $NR | xargs setfattr -x scoutfs.srch.scoutfs_bcp
diff_srch_find scoutfs.srch.scoutfs_bcp

echo "== remove files"
rm -rf "$DIR"
diff_srch_find scoutfs.srch.scoutfs_bcp

echo "== create entries that exceed one log"
NR=$((LOG * 3 / 2))
mkdir -p "$DIR"
seq -f "f-$SEQF" 1 $NR | src/bulk_create_paths -S -d "$DIR" > /dev/null
diff_srch_find scoutfs.srch.scoutfs_bcp

echo "== delete fractions in phases"
for i in $(seq 1 3); do
	seq -f "$DIR/f-$SEQF" $i 3 $NR | xargs setfattr -x scoutfs.srch.scoutfs_bcp
	diff_srch_find scoutfs.srch.scoutfs_bcp
done

echo "== remove files"
rm -rf "$DIR"
diff_srch_find scoutfs.srch.scoutfs_bcp

echo "== create entries for exceed search entry limit"
NR=$((LIM * 3 / 2))
mkdir -p "$DIR"
seq -f "f-$SEQF" 1 $NR | src/bulk_create_paths -S -d "$DIR" > /dev/null
diff_srch_find scoutfs.srch.scoutfs_bcp

echo "== delete half"
seq -f "$DIR/f-$SEQF" 1 2 $NR | xargs setfattr -x scoutfs.srch.scoutfs_bcp
diff_srch_find scoutfs.srch.scoutfs_bcp

echo "== entirely remove third batch"
rm -rf "$DIR"
diff_srch_find scoutfs.srch.scoutfs_bcp

t_pass
