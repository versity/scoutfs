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
	scoutfs search-xattrs "$n" -p "$T_M0" > "$T_TMP.srch" || \
		t_fail "search-xattrs failed"
	find_xattrs -d "$T_D0" -m "$T_M0" -n "$n" > "$T_TMP.find" || \
		t_fail "find_xattrs failed"

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

echo "== trigger small log merges by rotating single block with unmount"
sv=$(t_server_nr)
i=1
while [ "$i" -lt "8" ]; do
	for nr in $(t_fs_nrs); do
		# not checking, can go over limit by fs_nrs
		((i++))

		if [ $nr == $sv ]; then
			continue;
		fi

		eval path="\$T_D${nr}/single-block-$i"
		touch "$path"
		setfattr -n scoutfs.srch.single-block-logs -v $i "$path"
		t_umount $nr
		t_mount $nr

		((i++))
	done
done
# wait for srch compaction worker delay
sleep 10
rm -rf "$T_D0/single-block-*"

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
