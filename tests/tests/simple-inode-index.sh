#
# Test basic inode index item behaviour
#

t_require_commands touch mkdir sync scoutfs setfattr dd stat

get_meta_seq()
{
	scoutfs stat -s meta_seq "$1"
}

query_index() {
	local which="$1"
	local first="${2:-0}"
	local last="${3:--1}"

	scoutfs walk-inodes -p "$T_M0" -- $which $first $last
}

# print the major in the index for the ino if it's found
ino_major() {
	local which="$1"
	local ino="$2"

	scoutfs walk-inodes -p "$T_M0" -- $which 0 -1 | \
		awk '($4 == "'$ino'") {print $2}'
}

DIR="$T_D0/dir"

echo "== dirs shouldn't appear in data_seq queries"
mkdir "$DIR"
ino=$(stat -c "%i" "$DIR")
t_sync_seq_index
query_index data_seq | grep "$ino\>"

echo "== two created files are present and come after each other"
touch "$DIR/first"
t_sync_seq_index
touch "$DIR/second"
t_sync_seq_index
ino=$(stat -c "%i" "$DIR/first")
query_index data_seq | awk '($4 == "'$ino'") {print "found first"}'
ino=$(stat -c "%i" "$DIR/second")
query_index data_seq | awk '($4 == "'$ino'") {print "found second"}'

echo "== unlinked entries must not be present"
touch "$DIR/victim"
ino=$(stat -c "%i" "$DIR/victim")
rm -f "$DIR/victim"
t_sync_seq_index
query_index data_seq | awk '($4 == "'$ino'") {print "found victim"}'

echo "== dirty inodes can not be present"
touch "$DIR/dirty_before"
ino=$(stat -c "%i" "$DIR/dirty_before")
before=$(get_meta_seq "$DIR/dirty_before")
if query_index meta_seq | grep -q "$ino\>"; then
	# was dirty while in index if its seq matches newly created
	touch "$DIR/dirty_after"
	after=$(get_meta_seq "$DIR/dirty_after")
	if [ "$before" == "$after" ]; then
		echo "ino $ino before $before after $after"
	fi
fi

echo "== changing metadata must increase meta seq"
touch "$DIR/meta_file"
ino=$(stat -c "%i" "$DIR/meta_file")
t_sync_seq_index
before=$(ino_major meta_seq $ino)
# no setattr at the time of writing, xattrs update :)
setfattr -n user.scoutfs-testing.meta_seq -v 1 "$DIR/meta_file"
t_sync_seq_index
after=$(ino_major meta_seq $ino)
test "$before" -lt "$after" || \
	echo "meta seq after xattr set $after <= before $before"

echo "== changing contents must increase data seq"
echo "first contents" > "$DIR/regular_file"
ino=$(stat -c "%i" "$DIR/regular_file")
t_sync_seq_index
before=$(ino_major data_seq $ino)
echo "more contents" >> "$DIR/regular_file"
t_sync_seq_index
after=$(ino_major data_seq $ino)
test "$before" -lt "$after" || \
	echo "data seq after modification $after <= before $before"

#
# we had a bug where sampling the next key in the manifest+segmenets
# didn't skip past deleted dirty items
#
echo "== make sure dirtying doesn't livelock walk"
dd if=/dev/urandom of="$DIR/dirtying" bs=4K count=1 >> "$T_TMPDIR/seqres.full" 2>&1
nr=1
while [ "$nr" -lt 100 ]; do
	echo "dirty/walk attempt $nr" >> "$T_TMPDIR/seqres.full"
	sync
	dd if=/dev/urandom of="$DIR/dirtying" bs=4K count=1 conv=notrunc \
		>> "$T_TMPDIR/seqres.full" 2>&1
	scoutfs walk-inodes data_seq 0 -1 $DIR/dirtying >& /dev/null 
	((nr++))
done

#
# make sure rapid concurrent metadata updates don't create multiple
# meta_seq entries
#
# we had a bug where deletion items created under concurrent_write locks
# could get versions older than the items they're deleting which were
# protected by read/write locks.
#
echo "== concurrent update attempts maintain single entries"
FILES=4
nr=1
while [ "$nr" -lt 10 ]; do
	# touch a bunch of files in parallel from all mounts
	for i in $(t_fs_nrs); do
		eval path="\$T_D${i}"
		seq -f "$path/file-%.0f" 1 $FILES | xargs touch &
	done
	wait || t_fail "concurrent file updates failed"

	# make sure no inodes have duplicate entries
	sync
	scoutfs walk-inodes -p "$T_D0" meta_seq -- 0 -1 | \
		grep -v "minor" | \
		awk '{print $4}' | \
		sort -n | uniq -c | \
		awk '($1 != 1)' | \
		sort -n
	((nr++))
done

t_pass
