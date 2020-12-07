#
# Test correctness of the staging operation
#

t_require_commands filefrag dd scoutfs cp cmp rm

fiemap_file() {
	filefrag -v -b4096 "$1"
}

create_file() {
	local file="$1"
	local size="$2"
	local blocks=$((size / 4096))
	local remainder=$((size % 4096))

	if [ "$blocks" != 0 ]; then
		dd if=/dev/urandom bs=4096 count=$blocks of="$file" \
			>> $seqres.full 2>&1
	fi

	if [ "$remainder" != 0 ]; then
		dd if=/dev/urandom bs="$remainder" count=1 of="$file" \
			conv=notrunc oflag=append >> $seqres.full 2>&1
	fi
}

# if vers is "stat" then we ask stat_more for the data_version
release_vers() {
	local file="$1"
	local vers="$2"
	local block="$3"
	local count="$4"

	if [ "$vers" == "stat" ]; then
		vers=$(scoutfs stat -s data_version "$file")
	fi

	scoutfs release "$file" "$vers" "$block" "$count"
}

# if vers is "stat" then we ask stat_more for the data_version
stage_vers() {
	local file="$1"
	local vers="$2"
	local offset="$3"
	local count="$4"
	local contents="$5"

	if [ "$vers" == "stat" ]; then
		vers=$(scoutfs stat -s data_version "$file")
	fi

	scoutfs stage "$file" "$vers" "$offset" "$count" "$contents"
}

FILE="$T_D0/file"
CHAR="$FILE-char"

echo "== create/release/stage single block file"
create_file "$FILE" 4096
cp "$FILE"  "$T_TMP"
release_vers "$FILE" stat 0 1
# make sure there only offline extents
fiemap_file "$FILE" | grep "^[ 0-9]*:" | grep -v "unknown"
stage_vers "$FILE" stat 0 4096 "$T_TMP"
cmp "$FILE" "$T_TMP"
rm -f "$FILE"

echo "== create/release/stage larger file"
create_file "$FILE" $((4096 * 4096))
cp "$FILE"  "$T_TMP"
release_vers "$FILE" stat 0 4096
# make sure there only offline extents
fiemap_file "$FILE" | grep "^[ 0-9]*:" | grep -v "unknown"
stage_vers "$FILE" stat 0 $((4096 * 4096)) "$T_TMP"
cmp "$FILE" "$T_TMP"
rm -f "$FILE"

echo "== multiple release,drop_cache,stage cycles"
create_file "$FILE" $((4096 * 1024))
cp "$FILE"  "$T_TMP"
nr=1
while [ "$nr" -lt 10 ]; do
	echo "attempt $nr" >> $seqres.full 2>&1
	release_vers "$FILE" stat 0 1024
	sync
	echo 3 > /proc/sys/vm/drop_caches
	stage_vers "$FILE" stat 0 $((4096 * 1024)) "$T_TMP"
	cmp "$FILE" "$T_TMP"
	sync
	((nr++))
done
rm -f "$FILE"

echo "== release+stage shouldn't change stat, data seq or vers"
create_file "$FILE" 4096
cp "$FILE"  "$T_TMP"
sync
stat "$FILE" > "$T_TMP.before"
scoutfs stat -s data_seq "$FILE" >> "$T_TMP.before"
scoutfs stat -s data_version "$FILE" >> "$T_TMP.before"
release_vers "$FILE" stat 0 1
stage_vers "$FILE" stat 0 4096 "$T_TMP"
stat "$FILE" > "$T_TMP.after"
scoutfs stat -s data_seq "$FILE" >> "$T_TMP.after"
scoutfs stat -s data_version "$FILE" >> "$T_TMP.after"
diff -u "$T_TMP.before" "$T_TMP.after"
rm -f "$FILE"

echo "== stage does change meta_seq"
create_file "$FILE" 4096
release_vers "$FILE" stat 0 1
sync
before=$(scoutfs stat -s meta_seq "$FILE")
stage_vers "$FILE" stat 0 4096 "$T_TMP"
after=$(scoutfs stat -s meta_seq "$FILE")
test "$before" == "$after" && echo "before $before == ater $after"
rm -f "$FILE"

# XXX this now waits, demand staging should be own test
#echo "== can't write to offline"
#create_file "$FILE" 4096
#release_vers "$FILE" stat 0 1
## make sure there only offline extents
#fiemap_file "$FILE" | grep "^[ 0-9]*:" | grep -v "unknown"
#dd if=/dev/zero of="$FILE" conv=notrunc bs=4096 count=1  2>&1 | t_filter_fs
#fiemap_file "$FILE" | grep "^[ 0-9]*:" | grep -v "unknown"
#rm -f "$FILE"

## XXX not worrying about this yet
#echo "== can't stage online when version matches"
#create_file "$FILE" 4096
#cp "$FILE"  "$T_TMP"
#stage_vers "$FILE" stat 0 4096 /dev/zero
#cmp "$FILE" "$T_TMP"
#rm -f "$FILE"

echo "== can't use stage to extend online file"
touch "$FILE"
stage_vers "$FILE" stat 0 4096 /dev/zero
hexdump -C "$FILE"
rm -f "$FILE"

echo "== wrapped region fails"
create_file "$FILE" 4096
stage_vers "$FILE" stat 0xFFFFFFFFFFFFFFFF 4096 /dev/zero
rm -f "$FILE"

echo "== non-block aligned offset fails"
create_file "$FILE" 4096
cp "$FILE"  "$T_TMP"
release_vers "$FILE" stat 0 1
stage_vers "$FILE" stat 1 4095 "$T_TMP"
fiemap_file "$FILE" | grep "^[ 0-9]*:" | grep -v "unknown"
rm -f "$FILE"

echo "== non-block aligned len within block fails"
create_file "$FILE" 4096
cp "$FILE"  "$T_TMP"
release_vers "$FILE" stat 0 1
stage_vers "$FILE" stat 0 1024 "$T_TMP"
fiemap_file "$FILE" | grep "^[ 0-9]*:" | grep -v "unknown"
rm -f "$FILE"

echo "== partial final block that writes to i_size does work"
create_file "$FILE" 2048
cp "$FILE"  "$T_TMP"
release_vers "$FILE" stat 0 1
stage_vers "$FILE" stat 0 2048 "$T_TMP"
cmp "$FILE" "$T_TMP"
rm -f "$FILE"

echo "== zero length stage doesn't bring blocks online"
create_file "$FILE" $((4096 * 100))
release_vers "$FILE" stat 0 100
stage_vers "$FILE" stat 4096 0 /dev/zero
fiemap_file "$FILE" | grep "^[ 0-9]*:" | grep -v "unknown"
rm -f "$FILE"

# XXX yup, needs to be updated for demand staging
##
## today readding offline returns -EIO (via -EINVAL from get_block and
## PageError), we'd want something more clever once this read hangs in
## demand staging
##
#echo "== stage suceeds after read error"
#create_file "$FILE" 4096
#cp "$FILE"  "$T_TMP"
#sync
#release_vers "$FILE" stat 0 1
#md5sum "$FILE" 2>&1 | t_filter_fs
#stage_vers "$FILE" stat 0 4096 "$T_TMP"
#cmp "$FILE" "$T_TMP"
#rm -f "$FILE"

echo "== stage of non-regular file fails"
mknod "$CHAR" c 1 3
stage_vers "$CHAR" stat 0 1 /dev/zero 2>&1 | t_filter_fs
rm "$CHAR"

t_pass
