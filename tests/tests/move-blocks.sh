#
# test MOVE_BLOCKS ioctl, mostly basic error testing and functionality,
# but a bit of expected use.
#

t_require_commands scoutfs dd

FROM="$T_D0/from"
TO="$T_D0/to"
HARD="$T_D0/hardlink"
OTHER="$T_TMP.other"

BLOCKS=8
BS=4096
PART=123
LEN=$(((BS * BLOCKS) + PART))
PIECES=8

regenerate_files() {
	rm -f "$FROM"
	rm -f "$TO"
	dd if=/dev/urandom of="$FROM" bs=$LEN count=1 status=none
	touch "$TO"
}

set_updated_fields() {
	local arr="$1"
	local path="$2"

	eval $arr["ctime"]="$(stat -c '%Z' "$path")"
	eval $arr["mtime"]="$(stat -c '%Y' "$path")"
	eval $arr["data_version"]="$(scoutfs stat -s data_version "$path")"
	eval $arr["meta_seq"]="$(scoutfs stat -s meta_seq "$path")"
	eval $arr["data_seq"]="$(scoutfs stat -s data_seq "$path")"
}

#
# before moving extents manually copy the byte regions so that we have
# expected good file contents to compare to.  We know that the byte
# regions are 4KB block aligned (with an allowance for a len that ends
# on from i_size).
#
move_and_compare() {
	local from="$1"
	local from_off="$2"
	local from_blk="$((from_off / BS))"
	local len="$3"
	local blocks="$(((len + BS - 1) / BS))"
	local to="$4"
	local to_off="$5"
	local to_blk="$((to_off / BS))"

	local right_start=$((from_blk + blocks))
	local from_size=$(stat -c "%s" "$from")
	local from_blocks=$(( (from_size + BS - 1) / BS ))
	local right_len=$((from_blocks - right_start))

	# copying around instead of punching hole
	dd if="$from" of="$from.expected" bs="$BS" \
		skip=0 seek=0 count="$from_blk" \
		status=none
	dd if="$from" of="$from.expected" bs="$BS" \
		skip="$right_start" seek="$right_start" count="$right_len" \
		status=none conv=notrunc
	# moving doesn't truncate, expect full size when no data
	truncate -s "$from_size" "$from.expected"

	cp "$to" "$to.expected"
	dd if="$from" of="$to.expected" bs="$BS" \
		skip="$from_blk" seek="$to_blk" count="$blocks" \
		status=none conv=notrunc

	scoutfs move-blocks "$from" -f "$from_off" -l "$len" "$to" -t "$to_off" \
		2>&1 | t_filter_fs

	cmp "$from" "$from.expected"
	cmp "$to" "$to.expected"
}

echo "== build test files"
regenerate_files
touch "$OTHER"
ln "$FROM" "$HARD"

echo "== wrapped offsets should fail"
HUGE=0xfffffffffffff000
scoutfs move-blocks "$FROM" -f "$HUGE" -l "8192" "$TO" -t 0 2>&1 | t_filter_fs
scoutfs move-blocks "$FROM" -f 0 -l "$HUGE" "$TO" -t "8192" 2>&1 | t_filter_fs

echo "== specifying same file fails"
scoutfs move-blocks "$FROM" -f 0 -l "$BS" "$HARD" -t 0 2>&1 | t_filter_fs

echo "== specifying files in other file systems fails"
scoutfs move-blocks "$OTHER" -f 0 -l "$BS" "$TO" -t 0 2>&1 | t_filter_fs

echo "== offsets must be multiples of 4KB"
scoutfs move-blocks "$FROM" -f 1 -l "$BS" "$TO" -t 0 2>&1 | t_filter_fs
scoutfs move-blocks "$FROM" -f 0 -l 1 "$TO" -t 0 2>&1 | t_filter_fs
scoutfs move-blocks "$FROM" -f 0 -l "$BS" "$TO" -t 1 2>&1 | t_filter_fs

echo "== can't move onto existing extent"
dd if=/dev/urandom of="$TO" bs=$BS count=1 status=none
scoutfs move-blocks "$FROM" -f 0 -l "$BS" "$TO" -t 0 2>&1 | t_filter_fs

echo "== can't move between files with offline extents"
dd if=/dev/zero of="$TO" bs=$BS count=1 status=none
vers=$(scoutfs stat -s data_version "$TO")
scoutfs release "$TO" -V "$vers" -o 0 -l $BS
scoutfs move-blocks "$FROM" -f 0 -l "$BS" "$TO" -t 0 2>&1 | t_filter_fs
regenerate_files
vers=$(scoutfs stat -s data_version "$FROM")
scoutfs release "$FROM" -V "$vers" -o 0 -l $BS
scoutfs move-blocks "$FROM" -f 0 -l "$BS" "$TO" -t 0 2>&1 | t_filter_fs
regenerate_files

echo "== basic moves work"
move_and_compare "$FROM" 0 "$BS" "$TO" 0
regenerate_files
move_and_compare "$FROM" 0 "$BS" "$TO" "$BS"
regenerate_files
move_and_compare "$FROM" 0 "$LEN" "$TO" 0
regenerate_files

echo "== moving final partial block sets partial i_size"
move_and_compare "$FROM" $((LEN - PART)) "$PART" "$TO" 0
stat -c '%s' "$TO"
regenerate_files

echo "== moving updates inode fields"
declare -A from_before from_after to_before to_after
set_updated_fields from_before "$FROM"
set_updated_fields to_before "$TO"
t_quiet sync
sleep 1
move_and_compare "$FROM" 0 "$BS" "$TO" 0
set_updated_fields from_after "$FROM"
set_updated_fields to_after "$TO"
for k in ${!from_after[@]}; do
	if [ "${from_before[$k]}" == "${from_after[$k]}" ]; then
		echo "move didn't change from $k ${from_before[$k]}"
	fi
	if [ "${to_before[$k]}" == "${to_after[$k]}" ]; then
		echo "move didn't change to $k ${to_before[$k]}"
	fi
done
regenerate_files

echo "== moving blocks backwards works"
cp "$FROM" "$FROM.orig"
move_and_compare "$FROM" $((LEN - PART)) "$PART" "$TO" $((LEN - PART))
for i in $(seq $((BLOCKS - 1)) -1 0); do
	move_and_compare "$FROM" $((i * BS)) "$BS" "$TO" $((i * BS))
done
cmp "$TO" "$FROM.orig"
regenerate_files

echo "== combine many files into one"
for i in $(seq 0 $((PIECES - 1))); do
	dd if=/dev/urandom of="$FROM.$i" bs=$BS count=$BLOCKS status=none
	cat "$FROM.$i" >> "$TO.large"
	move_and_compare "$FROM.$i" 0 "$((BS * BLOCKS))" \
		"$TO" $((i * BS * BLOCKS))
done
((i++))
cat "$FROM" >> "$TO.large"
move_and_compare "$FROM" 0 "$LEN" "$TO" $((i * BS * BLOCKS))
cmp "$TO.large" "$TO"

t_pass
