#
# test waiting for offline extents
#

t_require_commands dd cat cp scoutfs xfs_io

DIR="$T_D0/dir"
BLOCKS=256
BS=4096
BYTES=$(($BLOCKS * $BS))

expect_wait()
{
	local file=$1
	local ops=$2
	shift
	shift

	> $T_TMP.wait.expected

	while test -n "$ops" -a -n "$1"; do
		echo "ino $1 iblock $2 ops $ops" >> $T_TMP.wait.expected
		shift
		shift
	done

	scoutfs data-waiting 0 0 "$file" > $T_TMP.wait.output
	diff -u $T_TMP.wait.expected $T_TMP.wait.output
}

t_quiet mkdir -p "$DIR"

echo "== create files"
dd if=/dev/urandom of="$DIR/golden" bs=$BS count=$BLOCKS status=none
cp "$DIR/golden" "$DIR/file"
ino=$(stat -c "%i" "$DIR/file")
vers=$(scoutfs stat -s data_version "$DIR/file")

echo "== waiter shows up in ioctl"
echo "offline wating should be empty:"
scoutfs data-waiting 0 0 "$DIR" | wc -l
scoutfs release "$DIR/file" "$vers" 0 $BLOCKS
cat "$DIR/file" > /dev/null &
sleep .1
echo "offline waiting should now have one known entry:"
expect_wait "$DIR/file" "read" $ino 0

echo "== multiple waiters on same block listed once"
cat "$DIR/file" > /dev/null &
sleep .1
echo "offline waiting still has one known entry:"
expect_wait "$DIR/file" "read" $ino 0

echo "== different blocks show up"
dd if="$DIR/file" of=/dev/null bs=$BS count=1 skip=1 2> /dev/null &
sleep .1
echo "offline waiting now has two known entries:"
expect_wait "$DIR/file" "read" $ino 0 $ino 1

echo "== staging wakes everyone"
scoutfs stage "$DIR/file" "$vers" 0 $BYTES "$DIR/golden"
sleep .1
echo "offline wating should be empty again:"
scoutfs data-waiting 0 0 "$DIR" | wc -l

echo "== interruption does no harm"
scoutfs release "$DIR/file" "$vers" 0 $BLOCKS
cat "$DIR/file" > /dev/null 2>&1 &
pid="$!"
sleep .1
echo "offline waiting should now have one known entry:"
expect_wait "$DIR/file" "read" $ino 0
kill "$pid"
# silence terminated message
wait "$pid" 2> /dev/null
echo "offline waiting should be empty again:"
scoutfs data-waiting 0 0 "$DIR" | wc -l

echo "== EIO injection for waiting readers works"
ino=$(stat -c "%i" "$DIR/file")
dd if="$DIR/file" bs=$BS skip=0 of=/dev/null 2>&1 | \
	t_filter_fs | head -3 > $T_TMP.cat1 &
pid="$!"
dd if="$DIR/file" bs=$BS skip=1 of=/dev/null 2>&1 | \
	t_filter_fs | head -3 > $T_TMP.cat2 &
pid2="$!"
sleep .1
echo "offline waiting should now have two known entries:"
scoutfs data-waiting 0 0 "$DIR" | wc -l
expect_wait "$DIR/file" "read" $ino 0 $ino 1
scoutfs data-wait-err "$DIR" "$ino" "$vers" 0 $((BS*2)) read -5
sleep .1
echo "offline waiting should now have 0 known entries:"
scoutfs data-waiting 0 0 "$DIR" | wc -l
# silence terminated message
wait "$pid" 2> /dev/null
wait "$pid2" 2> /dev/null
cat $T_TMP.cat1
cat $T_TMP.cat2
echo "offline waiting should be empty again:"
scoutfs data-waiting 0 0 "$DIR" | wc -l

echo "== readahead while offline does no harm"
xfs_io -c "fadvise -w 0 $BYTES" "$DIR/file"
scoutfs stage "$DIR/file" "$vers" 0 $BYTES "$DIR/golden"
cmp "$DIR/file" "$DIR/golden"

echo "== waiting on interesting blocks works"
blocks=""
for base in $(echo 0 $(($BLOCKS / 2)) $(($BLOCKS - 2))); do
	for off in 0 1; do
		blocks="$blocks $(($base + off))"
	done
done
for b in $blocks; do
	scoutfs release "$DIR/file" "$vers" 0 $BLOCKS
	dd if="$DIR/file" of=/dev/null \
		status=none bs=$BS count=1 skip=$b 2> /dev/null &
	sleep .1
	scoutfs stage "$DIR/file" "$vers" 0 $BYTES "$DIR/golden"
	sleep .1
	echo "offline waiting is empty at block $b"
	scoutfs data-waiting 0 0 "$DIR" | wc -l
done

echo "== contents match when staging blocks forward"
scoutfs release "$DIR/file" "$vers" 0 $BLOCKS
cat "$DIR/file" > "$DIR/forward" &
for b in $(seq 0 1 $((BLOCKS - 1))); do
	dd if="$DIR/golden" of="$DIR/block" status=none bs=$BS skip=$b count=1
	scoutfs stage "$DIR/file" "$vers" $((b * $BS)) $BS "$DIR/block"
done
sleep .1
cmp "$DIR/golden" "$DIR/forward"

echo "== contents match when staging blocks backwards"
scoutfs release "$DIR/file" "$vers" 0 $BLOCKS
cat "$DIR/file" > "$DIR/backward" &
for b in $(seq $((BLOCKS - 1)) -1 0); do
	dd if="$DIR/golden" of="$DIR/block" status=none bs=$BS skip=$b count=1
	scoutfs stage "$DIR/file" "$vers" $((b * $BS)) $BS "$DIR/block"
done
sleep .1
cmp "$DIR/golden" "$DIR/backward"

echo "== truncate to same size doesn't wait"
scoutfs release "$DIR/file" "$vers" 0 $BLOCKS
truncate -s "$BYTES" "$DIR/file" &
sleep .1
echo "offline wating should be empty:"
scoutfs data-waiting 0 0 "$DIR" | wc -l

echo "== truncating does wait"
truncate -s "$BS" "$DIR/file" &
sleep .1
echo "truncate should be waiting for first block:"
expect_wait "$DIR/file" "change_size" $ino 0
scoutfs stage "$DIR/file" "$vers" 0 $BYTES "$DIR/golden"
sleep .1
echo "trunate should no longer be waiting:"
scoutfs data-waiting 0 0 "$DIR" | wc -l
cat "$DIR/golden" > "$DIR/file"
vers=$(scoutfs stat -s data_version "$DIR/file")

echo "== writing waits"
dd if=/dev/urandom of="$DIR/other" bs=$BS count=$BLOCKS status=none
scoutfs release "$DIR/file" "$vers" 0 $BLOCKS
# overwrite, not truncate+write
dd if="$DIR/other" of="$DIR/file" \
	bs=$BS count=$BLOCKS conv=notrunc status=none &
sleep .1
echo "should be waiting for write"
expect_wait "$DIR/file" "write" $ino 0
scoutfs stage "$DIR/file" "$vers" 0 $BYTES "$DIR/golden"
cmp "$DIR/file" "$DIR/other"

echo "== cleanup"
rm -rf "$DIR"

t_pass
