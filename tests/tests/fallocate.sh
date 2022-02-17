
t_require_commands fallocate cat

echo "== creating reasonably large per-mount files"
for n in $(t_fs_nrs); do
	eval path="\$T_D${n}/file-$n"

	LC_ALL=C fallocate -l 128MiB  "$path" || \
		t_fail "initial creating fallocate failed"
done

#
# we had lock inversions between read and fallocate, dropping
# the cache each time forces waiting for IO during the calls
# with the inverted locks held so we have a better chance
# of the deadlock happening.
#
DURATION=10
echo "== ${DURATION}s of racing cold reads and fallocate nop"
END=$((SECONDS + DURATION))
while [ $SECONDS -le $END ]; do

	echo 3 > /proc/sys/vm/drop_caches

	for n in $(t_fs_nrs); do
		eval path="\$T_D${n}/file-$n"
		
		LC_ALL=C fallocate -o 0 -l 4KiB  "$path" &
		cat "$path" > /dev/null &
	done

	wait || t_fail "fallocate or cat failed"
done

echo "== cleaning up files"
rm -f "$T_D0"/file-*

t_pass
