#
# make sure pr/cw don't conflict
#

t_require_commands scoutfs

FILE="$T_D0/file"

echo "== race writing and index walking"
for i in $(seq 1 10); do
	dd if=/dev/zero of="$FILE" bs=4K count=1 status=none conv=notrunc &
	scoutfs walk-inodes data_seq 0 -1 "$T_M0" > /dev/null &
	wait
done

t_pass
