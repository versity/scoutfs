#
# cross mount freeing
#
# We should be able to continually allocate on one node and free
# on another and have free blocks flow without seeing premature
# enospc failures.
#

t_require_commands stat fallocate truncate
t_require_mounts 2

echo "== repeated cross-mount alloc+free, totalling 2x free"
free_blocks=$(stat -f -c "%a" "$T_M0")
file_blocks=$((free_blocks / 10))
iter=$((free_blocks * 2 / file_blocks))
file_size=$((file_blocks * 4096))

for i in $(seq 1 $iter); do
	fallocate -l $file_size "$T_D0/file"
	truncate -s 0 "$T_D1/file"
done

echo "== remove empty test file"
t_quiet rm $T_D0/file

t_pass
