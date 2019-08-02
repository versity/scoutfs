#
# Multi-mount, multi-process EX locking test. This has uncovered at
# least one race between the downconvert thread and local processes
# wanting a lock.
#

t_require_commands setfattr

DIR="$T_D0/dir"
FILES=4
COUNT=250

echo "=== setup files ==="
mkdir -p $T_D0/dir
for f in $(seq 1 $FILES); do
	touch $T_D0/dir/file-$f
done

echo "=== ping-pong xattr ops ==="
pids=""
for f in $(seq 1 $FILES); do
	for m in $(t_fs_nrs); do
		eval file="\$T_D${m}/dir/file-$f"
		(for i in $(seq 1 $COUNT); do
			setfattr -n user.test -v mount-$m $file; 
		done) &
	pids="$pids $!"
	done
done
wait $pids

t_pass
