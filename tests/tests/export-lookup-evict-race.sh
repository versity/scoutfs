#
# test racing fh_to_dentry with evict from lock invalidation.   We've
# had deadlocks between the ordering of iget and evict when they acquire
# cluster locks.
# 

t_require_commands touch stat handle_cat
t_require_mounts 2

CPUS=$(getconf _NPROCESSORS_ONLN)
NR=$((CPUS * 4))
END=$((SECONDS + 30))

touch "$T_D0/file"
ino=$(stat -c "%i" "$T_D0/file")

while test $SECONDS -lt $END; do
	for i in $(seq 1 $NR); do
		fs=$((RANDOM % T_NR_MOUNTS))
		eval dir="\$T_D${fs}"
		write=$((RANDOM & 1))

		if [ "$write" == 1 ]; then
			touch "$dir/file" &
		else
			handle_cat "$dir" "$ino" &
		fi
	done
	wait
done

t_pass
