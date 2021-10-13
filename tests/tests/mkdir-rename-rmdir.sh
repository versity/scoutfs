#
# Sequentially perform operations on a dir (mkdir; rename*2; rmdir) on
# all possible combinations of different mounts that could perform the
# operations.
#
# We're testing that the tracking of the entry key in our cached dirents
# stays consitent with the persistent entry items as they're modified
# around the cluster.
#

t_require_commands mkdir mv rmdir

NR_OPS=4

unset op_mnt
for op in $(seq 0 $NR_OPS); do
	op_mnt[$op]=0
done

if [ $T_NR_MOUNTS -gt $NR_OPS ]; then
	NR_MNTS=$NR_OPS
else
	NR_MNTS=$T_NR_MOUNTS
fi

while : ; do
	# sequentially perform each op from its mount dir
	for op in $(seq 0 $((NR_OPS - 1))); do
		m=${op_mnt[$op]}
		eval dir="\$T_D${m}/dir"

		case "$op" in
			0) mkdir "$dir" ;;
			1) mv "$dir" "$dir-1" ;;
			2) mv "$dir-1" "$dir-2" ;;
			3) rmdir "$dir-2" ;;
		esac

		if [ $? != 0 ]; then
			t_fail "${op_mnt[*]} failed at op $op"
		fi
	done

	# advance through mnt nrs for each op
	i=0
	while [ $i -lt $NR_OPS ]; do
		((op_mnt[$i]++))
		if [ ${op_mnt[$i]} -ge $NR_MNTS ]; then
			op_mnt[$i]=0
			((i++))
		else
			break
		fi
	done

	# done when the last op's mnt nr wrapped
	[ $i -ge $NR_OPS ] && break
done

t_pass
