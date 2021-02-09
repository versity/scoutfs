#
# stress concurrent mounting and unmounting across mounts
#
# At the start of the test all mounts are mounted.  Each iteration
# randomly decides to change each mount or to leave it alone.
#
# Each iteration create dirty items across the mounts randomly, giving
# unmount some work to do.
#
# For this test to be meaningful it needs multiple mounts beyond the
# quorum majority which can be racing to mount and unmount.  A
# reasonable config would be 5 mounts with 3 quorum members.  But the
# test will run with whatever count it finds.
#
# The test assumes that the first mounts are the quorum members.
#

majority_nr=$(t_majority_count)
quorum_nr=$T_QUORUM

cur_quorum=$quorum_nr
test "$cur_quorum" == "$majority_nr" && \
	t_skip "all quorum members make up majority, need more mounts to unmount"

echo "== create per mount files" 
for i in $(t_fs_nrs); do
	eval path="\$T_D${i}/$i"
	mkdir -p "$path"
	touch "$path/$i"
	mounted[$i]=1
done

LENGTH=30
echo "== ${LENGTH}s of racing random mount/umount"
END=$((SECONDS + LENGTH))
while [ "$SECONDS" -lt "$END" ]; do

	# give some mounts dirty data
	for i in $(t_fs_nrs); do
		eval path="\$T_D${i}/$i"
		dirty=$((RANDOM % 2))
		if [ "${mounted[$i]}" == 1 -a "$dirty" == 1 ]; then
			touch "$path/$i"
		fi
	done

	pids=""
	for i in $(t_fs_nrs); do

		change=$((RANDOM % 2))
		if [ "$change" == 0 ]; then
			continue;
		fi

		if [ "${mounted[$i]}" == 1 ]; then
			#
			# can always unmount non-quorum mounts,
			# can only unmount quorum members beyond majority
			#
			if [ "$i" -ge "$quorum_nr" -o \
			     "$cur_quorum" -gt "$majority_nr" ]; then
				t_umount $i &
				pid=$!
				echo "umount $i pid $pid quo $cur_quorum" \
					>> $T_TMP.log
				pids="$pids $pid"
				mounted[$i]=0
				if [ "$i" -lt "$quorum_nr" ]; then
					(( cur_quorum-- ))
				fi
			fi
		else
			t_mount $i &
			pid=$!
			pids="$pids $pid"
			echo "mount $i pid $pid quo $cur_quorum" >> $T_TMP.log
			mounted[$i]=1
			if [ "$i" -lt "$quorum_nr" ]; then
				(( cur_quorum++ ))
			fi
		fi
	done
		
	echo "waiting (secs $SECONDS)" >> $T_TMP.log
	for p in $pids; do
		wait $p
		rc=$?
		if [ "$rc" != 0 ]; then
			echo "waiting for pid $p returned $rc"
			t_fail "background mount/umount returned error"
		fi
	done
	echo "done waiting (secs $SECONDS))" >> $T_TMP.log
done

echo "== mounting any unmounted"
for i in $(t_fs_nrs); do
	if [ "${mounted[$i]}" == 0 ]; then
		t_mount $i
	fi
done

t_pass
