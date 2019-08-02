#
# stress concurrent mounting and unmounting across mounts
#
# At the start of the test all mounts are mounted.  Each iteration
# randomly decides to change each mount or to leave it alone.
#
# They create dirty items before unmounting to encourage compaction
# while unmounting
#
# For this test to be meaningful it needs multiple mounts beyond the
# quorum set which can be racing to mount and unmount.  A reasonable
# config would be 5 mounts with 3 quorum.  But the test will run with
# whatever count it finds.
#
# This assumes that all the mounts are configured as voting servers.  We
# could update it to be more clever and know that it can always safely
# unmount mounts that aren't configured as servers.
#

# nothing to do if we can't unmount
test "$T_NR_MOUNTS" == "$T_QUORUM" && t_skip

nr_mounted=$T_NR_MOUNTS
nr_quorum=$T_QUORUM

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
			if [ "$nr_mounted" -gt "$nr_quorum" ]; then
				t_umount $i &
				pid=$!
				pids="$pids $pid"
				mounted[$i]=0
				(( nr_mounted-- ))
			fi
		else
			t_mount $i &
			pid=$!
			pids="$pids $pid"
			mounted[$i]=1
			(( nr_mounted++ ))
		fi
	done
		
	echo "waiting (secs $SECONDS)" >> $T_TMP.log
	for p in $pids; do
		t_quiet wait $p
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
