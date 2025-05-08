#
# trigger server failover and lock recovery during heavy invalidating
# load on multiple mounts
#

majority_nr=$(t_majority_count)
quorum_nr=$T_QUORUM

test "$quorum_nr" == "$majority_nr" && \
        t_skip "need remaining majority when leader unmounted"

test "$T_NR_MOUNTS" -lt "$((quorum_nr + 2))" && \
        t_skip "need at least 2 non-quorum load mounts"

echo "== starting background invalidating read/write load"
touch "$T_D0/file"
load_pids=""
for i in $(t_fs_nrs); do
	if [ "$i" -ge "$quorum_nr" ]; then
		eval path="\$T_D${i}/file"

		(while true; do touch $path > /dev/null 2>&1; done) &
		load_pids="$load_pids $!"
		(while true; do stat $path > /dev/null 2>&1; done) &
		load_pids="$load_pids $!"
	fi
done

# had it reproduce in ~40s on wimpy debug kernel guests
LENGTH=60
echo "== ${LENGTH}s of lock recovery during invalidating load"
END=$((SECONDS + LENGTH))
while [ "$SECONDS" -lt "$END" ]; do
        sv=$(t_server_nr)
        t_umount $sv
        t_mount $sv
	# new server had to process greeting for mount to finish
done

echo "== stopping background load"
t_silent_kill $load_pids

t_pass
