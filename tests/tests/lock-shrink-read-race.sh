#
# We had a lock server refcounting bug that could let one thread get a
# reference on a lock struct that was being freed by another thread.  We
# were able to reproduce this by having all clients try and produce a
# lot of read and null requests.
#
# This will manfiest as a hung lock and timed out test runs, probably
# with hung task messages on the console.  Depending on how the race
# turns out, it can trigger KASAN warnings in
# process_waiting_requests().
#

READERS_PER=3
SECS=30

echo "=== setup"
touch "$T_D0/file"

echo "=== spin reading and shrinking"
END=$((SECONDS + SECS))
for m in $(t_fs_nrs); do
	eval file="\$T_D${m}/file"

	# lots of tasks reading as fast as they can
	for t in $(seq 1 $READERS_PER); do
		(while [ $SECONDS -lt $END ]; do
			stat $file > /dev/null
		 done) &
	done
	# one task shrinking (triggering null requests) and reading
	(while [ $SECONDS -lt $END ]; do
		stat $file > /dev/null
		t_trigger_arm_silent statfs_lock_purge $m
		stat -f "$file" > /dev/null
	 done) &
done

wait

t_pass
