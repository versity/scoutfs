#
# make sure we clean up orphaned inodes
#

t_require_commands sleep touch sync stat handle_cat kill rm
t_require_mounts 2

#
# usually bash prints an annoying output message when jobs
# are killed.  We can avoid that by redirecting stderr for
# the bash process when it reaps the jobs that are killed.
#
silent_kill() {
	exec {ERR}>&2 2>/dev/null
	kill "$@"
	wait "$@"
	exec 2>&$ERR {ERR}>&-
}

#
# We don't have a great way to test that inode items still exist.   We
# don't prevent opening handles with nlink 0 today, so we'll use that.
# This would have to change to some other method.
#
inode_exists()
{
	local ino="$1"

	scoutfs get-allocated-inos -i "$ino" -s -p "$T_M0" > $T_TMP.inos.log 2>&1
	test "$?" == 0 -a "$(head -1 $T_TMP.inos.log)" == "$ino"
}

t_save_all_sysfs_mount_options orphan_scan_delay_ms
restore_delays()
{
	t_restore_all_sysfs_mount_options orphan_scan_delay_ms
}
trap restore_delays EXIT

echo "== test our inode existance function"
path="$T_D0/file"
touch "$path"
ino=$(stat -c "%i" "$path")
inode_exists $ino || echo "$ino didn't exist"

echo "== unlinked and opened inodes still exist"
sleep 1000000 < "$path" &
sleep .1 # wait for background sleep to run and open stdin
pid="$!"
rm -f "$path"
inode_exists $ino || echo "$ino didn't exist"

echo "== orphan from failed evict deletion is picked up"
# pending kill signal stops evict from getting locks and deleting
silent_kill $pid
t_set_sysfs_mount_option 0 orphan_scan_delay_ms 1000
sleep 5
inode_exists $ino && echo "$ino still exists"

echo "== orphaned inos in all mounts all deleted"
pids=""
inos=""
for nr in $(t_fs_nrs); do
	eval path="\$T_D${nr}/file-$nr"
	touch "$path"
	inos="$inos $(stat -c %i $path)"
	sleep 1000000 < "$path" &
	sleep .1 # wait for background sleep to run and open stdin
	pids="$pids $!"
	rm -f "$path"
done
sync
silent_kill $pids
for nr in $(t_fs_nrs); do
	t_force_umount $nr
done
t_mount_all
# wait for all fence requests to complete
while test -d $(echo /sys/fs/scoutfs/*/fence/* | cut -d " " -f 1); do
	sleep .5
done
# wait for orphan scans to run
t_set_all_sysfs_mount_options orphan_scan_delay_ms 1000
# also have to wait for delayed log merge work from mount
C=120
while (( C-- )); do
	brk=1
	for ino in $inos; do
		inode_exists $ino && brk=0
	done
	test $brk -eq 1 && break
	sleep 1
done
for ino in $inos; do
	inode_exists $ino && echo "$ino still exists"
done

RUNTIME=30
echo "== ${RUNTIME}s of racing evict deletion, orphan scanning, and open by handle"

# exclude last client mount
last=""
for nr in $(t_fs_nrs); do
	last=$nr
done

END=$((SECONDS + RUNTIME))
while [ $SECONDS -lt $END ]; do
	# hold open per-mount unlinked files
	pids=""
	ino_args=""
	for nr in $(t_fs_nrs); do
		test $nr == $last && continue

		eval path="\$T_D${nr}/racing-$nr"
		touch "$path"
		ino_args="$ino_args -i $(stat -c %i $path)"

		sleep 1000000 < "$path" &
		sleep .1 # wait for sleep to start and open input :/
		pids="$pids $!"
		rm -f "$path"
	done

	# remount excluded last client to force log merging and make orphan visible
	sync
	t_umount $last
	t_mount $last

	# get all mounts scanning orphans at high frequency
	t_set_all_sysfs_mount_options orphan_scan_delay_ms 100

	# spin having tasks in each mount trying to open/fsetxattr all inos
	for nr in $(t_fs_nrs); do
		test $nr == $last && continue

		eval path="\$T_M${nr}"
		handle_fsetxattr -e $ino_args -m "$path" -s 2 &
	done

	# trigger eviction deletion of each file in each mount
	silent_kill $pids

	wait || t_fail "handle_fsetxattr failed"

	# slow down orphan scanning for the next iteration
	t_set_all_sysfs_mount_options orphan_scan_delay_ms $(((RUNTIME * 2) * 1000))
done

t_pass
