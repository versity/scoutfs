#
# Fence nodes and reclaim their resources.
#

t_require_commands sleep touch grep sync scoutfs
t_require_mounts 2

#
# Make sure that all mounts can read the results of a write from each
# mount.
#
check_read_write()
{
	local expected
	local path
	local saw
	local w
	local r

	for w in $(t_fs_nrs); do
		expected="$w wrote at $(date --rfc-3339=ns)"
		eval path="\$T_D${w}/written"
		echo "$expected" > "$path"

		for r in $(t_fs_nrs); do
			eval path="\$T_D${r}/written"
			saw=$(cat "$path")
			if [ "$saw" != "$expected" ]; then
				echo "mount $r read '$saw' after mount $w wrote '$expected'"
			fi
		done
	done
}

# verify that fenced ran our testing fence script
verify_fenced_run()
{
	local rids="$@"
	local rid
	local n=3

	while ((n--)); do
		for rid in $rids; do
			grep -q ".* running rid '$rid'.* args 'ignored run args'" "$T_FENCED_LOG" || \
				if (( n == 0 )); then
					t_fail "fenced didn't execute RUN script for rid $rid"
				else
					sleep 1
				fi
		done
	done
}

echo "== make sure all mounts can see each other"
check_read_write

echo "== force unmount one client, connection timeout, fence nop, mount"
cl=$(t_first_client_nr)
sv=$(t_server_nr)
rid=$(t_mount_rid $cl)
echo "cl $cl sv $sv rid $rid" >> "$T_TMP.log"
sync
t_force_umount $cl
# wait for client reconnection to timeout
while grep -q $rid $(t_debugfs_path $sv)/connections; do
	sleep .5
done
while t_rid_is_fencing $rid; do
	sleep .5
done
verify_fenced_run $rid
t_mount $cl
check_read_write

echo "== force unmount all non-server, connection timeout, fence nop, mount"
sv=$(t_server_nr)
pattern="nonsense"
rids=""
sync
for cl in $(t_fs_nrs); do
	if [ $cl == $sv ]; then
		continue;
	fi

	rid=$(t_mount_rid $cl)
	rids="$rids $rid"
	pattern="$pattern|$rid"
	echo "cl $cl sv $sv rid $rid" >> "$T_TMP.log"

	t_force_umount $cl
done

# wait for all client reconnections to timeout
while egrep -q "($pattern)" $(t_debugfs_path $sv)/connections; do
	sleep .5
done
# wait for all fence requests to complete
while test -d $(echo /sys/fs/scoutfs/*/fence/* | cut -d " " -f 1); do
	sleep .5
done
verify_fenced_run $rids
# remount all the clients
for cl in $(t_fs_nrs); do
	if [ $cl == $sv ]; then
		continue;
	fi
	t_mount $cl
done
check_read_write

echo "== force unmount server, quorum elects new leader, fence nop, mount"
sv=$(t_server_nr)
rid=$(t_mount_rid $sv)
echo "sv $sv rid $rid" >> "$T_TMP.log"
sync
t_force_umount $sv
t_wait_for_leader
# wait until new server is done fencing unmounted leader rid
while t_rid_is_fencing $rid; do
	sleep .5
done
verify_fenced_run $rid
t_mount $sv
check_read_write

echo "== force unmount everything, new server fences all previous"
sync
rids=""
# get rids before forced unmount breaks scoutfs statfs
for nr in $(t_fs_nrs); do
	rids="$rids $(t_mount_rid $nr)"
done
for nr in $(t_fs_nrs); do
	t_force_umount $nr
done
t_mount_all
# wait for all fence requests to complete
while test -d $(echo /sys/fs/scoutfs/*/fence/* | cut -d " " -f 1); do
	sleep .5
done
verify_fenced_run $rids
check_read_write

t_pass
