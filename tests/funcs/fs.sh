
#
# Make all previously dirty items in memory in all mounts synced and
# visible in the inode seq indexes.  We have to force a sync on every
# node by dirtying data as that's the only way to guarantee advancing
# the sequence number on each node which limits index visibility.  Some
# distros don't have sync -f so we dirty our mounts then sync
# everything.
#
t_sync_seq_index()
{
	local m
	
	for m in $T_MS; do
		t_quiet touch $m
	done
	t_quiet sync
}

#
# Output the "f.$fsid.r.$rid" identifier string for the given mount
# number, 0 is used by default if none is specified. 
#
t_ident()
{
	local nr="${1:-0}"
	local mnt="$(eval echo \$T_M$nr)"
	local fsid
	local rid

	fsid=$(scoutfs statfs -s fsid -p "$mnt")
	rid=$(scoutfs statfs -s rid -p "$mnt")

	echo "f.${fsid:0:6}.r.${rid:0:6}"
}

#
# Output the mount's sysfs path, defaulting to mount 0 if none is
# specified.
#
t_sysfs_path()
{
	local nr="$1"

	echo "/sys/fs/scoutfs/$(t_ident $nr)"
}

#
# Output the mount's debugfs path, defaulting to mount 0 if none is
# specified.
#
t_debugfs_path()
{
	local nr="$1"

	echo "/sys/kernel/debug/scoutfs/$(t_ident $nr)"
}

#
# output all the configured test nrs for iteration
#
t_fs_nrs()
{
	seq 0 $((T_NR_MOUNTS - 1))
}

#
# Output the mount nr of the current server.  This takes no steps to
# ensure that the server doesn't shut down and have some other mount
# take over.  
#
t_server_nr()
{
	for i in $(t_fs_nrs); do
		if [ "$(cat $(t_sysfs_path $i)/quorum/is_leader)" == "1" ]; then
			echo $i
			return
		fi
	done

	t_fail "t_server_nr didn't find a server"
}

#
# Output the mount nr of the first client that we find.  There can be
# no clients if there's only one mount who has to be the server.  This
# takes no steps to ensure that the client doesn't become a server at
# any point.
#
t_first_client_nr()
{
	for i in $(t_fs_nrs); do
		if [ "$(cat $(t_sysfs_path $i)/quorum/is_leader)" == "0" ]; then
			echo $i
			return
		fi
	done

	t_fail "t_first_client_nr didn't find any clients"
}

#
# The number of quorum members needed to form a majority to start the
# server.
#
t_majority_count()
{
	if [ "$T_QUORUM" -lt 3 ]; then
		echo 1
	else
		echo $(((T_QUORUM / 2) + 1))
	fi
}

t_mount()
{
	local nr="$1"

	test "$nr" -lt "$T_NR_MOUNTS" || \
		t_fail "fs nr $nr invalid"

	eval t_quiet mount -t scoutfs \$T_O$nr \$T_DB$nr \$T_M$nr
}

t_umount()
{
	local nr="$1"

	test "$nr" -lt "$T_NR_MOUNTS" || \
		t_fail "fs nr $nr invalid"

	eval t_quiet umount \$T_M$i
}

#
# Attempt to mount all the configured mounts, assuming that they're
# not already mounted.
#
t_mount_all()
{
	local pids=""
	local p

	for i in $(t_fs_nrs); do
		t_mount $i &
		p="$!"
		pids="$pids $!"
	done
	for p in $pids; do
		t_quiet wait $p
	done
}

#
# Attempt to unmount all the configured mounts, assuming that they're
# all mounted.
#
t_umount_all()
{
	local pids=""
	local p

	for i in $(t_fs_nrs); do
		t_umount $i &
		p="$!"
		pids="$pids $!"
	done
	for p in $pids; do
		t_quiet wait $p
	done
}

t_remount_all()
{
	t_quiet t_umount_all || t_fail "umounting all failed"
	t_quiet t_mount_all || t_fail "mounting all failed"
}

t_reinsert_remount_all()
{
	t_quiet t_umount_all || t_fail "umounting all failed"

	t_quiet rmmod scoutfs || \
		t_fail "rmmod scoutfs failed"
	t_quiet insmod "$T_KMOD/src/scoutfs.ko" ||
		t_fail "insmod scoutfs failed"

	t_quiet t_mount_all || t_fail "mounting all failed"
}

t_trigger_path() {
	local nr="$1"

	echo "/sys/kernel/debug/scoutfs/$(t_ident $nr)/trigger"
}

t_trigger_get() {
	local which="$1"
	local nr="$2"

	cat "$(t_trigger_path "$nr")/$which"
}

t_trigger_show() {
	local which="$1"
	local string="$2"
	local nr="$3"

	echo "trigger $which $string: $(t_trigger_get $which $nr)"
}

t_trigger_arm_silent() {
	local which="$1"
	local nr="$2"
	local path=$(t_trigger_path "$nr")

	echo 1 > "$path/$which"
}

t_trigger_arm() {
	local which="$1"
	local nr="$2"

	t_trigger_arm_silent $which $nr
	t_trigger_show $which armed $nr
}

#
# output the value of the given counter for the given mount, defaulting
# to mount 0 if a mount isn't specified.
#
t_counter() {
	local which="$1"
	local nr="$2"

	cat "$(t_sysfs_path $nr)/counters/$which"
}

#
# output the difference between the current value of a counter and the
# caller's provided previous value.
#
t_counter_diff_value() {
	local which="$1"
	local old="$2"
	local nr="$3"
	local new="$(t_counter $which $nr)"

	echo "$((new - old))"
}

#
# output the value of the given counter for the given mount, defaulting
# to mount 0 if a mount isn't specified.  For tests which expect a
# specific difference in counters.
#
t_counter_diff() {
	local which="$1"
	local old="$2"
	local nr="$3"

	echo "counter $which diff $(t_counter_diff_value $which $old $nr)"
}

#
# output a message indicating whether or not the counter value changed.
# For tests that expect a difference, or not, but the amount of
# difference isn't significant.
#
t_counter_diff_changed() {
	local which="$1"
	local old="$2"
	local nr="$3"
	local diff="$(t_counter_diff_value $which $old $nr)"

	test "$diff" -eq 0 && \
		echo "counter $which didn't change" ||
		echo "counter $which changed"
}
