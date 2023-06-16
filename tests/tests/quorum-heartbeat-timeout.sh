#
# test that the quorum_heartbeat_time_ms option affects how long it
# takes to recover from a failed mount.
#

t_require_mounts 2

time_ms()
{
	# time_t in seconds, then trunate nanoseconds to 3 most dig digits
	date +%s%3N
}

set_bad_timeout() {
	local to="$1"
	t_set_sysfs_mount_option 0 quorum_heartbeat_timeout_ms $to && \
		t_fail "set bad q hb to $to"
}

set_timeout()
{
	local nr="$1"
	local how="$2"
	local to="$3"
	local is

	if [ $how == "sysfs" ]; then
		t_set_sysfs_mount_option $nr quorum_heartbeat_timeout_ms $to
	fi
	if [ $how == "mount" ]; then
		t_umount $nr
		t_mount_opt $nr "quorum_heartbeat_timeout_ms=$to"
	fi

	is=$(t_get_sysfs_mount_option $nr quorum_heartbeat_timeout_ms)

	if [ "$is" != "$to" ]; then
		t_fail "tried to set qhbto on $nr via $how to $to but got $is"
	fi
}

test_timeout()
{
	local how="$1"
	local to="$2"
	local start
	local nr
	local sv
	local delay
	local low
	local high

	# set timeout on non-server quorum mounts
	sv=$(t_server_nr)
	for nr in $(t_quorum_nrs); do
		if [ $nr -ne $sv ]; then
			set_timeout $nr $how $to
		fi
	done

	# give followers time to recv heartbeats and reset timeouts
	sleep 1

	# tear down the current server/leader
	t_force_umount $sv

	# see how long it takes for the next leader to start
	start=$(time_ms)
	t_wait_for_leader
	delay=$(($(time_ms) - start))

	# kind of fun to have these logged
	echo "to $to delay $delay" >> $T_TMP.delay

	# restore the mount that we tore down
	t_mount $sv

	# make sure the new leader delay was reasonable, allowing for some slack
	low=$((to - 1000))
	high=$((to + 5000))

	# make sure the new leader delay was reasonable
	test "$delay" -lt "$low" && t_fail "delay $delay < low $low (to $to)"
	test "$delay" -gt "$high" && t_fail "delay $delay > high $high (to $to)"
}

echo "== bad timeout values fail"
set_bad_timeout 0
set_bad_timeout -1
set_bad_timeout 1000000

echo "== bad mount option fails"
if [ "$(t_server_nr)" == 0 ]; then
	nr=1
else
	nr=0
fi
t_umount $nr
t_mount_opt $nr "quorum_heartbeat_timeout_ms=1000000" 2>/dev/null && \
	t_fail "bad mount option succeeded"
t_mount $nr

echo "== mount option"
def=$(t_get_sysfs_mount_option 0 quorum_heartbeat_timeout_ms)
test_timeout mount $def
test_timeout mount 3000
test_timeout mount $((def + 19000))

echo "== sysfs"
test_timeout sysfs $def
test_timeout sysfs 3000
test_timeout sysfs $((def + 19000))

echo "== reset all options"
t_remount_all

t_pass
