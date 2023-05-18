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

set_quorum_timeouts()
{
	local to="$1"
	local was
	local is

	for nr in $(t_quorum_nrs); do
		local mnt="$(eval echo \$T_M$nr)"

		was=$(t_get_sysfs_mount_option $nr quorum_heartbeat_timeout_ms)
		t_set_sysfs_mount_option $nr quorum_heartbeat_timeout_ms $to
		is=$(t_get_sysfs_mount_option $nr quorum_heartbeat_timeout_ms)

		if [ "$is" != "$to" ]; then
			t_fail "tried to set qhbto on $nr to $to but got $is"
		fi
	done
}

test_timeout()
{
	local to="$1"
	local orig_to
	local start
	local nr
	local delay

	# set new timeouts, saving original
	orig_to=$(t_get_sysfs_mount_option 0 quorum_heartbeat_timeout_ms)
	set_quorum_timeouts $to

	# give followers time to recv heartbeats and reset timeouts
	sleep 1

	# tear down the current server/leader
	nr=$(t_server_nr)
	t_force_umount $nr

	# see how long it takes for the next leader to start
	start=$(time_ms)
	t_wait_for_leader
	delay=$(($(time_ms) - start))

	# kind of fun to have these logged
	echo "to $to delay $delay" >> $T_TMP.delay

	# restore the mount that we tore down
	t_mount $nr

	# reset the original timeouts
	set_quorum_timeouts $orig_to

	# make sure the new leader delay was reasonable
	test "$delay" -gt "$to" || t_fail "delay $delay < to $to"
	# allow 5 seconds of slop
	test "$delay" -lt $(($to + 5000)) || t_fail "delay $delay > to $to + 5sec"
}

echo "== bad timeout values fail"
set_bad_timeout 0
set_bad_timeout -1
set_bad_timeout 1000000

echo "== test different timeouts"
def=$(t_get_sysfs_mount_option 0 quorum_heartbeat_timeout_ms)
test_timeout $def
test_timeout 3000
test_timeout $((def + 19000))

t_pass
