#
# portscan tests - assure malformed packets do not cause issues
#
# Send a short garbage payload to a scoutfs server quorum port. The
# accepted connection never completes a valid greeting, so after the
# reconnect timeout the kernel must drop it silently rather than
# fence it (which would restart the server).
#

t_require_commands scoutfs grep wc seq

send_garbage()
{
	local port="$1"

	(
		exec 3<>"/dev/tcp/127.0.0.1/$port" || exit 1
		printf '    ' >&3
		exec 3>&-
	) 2>/dev/null
}

echo "== send empty payload to a quorum port"
slot=-1
for i in $(seq 0 $((T_QUORUM - 1))); do
	if send_garbage "$((T_TEST_PORT + i))"; then
		slot=$i
		break
	fi
done
test "$slot" -ge 0 || t_fail "no quorum port accepted"

# CLIENT_RECONNECT_TIMEOUT_MS is 20s - wait until that happens.
echo "== greeting-less connections still in reconn_wait"
for _ in $(seq 1 25); do
	n=$(grep -h 'vg 0 .* rw 1' /sys/kernel/debug/scoutfs/*/connections | wc -l)
	[ "$n" = 0 ] && break
	sleep 1
done
test "$n" -eq 0 || t_fail "$n greeting-less conns remain in reconn_wait"

# the mount whose port we hit should be up and not disconnected now.
eval dir=\$T_D$slot
touch "$dir/portscan-after" 2>/dev/null || t_fail "fs on $dir not responsive after portscan"

t_pass
