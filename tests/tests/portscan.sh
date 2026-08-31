#
# Make sure the server ignores connections that aren't participating.
#

t_require_commands nc

echo "== make sure unknown disconnect doesn't shut down server"
# get server addr [1] and port [1]
sv=$(t_server_nr)
addrs=($(grep "peer 0.0.0.0" $(t_debugfs_path $sv)/connections |  \
	awk -F"[: ]" '{print $2,$3}'))

# verify that the server is leader and record its term
echo "should be leader: $(cat $(t_sysfs_path $sv)/quorum/is_leader)"
before=$(awk '($1 == "term") { print $2 }' < $(t_sysfs_path $sv)/quorum/status)

# send junk
echo "  " | nc ${addrs[0]} ${addrs[1]}

# make sure the server is still leader with the same term
echo "should still be leader: $(cat $(t_sysfs_path $sv)/quorum/is_leader)"
after=$(awk '($1 == "term") { print $2 }' < $(t_sysfs_path $sv)/quorum/status)

if [ -z "$before" -o -z "$after" ]; then
	echo "couldn't find terms: before '$before', or after '$after'"
fi
if [ "$before" != "$after" ]; then
	echo "term before $before != term after $after"
fi

t_pass
