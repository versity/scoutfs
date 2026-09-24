#
# Make sure that a fenced client regaining connectivity doesn't fence the
# current leader after a new election.
#
# 1) disable the quorum network port for a follower victim
# 2) wait for the victim to start issuing vote requests for increasing terms
# 3) reenable the quorum network port
# 4) watch for a new leader
# 5) make sure that the new leader has not fenced the previous one

t_require_commands grep iptables scoutfs
t_require_mounts 3
t_require_quorum 2

orig_leader="$(t_server_nr)"
orig_leader_sysfs="$(t_sysfs_path $orig_leader)"

t_select_victim()
{
	local nr;

	for nr in $(t_quorum_nrs)
	do
		if [ "$nr" -ne "$orig_leader" ]
		then
			echo $nr
			break
		fi
	done
}

t_disable_qport()
{
	local slot="$1"
	local port="$((T_PORT_START + slot))"

	iptables -I INPUT -p tcp --dport $port -j DROP
	iptables -I INPUT -p udp --dport $port -j DROP
	iptables -I OUTPUT -p tcp --sport $port -j DROP
	iptables -I OUTPUT -p udp --sport $port -j DROP
}

t_enable_qport()
{
	iptables -D INPUT 1
	iptables -D OUTPUT 1
	iptables -D INPUT 1
	iptables -D OUTPUT 1
}

t_get_victim_term()
{
	echo "$(cat $(t_sysfs_path $victim)/quorum/status | egrep '^term' | awk '{print $2}')"
}

t_wait_for_term_advance()
{
	local new_term

	while true
	do
		new_term="$(t_get_victim_term)"
		if [ $((new_term - orig_victim_term)) -gt 10 ]
		then
			break
		fi
		sleep 1
	done
}

victim="$(t_select_victim)"
orig_victim_term="$(t_get_victim_term)"

echo "== disabling quorum port"
t_disable_qport "$victim"

echo "== waiting for victim's term to advance"
t_wait_for_term_advance

echo "== sleeping for 3s"
sleep 3

echo "== enabling quorum port"
t_enable_qport

echo "== sleeping for 20s"
sleep 20

echo "== make sure the victim won the election"
if [ "$(t_fs_is_leader $victim)" -eq "0" ]
then
	echo Victim in slot "$victim" did not win the election
	echo slot "$(t_server_nr)" did
fi

echo "== make sure the original leader was fenced"
if [ -d "$orig_leader_sysfs" ]
then
	echo Original leader was not fenced
fi

echo "== remount the fenced leader"
t_mount "$orig_leader"

t_pass
