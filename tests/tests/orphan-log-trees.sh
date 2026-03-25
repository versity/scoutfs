#
# Test that orphaned log_trees entries from unmounted rids are
# finalized and merged.
#
# An orphan log_trees entry is one whose rid has no mounted_clients
# entry.  This can happen from incomplete reclaim across server
# failovers.  We simulate it with the reclaim_skip_finalize trigger
# which makes reclaim_open_log_tree skip the finalization step.
#

t_require_commands touch scoutfs
t_require_mounts 2

TIMEOUT=90

echo "== create orphan log_trees entry via trigger"
sv=$(t_server_nr)
cl=$(t_first_client_nr)
rid=$(t_mount_rid $cl)

touch "$T_D0/file" "$T_D1/file"
sync

# arm the trigger so reclaim skips finalization
t_trigger_arm_silent reclaim_skip_finalize $sv

# force unmount the client, server will fence and reclaim it
# but the trigger makes reclaim leave log_trees unfinalized
t_force_umount $cl

# wait for fencing to run
verify_fenced() {
	grep -q "running rid '$rid'" "$T_FENCED_LOG" 2>/dev/null
}
t_wait_until_timeout $TIMEOUT verify_fenced

# give the server time to complete reclaim after fence
sleep 5

# remount the client so t_force_log_merge can sync all mounts.
# the client gets a new rid; the old rid's log_trees is the orphan.
t_mount $cl

echo "== verify orphan is reclaimed and merge completes"
t_force_log_merge

echo "== verify orphan reclaim was logged"
if ! dmesg | grep -q "reclaiming orphan log trees for rid $rid"; then
	t_fail "expected orphan reclaim message for rid $rid in dmesg"
fi

t_pass
