#
# There was a bug where srch file compaction could get stuck if a
# partial compaction finished at the specific _SAFE_BYTES offset in a
# block.  Resuming from that position would return an error and
# compaction would stop making forward progress.
#
# We use triggers to pad the output of log compaction to end on the safe
# offset and then cause compaction of those padded inputs to stop at the
# safe offset.  Continuation will either succeed or return errors.  
#

# forcing rotation, so just a few
NR=10
SEQF="%.20g"
COMPACT_NR=4

echo "== initialize per-mount values"
declare -a err
declare -a compact_delay
for nr in $(t_fs_nrs); do
	err[$nr]=$(t_counter srch_compact_error $nr)
	compact_delay[$nr]=$(cat $(t_sysfs_path $nr)/srch/compact_delay_ms)
done
restore_compact_delay()
{
	for nr in $(t_fs_nrs); do
		echo ${compact_delay[$nr]} > $(t_sysfs_path $nr)/srch/compact_delay_ms
	done
}
trap restore_compact_delay EXIT

echo "== arm compaction triggers"
for nr in $(t_fs_nrs); do
	t_trigger_arm_silent srch_compact_logs_pad_safe $nr
	t_trigger_arm_silent srch_merge_stop_safe $nr
done

echo "== compact more often"
for nr in $(t_fs_nrs); do
	echo 1000 > $(t_sysfs_path $nr)/srch/compact_delay_ms
done

echo "== create padded sorted inputs by forcing log rotation"
sv=$(t_server_nr)
for i in $(seq 1 $COMPACT_NR); do
	for j in $(seq 1 $COMPACT_NR); do
		t_trigger_arm_silent srch_force_log_rotate $sv

		seq -f "f-$i-$j-$SEQF" 1 10 | \
			bulk_create_paths -X "scoutfs.srch.t-srch-safe-merge-pos" -d "$T_D0" > \
			/dev/null
		sync

		test "$(t_trigger_get srch_force_log_rotate $sv)" == "0" || \
			t_fail "srch_force_log_rotate didn't trigger"
	done

	padded=0
	while test $padded == 0 && sleep .5; do
		for nr in $(t_fs_nrs); do
			if [ "$(t_trigger_get srch_compact_logs_pad_safe $nr)" == "0" ]; then
				t_trigger_arm_silent srch_compact_logs_pad_safe $nr
				padded=1
				break
			fi
			test "$(t_counter srch_compact_error $nr)" == "${err[$nr]}" || \
				t_fail "srch_compact_error counter increased on mount $nr"
		done
	done
done

echo "== compaction of padded should stop at safe"
sleep 2
for nr in $(t_fs_nrs); do
	if [ "$(t_trigger_get srch_merge_stop_safe $nr)" == "0" ]; then
		break
	fi
done

echo "== verify no compaction errors"
sleep 2
for nr in $(t_fs_nrs); do
	test "$(t_counter srch_compact_error $nr)" == "${err[$nr]}" || \
		t_fail "srch_compact_error counter increased on mount $nr"
done

echo "== cleanup"
find "$T_D0" -type f -name 'f-*' -delete

t_pass
