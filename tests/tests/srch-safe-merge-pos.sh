#
# There was a bug where srch file compaction could get stuck if a
# partial compaction finished at the specific _SAFE_BYTES offset in a
# block.  Resuming from that position would return an error and
# compaction would stop making forward progress.
#
# We use triggers to make sure that we create the circumstance where a
# sorted srch block ends at the _SAFE_BYTES offsset and that a merge
# request stops with a partial block at that specific offset.  We then
# watch error counters to make sure compaction doesn't get stuck.
#

# forcing rotation, so just a few
NR=10
SEQF="%.20g"
COMPACT_NR=4

echo "== snapshot errors"
declare -a err
for nr in $(t_fs_nrs); do
	err[$nr]=$(t_counter srch_compact_error $nr)
done

echo "== arm compaction triggers"
for nr in $(t_fs_nrs); do
	t_trigger_arm srch_compact_logs_pad_safe $nr
	t_trigger_arm srch_merge_stop_safe $nr
done

echo "== force lots of small rotated log files for compaction"
sv=$(t_server_nr)
iter=1
while [ $iter -le $((COMPACT_NR * COMPACT_NR * COMPACT_NR)) ]; do
	t_trigger_arm srch_force_log_rotate $sv

	seq -f "f-$iter-$SEQF" 1 10 | src/bulk_create_paths -S -d "$T_D0" > /dev/null
	sync

	test "$(t_trigger_get srch_force_log_rotate $sv)" == "0" || \
		t_fail "srch_force_log_rotate didn't trigger"

	((iter++))
done

echo "== wait for compaction"
sleep 15

echo "== test and disarm compaction triggers"
pad=0
merge_stop=0
for nr in $(t_fs_nrs); do
	test "$(t_trigger_get srch_compact_logs_pad_safe $nr)" == "0" && pad=1
	t_trigger_set srch_compact_logs_pad_safe $nr 0
	test "$(t_trigger_get srch_merge_stop_safe $nr)" == "0" && merge_stop=1
	t_trigger_set srch_merge_stop_safe $nr 0
done

echo "== verify triggers and errors" 
test $pad == 1 || t_fail "srch_compact_logs_pad_safe didn't trigger"
test $merge_stop == 1 || t_fail "srch_merge_stop_safe didn't trigger"
for nr in $(t_fs_nrs); do
	test "$(t_counter srch_compact_error $nr)" == "${err[$nr]}" || \
		t_fail "srch_compact_error counter increased on mount $nr"
done

echo "== cleanup"
find "$T_D0" -type f -name 'f-*' -delete

t_pass
