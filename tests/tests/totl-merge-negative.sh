#
# Test that merge_read_item() correctly updates the sequence number when
# combining delta items from multiple finalized log trees.
#
# A bug in merge_read_item() fails to update found->seq to the max of
# both items' seqs when combining deltas.  The combined item retains
# a stale seq from the lower-RID tree processed first.
#
# Two mounts create totl delta items for the same keys.  The lower-RID
# mount writes first so it acquires locks first and gets lower seqs.
# Finalized trees are iterated in (rid, nr) key order during merge, so
# the lower-RID tree (with lower seqs) is processed first -- the
# combined item keeps the stale seq from that tree.
#
# An initial round of writes + merge establishes baseline totl values
# and commits all transactions.  The second round writes FIRST then
# SECOND in sequence so FIRST opens a fresh transaction first (lower
# trans_seq) and acquires locks first (lower write_seq).
#
# The dirty limit override forces partial merges so that stale-seq
# items are written to fs_root while finalized logs still exist,
# causing readers to double-count finalized deltas.
#
# The read-xattr-totals ioctl uses a sliding cursor that can return
# pre-merge values (< expected) or duplicate entries when btree data
# changes between batches.  Only totals ABOVE the expected value
# indicate the double-counting bug.
#

t_require_commands totl_xattr_fill scoutfs
t_require_mounts 2

NR_KEYS=50000
EXPECTED_TOTAL=250

rid_0=$(t_mount_rid 0)
rid_1=$(t_mount_rid 1)

if [[ "$rid_0" < "$rid_1" ]]; then
	FIRST=0; SECOND=1
else
	FIRST=1; SECOND=0
fi

FIRST_D="$(eval echo \$T_D$FIRST)"
SECOND_D="$(eval echo \$T_D$SECOND)"

echo "== setup"
totl_xattr_fill -d "$FIRST_D" -p file-first- -n $NR_KEYS -v 100 -c
totl_xattr_fill -d "$SECOND_D" -p file-second- -n $NR_KEYS -v 100 -c
sync
t_force_log_merge

echo "== update and merge"

# FIRST writes first: opens new transaction first (lower trans_seq),
# acquires locks first (lower write_seq).
totl_xattr_fill -d "$FIRST_D" -p file-first- -n $NR_KEYS -v 200
totl_xattr_fill -d "$SECOND_D" -p file-second- -n $NR_KEYS -v 50

# Force partial merges by limiting dirty bytes to one block so that
# stale-seq combined items get written to fs_root while finalized
# logs still exist.
for i in $(t_fs_nrs); do
	echo 4096 > $(t_debugfs_path $i)/log_merge_dirty_limit
done

sync

# Start the merge but don't wait for completion -- read totals while
# the merge is running so we can catch the double-counting window.
sv=$(t_server_nr)
last_complete=$(t_counter log_merge_complete $sv)

t_trigger_arm_silent log_merge_force_finalize_ours $sv
t_sync_seq_index
while test "$(t_trigger_get log_merge_force_finalize_ours $sv)" == "1"; do
	sleep .1
done

echo "== verify totals"

# Read totals repeatedly while the merge runs.  The stale-seq bug
# causes totl_merge_resolve() to double-count finalized deltas for
# keys spliced into fs_root with a stale sequence number, producing
# totals above the expected value.
#
# The sliding cursor may return pre-merge values (below expected) or
# duplicate entries -- these are not the bug.  Only totals ABOVE the
# expected value indicate double-counting.
nr_reads=0
while (( $(t_counter log_merge_complete $sv) == last_complete )); do
	for i in $(t_fs_nrs); do
		echo 1 > $(t_debugfs_path $i)/drop_weak_item_cache
	done
	bad=$(scoutfs read-xattr-totals -p "$T_M0" | \
		awk -F'[ =,]+' -v limit=$EXPECTED_TOTAL '$2+0 > limit+0')
	nr_reads=$((nr_reads + 1))
	if [ -n "$bad" ]; then
		echo "double-counted totals during merge (read $nr_reads):"
		echo "$bad"
		for i in $(t_fs_nrs); do
			echo 0 > $(t_debugfs_path $i)/log_merge_dirty_limit
		done
		t_fail "stale seq caused double-counted totals"
	fi
done

# Restore normal dirty limit.
for i in $(t_fs_nrs); do
	echo 0 > $(t_debugfs_path $i)/log_merge_dirty_limit
done

echo "== cleanup"
find "$FIRST_D" -maxdepth 1 -name 'file-first-*' -delete
find "$SECOND_D" -maxdepth 1 -name 'file-second-*' -delete

t_pass
