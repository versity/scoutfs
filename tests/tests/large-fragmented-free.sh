#
# Make sure the server can handle a transaction with a data_freed whose
# blocks all hit different btree blocks in the main free list.  It
# probably has to be merged in multiple commits.
#

t_require_commands fragmented_data_extents

EXTENTS_PER_BTREE_BLOCK=600
EXTENTS_PER_LIST_BLOCK=8192
FREED_EXTENTS=$((EXTENTS_PER_BTREE_BLOCK * EXTENTS_PER_LIST_BLOCK))

#
# This test specifically creates a pathologically sparse file that will
# be as expensive as possible to free.  This is usually fine on
# dedicated or reasonable hardware, but trying to run this in
# virtualized debug kernels can take a very long time.  This test is
# about making sure that the server doesn't fail, not that the platform
# can handle the scale of work that our btree formats happen to require
# while execution is bogged down with use-after-free memory reference
# tracking.  So we give the test a lot more breathing room before
# deciding that its hung.
#
echo "== setting longer hung task timeout"
if [ -w /proc/sys/kernel/hung_task_timeout_secs ]; then
	secs=$(cat /proc/sys/kernel/hung_task_timeout_secs)
	test "$secs" -gt 0 || \
		t_fail "confusing value '$secs' from /proc/sys/kernel/hung_task_timeout_secs"
	restore_hung_task_timeout()
	{
		echo "$secs" > /proc/sys/kernel/hung_task_timeout_secs
	}
	trap restore_hung_task_timeout EXIT
	echo "$((secs * 5))" > /proc/sys/kernel/hung_task_timeout_secs
fi

echo "== creating fragmented extents"
fragmented_data_extents $FREED_EXTENTS $EXTENTS_PER_BTREE_BLOCK "$T_D0/alloc" "$T_D0/move"

echo "== unlink file with moved extents to free extents per block"
rm -f "$T_D0/move"

echo "== cleanup"
rm -f "$T_D0/alloc"

t_pass
