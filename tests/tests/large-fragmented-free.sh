#
# Make sure the server can handle a transaction with a data_freed whose
# blocks all hit different btree blocks in the main free list.  It
# probably has to be merged in multiple commits.
#

t_require_commands fragmented_data_extents

EXTENTS_PER_BTREE_BLOCK=600
EXTENTS_PER_LIST_BLOCK=8192
FREED_EXTENTS=$((EXTENTS_PER_BTREE_BLOCK * EXTENTS_PER_LIST_BLOCK))

echo "== creating fragmented extents"
fragmented_data_extents $FREED_EXTENTS $EXTENTS_PER_BTREE_BLOCK "$T_D0/alloc" "$T_D0/move"

echo "== unlink file with moved extents to free extents per block"
rm -f "$T_D0/move"

echo "== cleanup"
rm -f "$T_D0/alloc"

t_pass
