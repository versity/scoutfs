#
# Use the ALLOC_DATA_ENOBUFS trigger to force an ENOBUFS return from
# the data allocator.
#

t_require_commands dd rm xfs_io
t_require_o_direct

echo "== arm trigger"
t_trigger_arm_silent alloc_data_enobufs 0

echo "== generate some direct I/O"
dd if=/dev/zero of="$T_D0"/outfile_direct bs=65536 count=4096 oflag=direct status=none

echo "== confirm trigger fired"
if [ "$(t_trigger_get alloc_data_enobufs 0)" -ne "0" ]
then
	echo "trigger didn't fire for direct I/O"
fi

echo "== arm trigger"
t_trigger_arm_silent alloc_data_enobufs 0

echo "== generate some buffered I/O"
dd if=/dev/zero of="$T_D0"/outfile_buffered bs=65536 count=1024 status=none

echo "== confirm trigger fired"
if [ "$(t_trigger_get alloc_data_enobufs 0)" -ne "0" ]
then
	echo "trigger didn't fire for buffered I/O"
fi

echo "== cleanup"
rm -f "$T_D0"/outfile_direct
rm -f "$T_D0"/outfile_buffered

t_pass
