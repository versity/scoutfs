#
# Run tmpfile_stage and check the output with hexdump.
#

t_require_commands stage_tmpfile hexdump

DEST_FILE="$T_D0/dest_file"

stage_tmpfile $T_D0 $DEST_FILE

hexdump -C "$DEST_FILE"

rm -fr "$DEST_FILE"

t_pass
