#
# basic tests of O_TMPFILE
#

t_require_commands stage_tmpfile hexdump

echo "== non-acl O_TMPFILE creation honors umask"
o_tmpfile_umask "$T_D0" "$T_D0/umask-file" 

echo "== stage from tmpfile"
DEST_FILE="$T_D0/dest_file"
stage_tmpfile $T_D0 $DEST_FILE
hexdump -C "$DEST_FILE"
rm -f "$DEST_FILE"

t_pass
