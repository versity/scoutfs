#
# Test basic correctness of truncate.
#

t_require_commands yes dd od truncate

FILE="$T_D0/file"

#
# We forgot to write a dirty block that zeroed the tail of a partial
# final block as we truncated past it.
#
echo "== truncate writes zeroed partial end of file block"
yes | dd of="$FILE" bs=8K count=1 status=none
sync
truncate -s 6K "$FILE"
truncate -s 12K "$FILE"
echo 3 > /proc/sys/vm/drop_caches
od -Ad -x "$FILE"

t_pass
