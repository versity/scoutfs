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
yes | dd of="$FILE" bs=8K count=1 status=none iflag=fullblock
sync

# not passing iflag=fullblock causes the file occasionally to just be
# 4K, so just to be safe we should at least check size once
test `stat --printf="%s\n" "$FILE"` -eq 8192 || t_fail "test file incorrect start size"

truncate -s 6K "$FILE"
truncate -s 12K "$FILE"
echo 3 > /proc/sys/vm/drop_caches
od -Ad -x "$FILE"

t_pass
