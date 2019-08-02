#
# We had some segment reading patterns that lead to excessive segment
# reading if ops iterated over items in the opposite order that they're
# sorted in segments.
#
# Let's make sure iterating over items in either directions causes the
# item reading path to cache the items in the segments regardless of
# which item caused the miss.
#
# We can use the count of item allocations as a proxy for the bad
# behaviour.
#

t_require_commands mkdir touch stat cat

DIR="$T_D0/dir"
NR=3000

t_quiet mkdir -p "$DIR"

echo "== create files"
for a in $(seq 1 $NR); do t_quiet touch $DIR/$a; done

echo "== count allocations reading forwards"
echo 3 > /proc/sys/vm/drop_caches
for a in $(seq 1 $NR); do stat $DIR/$a > /dev/null; done
FWD=$(t_counter item_alloc)
echo "forward item allocations: $FWD" >> "$T_TMP.log"

echo "== count allocations reading backwards"
echo 3 > /proc/sys/vm/drop_caches
for a in $(seq $NR -1 1); do stat $DIR/$a > /dev/null; done
BWD=$(t_counter item_alloc)
echo "backward item allocations: $BWD" >> "$T_TMP.log"
if [ "$BWD" -gt "$((FWD * 5))" ]; then
	echo "backward item iteration allocated $BWD > 5x forward $FWD"
fi

t_pass
