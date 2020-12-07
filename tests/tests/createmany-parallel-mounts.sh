#
# Test clustered parallel createmany
#

t_require_commands mkdir createmany
t_require_mounts 2

COUNT=50000

# Prep dirs for test. Each mount needs to make their own parent dir for
# the createmany run, otherwise both dirs will end up in the same inode
# group, causing updates to bounce that lock around.
echo "== measure initial createmany"
mkdir -p $T_D0/dir/0
mkdir $T_D1/dir/1

echo "== measure initial createmany"
START=$SECONDS
createmany -o "$T_D0/file_" $COUNT >> $T_TMP.full
SINGLE=$((SECONDS - START))
echo single $SINGLE >> $T_TMP.full

echo "== measure two concurrent createmany runs"
START=$SECONDS
createmany -o $T_D0/dir/0/file $COUNT > /dev/null &
pids="$!"
createmany -o $T_D1/dir/1/file $COUNT > /dev/null &
pids="$pids $!"
for p in $pids; do
        wait $p
done
BOTH=$((SECONDS - START))
echo both $BOTH >> $T_TMP.full

# Multi node still adds significant overhead, even with our CW locks
# being effectively local node for this test. Different hardware
# setups might have a different amount of skew on the result as
# well. Cover for this with a sufficiently large safety factor so
# we're not needlessly tripping up testing. We will still easily
# exceed this factor should the CW locked items go back to fully
# synchronized operation.
FACTOR=200
if [ "$BOTH" -gt $(($SINGLE*$FACTOR)) ]; then
	echo "both createmany took $BOTH sec, more than $FACTOR x single $SINGLE sec"
fi

t_pass
