#
# Test clustered parallel createmany
#

t_require_commands mkdir createmany
t_require_mounts 2

COUNT=50000

#
# Prep dirs for test.  We have per-directory inode number allocators so
# by putting each createmany in a per-mount dir they get their own inode
# number region and cluster locks.
#
echo "== measure initial createmany"
mkdir -p $T_D0/dir/0
mkdir $T_D1/dir/1

echo "== measure initial createmany"
START=$SECONDS
createmany -o "$T_D0/file_" $COUNT >> $T_TMP.full
sync
SINGLE=$((SECONDS - START))
echo single $SINGLE >> $T_TMP.full

echo "== measure two concurrent createmany runs"
START=$SECONDS
(cd $T_D0/dir/0; createmany -o ./file_ $COUNT > /dev/null) &
pids="$!"
(cd $T_D1/dir/1; createmany -o ./file_ $COUNT > /dev/null) &
pids="$pids $!"
for p in $pids; do
        wait $p
done
sync
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
	t_fail "both createmany took $BOTH sec, more than $FACTOR x single $SINGLE sec"
fi

echo "== cleanup"
find $T_D0/dir -delete

t_pass
