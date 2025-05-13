#
# simple renameat2 NOREPLACE unit test
#

t_require_commands dumb_renameat2
t_require_mounts 2

echo "=== renameat2 noreplace flag test"

# give each mount their own dir (lock group) to minimize create contention
mkdir $T_D0/dir0
mkdir $T_D1/dir1

echo "=== run two asynchronous calls to renameat2 NOREPLACE"
for i in $(seq 0 100); do
        # prepare inputs in isolation
        touch "$T_D0/dir0/old0"
        touch "$T_D1/dir1/old1"

        # race doing noreplace renames, both can't succeed
        dumb_renameat2 -n "$T_D0/dir0/old0" "$T_D0/dir0/sharednew" 2> /dev/null &
        pid0=$!
        dumb_renameat2 -n "$T_D1/dir1/old1" "$T_D1/dir0/sharednew" 2> /dev/null &
        pid1=$!

        wait $pid0
        rc0=$?
        wait $pid1
        rc1=$?

        test "$rc0" == 0 -a "$rc1" == 0 && t_fail "both renames succeeded"

        # blow away possible files for either race outcome
        rm -f "$T_D0/dir0/old0" "$T_D1/dir1/old1" "$T_D0/dir0/sharednew" "$T_D1/dir1/sharednew"
done

t_pass
