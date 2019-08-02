#
# make sure lock revocation doesn't confuse getcwd
#

DIR="$T_D0/dir"

t_quiet mkdir -p "$DIR"

echo "=== getcwd after lock revocation"
cd "$DIR"
t_trigger_arm statfs_lock_purge
stat -f "$T_M0" > /dev/null
strace -e getcwd pwd 2>&1 | grep -i enoent
ls -la /proc/self/cwd | grep "(deleted)"
cd - > /dev/null

t_pass
