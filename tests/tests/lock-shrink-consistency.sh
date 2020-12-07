#
# Test that lock shrinking properly invalidates metadata so that future
# locks see new data.
#

t_require_commands getfattr
t_require_mounts 2

GETFATTR="getfattr --absolute-names"

# put the inode in its own lock in a new dir with new ino allocation
echo "=== setup test file ==="
t_quiet mkdir -p $T_D0/dir
touch $T_D0/dir/file
setfattr -n user.test -v aaa $T_D0/dir/file
$GETFATTR -n user.test $T_D0/dir/file 2>&1 | t_filter_fs

echo "=== commit dirty trans and revoke lock ==="
t_trigger_arm statfs_lock_purge
stat -f "$T_M0" > /dev/null
t_quiet sync
t_trigger_show statfs_lock_purge "after it fired"

echo "=== change xattr on other mount ==="
setfattr -n user.test -v bbb $T_D1/dir/file
$GETFATTR -n user.test $T_D1/dir/file 2>&1 | t_filter_fs

# This forces the shrinking node to recreate the lock resource. If our
# lock shrinker isn't properly invalidating metadata, we'd get the old
# xattr value here.
echo "=== verify new xattr under new lock on first mount ==="
$GETFATTR -n user.test $T_D0/dir/file 2>&1 | t_filter_fs

t_pass
