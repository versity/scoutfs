#
# Regression for the BUG_ON in scoutfs_quota_invalidate when a concurrent
# ruleset read on one mount races with a quota rule modification.
#

t_require_mounts 2

TEST_UID=22222
SET_UID="--ruid=$TEST_UID --euid=$TEST_UID"

echo "== setup"
mkdir -p "$T_D0/dir"
chown --quiet $TEST_UID "$T_D0/dir"

# totl xattr gives quota checks something to consult
setfattr -n scoutfs.totl.test.1.1.1 -v 1 "$T_D0/dir"

echo "== concurrent quota mod and check across mounts"

(
	for i in $(seq 1 20); do
		scoutfs quota-add -p "$T_M0" \
			-r "1 1,L,- 1,L,- $i,L,- I 999999 -" 2>/dev/null
		scoutfs quota-del -p "$T_M0" \
			-r "1 1,L,- 1,L,- $i,L,- I 999999 -" 2>/dev/null
	done
) &
MOD_PID=$!

# same mount as the mod: races local read against invalidate
(
	for i in $(seq 1 50); do
		setpriv $SET_UID touch "$T_D0/dir/race0_$i" 2>/dev/null
		rm -f "$T_D0/dir/race0_$i"
	done
) &
CHECK0_PID=$!

# other mount: drives cross-node lock traffic
(
	for i in $(seq 1 50); do
		setpriv $SET_UID touch "$T_D1/dir/race1_$i" 2>/dev/null
		rm -f "$T_D1/dir/race1_$i"
	done
) &
CHECK1_PID=$!

t_quiet wait $MOD_PID
t_quiet wait $CHECK0_PID
t_quiet wait $CHECK1_PID

echo "== verify quota rules are consistent after race"
scoutfs quota-wipe -p "$T_M0"
scoutfs quota-list -p "$T_M0"

echo "== verify file creation still works under quota"
scoutfs quota-add -p "$T_M0" -r "1 1,L,- 1,L,- 1,L,- I 999999 -"
sync
echo 1 > $(t_debugfs_path)/drop_weak_item_cache
echo 1 > $(t_debugfs_path)/drop_quota_check_cache
setpriv $SET_UID touch "$T_D0/dir/verify_file"
test -f "$T_D1/dir/verify_file" && echo "file visible on mount 1"
rm -f "$T_D0/dir/verify_file"
scoutfs quota-wipe -p "$T_M0"

echo "== cleanup"
setfattr -x scoutfs.totl.test.1.1.1 "$T_D0/dir"
rm -rf "$T_D0/dir"

t_pass
