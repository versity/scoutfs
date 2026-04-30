#
# Exercise the SCOUTFS_IOC_INJECT_TOTL_DELTA ioctl that injects totl
# deltas directly via totl-delta-inject(1).
#

t_require_commands setfattr scoutfs sync rm touch totl-delta-inject

# force a log merge then read-xattr-totals filtered to our own keys
read_totals()
{
	t_force_log_merge
	sync
	echo 1 > $(t_debugfs_path)/drop_weak_item_cache
	scoutfs read-xattr-totals -p "$T_M0" | \
		grep -E '^8888\.' || true
}

echo "== setup three files contributing to totl 8888.0.0"
touch "$T_D0/f1" "$T_D0/f2" "$T_D0/f3"
setfattr -n scoutfs.totl.inj.8888.0.0 -v 2  "$T_D0/f1"
setfattr -n scoutfs.totl.inj.8888.0.0 -v 8  "$T_D0/f2"
setfattr -n scoutfs.totl.inj.8888.0.0 -v 32 "$T_D0/f3"

echo "== merge baseline into fs_root"
read_totals

echo "== inject (+128, +2) unbalances totl 8888.0.0"
totl-delta-inject "$T_M0" 8888.0.0 128 2
read_totals

echo "== unlink f3 (value 32) produces a -32/-1 delta"
rm -f "$T_D0/f3"
read_totals

echo "== inject (-128, -2) restores accounting for the remaining files"
totl-delta-inject "$T_M0" 8888.0.0 -128 -2
read_totals

echo "== cleanup"
rm -f "$T_D0/f1" "$T_D0/f2"
read_totals

t_pass
