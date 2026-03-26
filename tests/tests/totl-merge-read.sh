#
# Test that merge_read_item() correctly updates the sequence number when
# combining delta items from multiple finalized log trees.  Each mount
# sets a totl value in its own 3-bit lane (powers of 8) so that any
# double-counting overflows the lane and is caught by: or(v, exp) != exp.
#

t_require_commands setfattr scoutfs
t_require_mounts 5

echo "== setup"
for nr in $(t_fs_nrs); do
	d=$(eval echo \$T_D$nr)
	for i in $(seq 1 2500); do : > "$d/f$nr$i"; done
done
sync
t_force_log_merge

vals=(1 8 64 512 4096)
expected=4681
n=0
for nr in $(t_fs_nrs); do
	d=$(eval echo \$T_D$nr)
	v=${vals[$((n++))]}
	for i in $(seq 1 2500); do
		setfattr -n "scoutfs.totl.t.$i.0.0" -v $v "$d/f$nr$i"
	done
done

t_trigger_arm_silent log_merge_force_partial $(t_server_nr)

bad="$T_TMPDIR/bad"
for nr in $(t_fs_nrs); do
	( while true; do
		echo 1 > "$(t_debugfs_path $nr)/drop_weak_item_cache"
		scoutfs read-xattr-totals -p "$(eval echo \$T_M$nr)" | \
			awk -F'[ =,]+' -v e=$expected 'or($2+0,e) != e'
	done ) >> "$bad" &
done

echo "expected $expected"
t_force_log_merge
t_silent_kill $(jobs -p)
test -s "$bad" && echo "double-counted:" && cat "$bad"

echo "== cleanup"
for nr in $(t_fs_nrs); do
	find "$(eval echo \$T_D$nr)" -name "f$nr*" -delete
done
t_pass
