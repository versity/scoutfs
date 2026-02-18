#
# Test that merge_read_item() correctly updates the sequence number when
# combining delta items from multiple finalized log trees.
#
# A bug in merge_read_item() fails to update found->seq to the max of
# both items' seqs when combining deltas.  The combined item retains
# a stale seq from the lower-RID tree processed first.
#
# Multiple write/merge/read passes increase the chance of hitting the
# double-counting window.
#
# The log_merge_force_partial trigger forces one-block dirty limits on
# each merge iteration, causing many partial merges that splice
# stale-seq items into fs_root while finalized logs still exist.
#
# The read-xattr-totals ioctl uses a sliding cursor that can return
# pre-merge values (< expected) or duplicate entries when btree data
# changes between batches. To avoid test false positives we've assigned
# a 3-bit window for each mount so that any double counting can
# identify the double counting by overflow in the bit window.
#

t_require_commands setfattr scoutfs perl
t_require_mounts 5

NR_KEYS=2500

echo "== setup"
for nr in $(t_fs_nrs); do
	d=$(eval echo \$T_D$nr)
	for i in $(seq 1 $NR_KEYS); do
		: > "$d/file-${nr}-${i}"
	done
done
sync
t_force_log_merge

sv=$(t_server_nr)

vals=( 4096 512 64 8 1 )
expected=$(( vals[0] + vals[1] + vals[2] + vals[3] + vals[4] ))

n=0
for nr in $(t_fs_nrs); do
	d=$(eval echo \$T_D$nr)
	val=${vals[$n]}
	(( n++ ))
	for i in $(seq 1 $NR_KEYS); do
		setfattr -n "scoutfs.totl.test.${i}.0.0" -v $val \
			"$d/file-${nr}-${i}"
	done
done

sync

last_complete=$(t_counter log_merge_complete $sv)

t_trigger_arm_silent log_merge_force_finalize_ours $sv
t_sync_seq_index
while test "$(t_trigger_get log_merge_force_finalize_ours $sv)" == "1"; do
	sleep .1
done

# Spam the log_merge_force_partial trigger in a tight Perl loop,
# avoiding fork/exec overhead of doing this in a shell "echo" loop.
trigger_paths=""
for i in $(t_fs_nrs); do
	trigger_paths="$trigger_paths $(t_trigger_path $i)/log_merge_force_partial"
done
perl -e '
    my @paths = @ARGV;
    while (1) {
        for my $p (@paths) {
            if (open my $fh, ">", $p) {
                print $fh "1";
                close $fh;
            }
        }
    }
' $trigger_paths &
spam_pid=$!

bad_dir="$T_TMPDIR/bad"
mkdir -p "$bad_dir"

read_totals() {
	local nr=$1
	local mnt=$(eval echo \$T_M$nr)
	while true; do
		echo 1 > $(t_debugfs_path $nr)/drop_weak_item_cache
		# This is probably too elaborate, but, it's pretty neat we can
		# illustrate the double reads this way with some awk magic.
		scoutfs read-xattr-totals -p "$mnt" | \
			awk -F'[ =,]+' -v expect=$expected \
			'or($2+0, expect) != expect {
				v = $2+0; s = ""
				split("0 1 2 3 4", m)
				split("12 9 6 3 0", sh)
				for (i = 1; i <= 5; i++) {
					c = and(rshift(v, sh[i]+0), 7)
					if (c > 1) s = s " m" m[i] ":" c
				}
				printf "%s (%s)\n", $0, substr(s, 2)
			}' >> "$bad_dir/$nr"
	done
}

echo "expected $expected"
reader_pids=""
for nr in $(t_fs_nrs); do
	read_totals $nr &
	reader_pids="$reader_pids $!"
done

while (( $(t_counter log_merge_complete $sv) == last_complete )); do
	sleep .1
done

t_silent_kill $spam_pid $reader_pids

for nr in $(t_fs_nrs); do
	if [ -s "$bad_dir/$nr" ]; then
		echo "double-counted totals on mount $nr:"
		cat "$bad_dir/$nr"
	fi
done

echo "== cleanup"
for nr in $(t_fs_nrs); do
	d=$(eval echo \$T_D$nr)
	find "$d" -maxdepth 1 -name "file-${nr}-*" -delete
done

t_pass
