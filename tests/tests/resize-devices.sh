#
# Some basic tests of online resizing metadata and data devices.
#

t_require_commands bc

statfs_total() {
	local single="total_$1_blocks"
	local mnt="$2"

	scoutfs statfs -s $single -p "$mnt"
}

df_free() {
	local md="$1"
	local mnt="$2"

	scoutfs df -p "$mnt" | awk '($1 == "'$md'") { print $5; exit }'
}

same_totals() {
	cur_meta_tot=$(statfs_total meta "$SCR")
	cur_data_tot=$(statfs_total data "$SCR")

	test "$cur_meta_tot" == "$exp_meta_tot" || \
		t_fail "cur total_meta_blocks $cur_meta_tot != expected $exp_meta_tot"
	test "$cur_data_tot" == "$exp_data_tot" || \
		t_fail "cur total_data_blocks $cur_data_tot != expected $exp_data_tot"
}

#
# make sure that the specified devices have grown by doubling.   The
# total blocks can be tested exactly but the df reported total needs
# some slop to account for reserved blocks and concurrent allocation.
#
devices_grew() {
	cur_meta_tot=$(statfs_total meta "$SCR")
	cur_data_tot=$(statfs_total data "$SCR")
	cur_meta_df=$(df_free MetaData "$SCR")
	cur_data_df=$(df_free Data "$SCR")

	local grow_meta_tot=$(echo "$exp_meta_tot * 2" | bc)
	local grow_data_tot=$(echo "$exp_data_tot * 2" | bc)
	local grow_meta_df=$(echo "($exp_meta_df * 1.95)/1" | bc)
	local grow_data_df=$(echo "($exp_data_df * 1.95)/1" | bc)

	if [ "$1" == "meta" ]; then
		test "$cur_meta_tot" == "$grow_meta_tot" || \
			t_fail "cur total_meta_blocks $cur_meta_tot != grown $grow_meta_tot"
		test "$cur_meta_df" -lt "$grow_meta_df" && \
			t_fail "cur meta df total $cur_meta_df < grown $grow_meta_df"
		exp_meta_tot=$cur_meta_tot
		exp_meta_df=$cur_meta_df
		shift
	fi

	if [ "$1" == "data" ]; then
		test "$cur_data_tot" == "$grow_data_tot" || \
			t_fail "cur total_data_blocks $cur_data_tot != grown $grow_data_tot"
		test "$cur_data_df" -lt "$grow_data_df" && \
			t_fail "cur data df total $cur_data_df < grown $grow_data_df"
		exp_data_tot=$cur_data_tot
		exp_data_df=$cur_data_df
	fi
}

# first calculate small mkfs based on device size
size_meta=$(blockdev --getsize64 "$T_EX_META_DEV")
size_data=$(blockdev --getsize64 "$T_EX_DATA_DEV")
quarter_meta=$(echo "$size_meta / 4" | bc)
quarter_data=$(echo "$size_data / 4" | bc)

# XXX this is all pretty manual, would be nice to have helpers
echo "== make initial small fs"
scoutfs mkfs -A -f -Q 0,127.0.0.1,53000 -m $quarter_meta -d $quarter_data \
	"$T_EX_META_DEV" "$T_EX_DATA_DEV" > $T_TMP.mkfs.out 2>&1 || \
		t_fail "mkfs failed"
SCR="$T_TMPDIR/mnt.scratch"
mkdir -p "$SCR"
mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
	"$T_EX_DATA_DEV" "$SCR"

# then calculate sizes based on blocks that mkfs used
quarter_meta=$(echo "$(statfs_total meta "$SCR") * 64 * 1024" | bc)
quarter_data=$(echo "$(statfs_total data "$SCR") * 4 * 1024" | bc)
whole_meta=$(echo "$quarter_meta * 4" | bc)
whole_data=$(echo "$quarter_data * 4" | bc)
outsize_meta=$(echo "$whole_meta * 2" | bc)
outsize_data=$(echo "$whole_data * 2" | bc)
half_meta=$(echo "$whole_meta / 2" | bc)
half_data=$(echo "$whole_data / 2" | bc)
shrink_meta=$(echo "$quarter_meta / 2" | bc)
shrink_data=$(echo "$quarter_data / 2" | bc)

# and save expected values for checks
exp_meta_tot=$(statfs_total meta "$SCR")
exp_meta_df=$(df_free MetaData "$SCR")
exp_data_tot=$(statfs_total data "$SCR")
exp_data_df=$(df_free Data "$SCR")

echo "== 0s do nothing"
scoutfs resize-devices -p "$SCR" 
scoutfs resize-devices -p "$SCR" -m 0
scoutfs resize-devices -p "$SCR" -d 0
scoutfs resize-devices -p "$SCR" -m 0 -d 0

echo "== shrinking fails"
scoutfs resize-devices -p "$SCR" -m $shrink_meta
scoutfs resize-devices -p "$SCR" -d $shrink_data
scoutfs resize-devices -p "$SCR" -m $shrink_meta -d $shrink_data
same_totals

echo "== existing sizes do nothing"
scoutfs resize-devices -p "$SCR" -m $quarter_meta
scoutfs resize-devices -p "$SCR" -d $quarter_data
scoutfs resize-devices -p "$SCR" -m $quarter_meta -d $quarter_data
same_totals

echo "== growing outside device fails"
scoutfs resize-devices -p "$SCR" -m $outsize_meta
scoutfs resize-devices -p "$SCR" -d $outsize_data
scoutfs resize-devices -p "$SCR" -m $outsize_meta -d $outsize_data
same_totals

echo "== resizing meta works"
scoutfs resize-devices -p "$SCR" -m $half_meta
devices_grew meta

echo "== resizing data works"
scoutfs resize-devices -p "$SCR" -d $half_data
devices_grew data

echo "== shrinking back fails"
scoutfs resize-devices -p "$SCR" -m $quarter_meta
scoutfs resize-devices -p "$SCR" -m $quarter_data
same_totals

echo "== resizing again does nothing"
scoutfs resize-devices -p "$SCR" -m $half_meta
scoutfs resize-devices -p "$SCR" -m $half_data
same_totals

echo "== resizing to full works"
scoutfs resize-devices -p "$SCR" -m $whole_meta -d $whole_data
devices_grew meta data

echo "== cleanup extra fs"
umount "$SCR"
rmdir "$SCR"

t_pass
