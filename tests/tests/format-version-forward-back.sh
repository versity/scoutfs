#
# Test our basic ability to work with different format versions.
#
# The current code being tested has a range of supported format
# versions.   For each of the older supported format versions we have a
# git hash of the commit before the next greater version was introduced.
# We build versions of the scoutfs utility and kernel module for the
# last commit in tree that had a lesser supported version as its max
# supported version.   We use those binaries to test forward and back
# compat as new and old code works with a persistent volume with a given
# format version.
#

# not supported on el8 or higher
if [ $(source /etc/os-release ; echo ${VERSION_ID:0:1}) -gt 7 ]; then
	t_skip_permitted "Unsupported OS version"
fi

mount_has_format_version()
{
	local mnt="$1"
	local vers="$2"
	local sysfs_fmt_vers="$(t_sysfs_path_from_mnt $SCR)/format_version"

	test "$(cat $sysfs_fmt_vers)" == "$vers"
}

SCR="/mnt/scoutfs.scratch"

MIN=$(modinfo $T_MODULE | awk '($1 == "scoutfs_format_version_min:"){print $2}')
MAX=$(modinfo $T_MODULE | awk '($1 == "scoutfs_format_version_max:"){print $2}')

echo "min: $MIN max: $MAX" > "$T_TMP.log"

test "$MIN" -gt 0 -a "$MAX" -gt 0 -a "$MIN" -le "$MAX" || \
	t_fail "parsed bad versions, min: $MIN max: $MAX"

test "$MIN" == "$MAX" && \
	t_skip "only one supported format version: $MIN"

# prepare dir and wipe any weird old partial state
builds="$T_RESULTS/format_version_builds"
mkdir -p "$builds"

echo "== ensuring utils and module for old versions"
declare -A commits
commits[1]=c3c4b080
for vers in $(seq $MIN $((MAX - 1))); do
	dir="$builds/$vers"
	platform=$(uname -rp)
	buildmark="$dir/buildmark"
	commit="${commits[$vers]}"

	test -n "$commit" || \
		t_fail "no commit for vers $vers"

	# have our files for this version
	test "$(cat $buildmark 2>&1)" == "$platform" && \
		continue

	# build as one big sequence of commands that can return failure
	(
		set -o pipefail

		rm -rf $dir							&&
		mkdir -p $dir/building						&&
		cd "$T_TESTS/.."						&&
		git archive --format=tar "$commit" | tar -C "$dir/building" -xf - &&
		cd -								&&
		find $dir							&&
		make -C "$dir/building"						&&
		mv $dir/building/utils/src/scoutfs $dir				&&
		mv $dir/building/kmod/src/scoutfs.ko $dir			&&
		rm -rf $dir/building						&&
		echo "$platform" > $buildmark					&&
		find $dir							&&
		cat $buildmark
	) >> "$T_TMP.log" 2>&1 || t_fail "version $vers build failed"
done

echo "== unmounting test fs and removing test module"
t_quiet t_umount_all
t_quiet rmmod scoutfs

echo "== testing combinations of old and new format versions"
mkdir -p "$SCR"
for vers in $(seq $MIN $((MAX - 1))); do
	old_scoutfs="$builds/$vers/scoutfs"
	old_module="$builds/$vers/scoutfs.ko"

	echo "mkfs $vers" >> "$T_TMP.log"
	t_quiet $old_scoutfs mkfs -f -Q 0,127.0.0.1,$T_SCRATCH_PORT "$T_EX_META_DEV" "$T_EX_DATA_DEV" \
		|| t_fail "mkfs $vers failed"

	echo "mount $vers with $vers" >> "$T_TMP.log"
	t_quiet insmod $old_module
	t_quiet mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
		"$T_EX_DATA_DEV" "$SCR"
	t_quiet mount_has_format_version "$SCR" "$vers"

	echo "creating files in $vers" >> "$T_TMP.log"
	t_quiet touch "$SCR/file-"{1,2,3}
	stat "$SCR"/file-* > "$T_TMP.stat" || \
		t_fail "stat in $vers failed"

	echo "remounting $vers fs with $MAX" >> "$T_TMP.log"
	t_quiet umount "$SCR"
	rmmod scoutfs
	insmod "$T_MODULE"
	t_quiet mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
		"$T_EX_DATA_DEV" "$SCR"
	t_quiet mount_has_format_version "$SCR" "$vers"

	echo "verifying stat in $vers with $MAX" >> "$T_TMP.log"
	diff -u "$T_TMP.stat" <(stat "$SCR"/file-*)

	echo "keep/update/del existing, create new in $vers" >> "$T_TMP.log"
	t_quiet touch "$SCR/file-2"
	t_quiet rm -f "$SCR/file-3"
	t_quiet touch "$SCR/file-4"
	stat "$SCR"/file-* > "$T_TMP.stat" || \
		t_fail "stat in $vers failed"

	echo "remounting $vers fs with $vers" >> "$T_TMP.log"
	t_quiet umount "$SCR"
	rmmod scoutfs
	insmod "$old_module"
	t_quiet mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
		"$T_EX_DATA_DEV" "$SCR"
	t_quiet mount_has_format_version "$SCR" "$vers"

	echo "verifying stat in $vers with $vers" >> "$T_TMP.log"
	diff -u "$T_TMP.stat" <(stat "$SCR"/file-*)

	echo "changing format vers to $MAX" >> "$T_TMP.log"
	t_quiet umount "$SCR"
	rmmod scoutfs
	t_quiet scoutfs change-format-version -F -V $MAX $T_EX_META_DEV "$T_EX_DATA_DEV"

	echo "mount fs $MAX with old $vers should fail" >> "$T_TMP.log"
	insmod "$old_module"
	mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
		"$T_EX_DATA_DEV" "$SCR" >> "$T_TMP.log" 2>&1
	if [ "$?" == "0" ]; then
		umount "$SCR"
		t_fail "old code ver $vers able to mount new ver $MAX"
	fi

	echo "remounting $MAX fs with $MAX" >> "$T_TMP.log"
	rmmod scoutfs
	insmod "$T_MODULE"
	t_quiet mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
		"$T_EX_DATA_DEV" "$SCR"
	t_quiet mount_has_format_version "$SCR" "$MAX"

	echo "verifying stat in $MAX with $MAX" >> "$T_TMP.log"
	diff -u "$T_TMP.stat" <(stat "$SCR"/file-*)

	echo "keep/update/del existing, create new in $MAX" >> "$T_TMP.log"
	t_quiet touch "$SCR/file-2"
	t_quiet rm -f "$SCR/file-4"
	t_quiet touch "$SCR/file-5"
	stat "$SCR"/file-* > "$T_TMP.stat" || \
		t_fail "stat in $MAX failed"

	echo "remounting $MAX fs with $MAX again" >> "$T_TMP.log"
	t_quiet umount "$SCR"
	t_quiet mount -t scoutfs -o metadev_path=$T_EX_META_DEV,quorum_slot_nr=0 \
		"$T_EX_DATA_DEV" "$SCR"
	t_quiet mount_has_format_version "$SCR" "$MAX"

	echo "verifying stat in $MAX with $MAX again" >> "$T_TMP.log"
	diff -u "$T_TMP.stat" <(stat "$SCR"/file-*)

	echo "done with old vers $vers" >> "$T_TMP.log"
	t_quiet umount "$SCR"
	rmmod scoutfs
done

echo "== restoring test module and mount"
insmod "$T_MODULE"
t_mount_all

t_pass
