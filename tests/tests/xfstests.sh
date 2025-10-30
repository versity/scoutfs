#
# Run a specific set of tests in xfstests and make sure they pass.  This
# references an external existing xfstests repo.  It points xfstests at
# the first scoutfs mount and its device.
#
# This is a bit odd as a test because it's really running a bunch of
# tests on its own.  We want to see their output as they progress.
# so we restore output to stdout while xfstests is running.  We manually
# generate compared output from the check.log that xfstests procuces
# which lists the tests that were run and their result.
#
# _flakey_drop_and_remount drops writes during unmount, this stops a
# server from indicating that it is done and it will be fenced by the
# next server.. it's right there in the comment: "to simulate a crash".
# our fencing agent would find that the mount isn't actually live
# anymore and would be fine.  For now it just barks out a warning
# in dmesg.
#   

# make sure we have our config
if [ -z "$T_XFSTESTS_REPO" ]; then
	t_fail "xfstests requires -X repo"
fi
if [ -z "$T_XFSTESTS_BRANCH" -a -z "$T_SKIP_CHECKOUT" ]; then
	t_fail "xfstests requires -x branch"
fi

t_quiet mkdir -p "$T_TMPDIR/mnt.scratch"

t_quiet cd "$T_XFSTESTS_REPO"
if [ -z "$T_SKIP_CHECKOUT" ]; then
	t_quiet git fetch
	# if we're passed a tag instead of a branch, we can't --track
	TRACK="--track"
	if git tag -l | grep -q "$T_XFSTESTS_BRANCH" ; then
		TRACK=""
	fi
	# this remote use is bad, do better
	t_quiet git checkout -B "$T_XFSTESTS_BRANCH" ${TRACK} "origin/$T_XFSTESTS_BRANCH"
fi
t_quiet make
t_quiet sync
# pwd stays in xfstests dir to build config and run

#
# Each filesystem needs specific mkfs and mount options because we put
# quorum member addresess in mkfs options and the metadata device in
# mount options.
#
cat << EOF > local.config
export FSTYP=scoutfs
export MKFS_OPTIONS="-f"
export MKFS_TEST_OPTIONS="-Q 0,127.0.0.1,$T_TEST_PORT"
export MKFS_SCRATCH_OPTIONS="-Q 0,127.0.0.1,$T_SCRATCH_PORT"
export MKFS_DEV_OPTIONS="-Q 0,127.0.0.1,$T_DEV_PORT"
export TEST_DEV=$T_DB0
export TEST_DIR=$T_M0
export SCRATCH_META_DEV=$T_EX_META_DEV
export SCRATCH_DEV=$T_EX_DATA_DEV
export SCRATCH_MNT="$T_TMPDIR/mnt.scratch"
export SCOUTFS_SCRATCH_MOUNT_OPTIONS="-o quorum_slot_nr=0,metadev_path=$T_EX_META_DEV"
export MOUNT_OPTIONS="-o quorum_slot_nr=0,metadev_path=$T_MB0"
export TEST_FS_MOUNT_OPTS="-o quorum_slot_nr=0,metadev_path=$T_MB0"
EOF

cat << EOF > local.exclude
generic/003	# missing atime update in buffered read
generic/075	# file content mismatch failures (fds, etc)
generic/103	# enospc causes trans commit failures
generic/108	# mount fails on failing device?
generic/112	# file content mismatch failures (fds, etc)
generic/213	# enospc causes trans commit failures
generic/318	# can't support user namespaces until v5.11
generic/321	# requires selinux enabled for '+' in ls?
generic/338	# BUG_ON update inode error handling
generic/347	# _dmthin_mount doesn't work?
generic/356	# swap
generic/357	# swap
generic/409	# bind mounts not scripted yet
generic/410	# bind mounts not scripted yet
generic/411	# bind mounts not scripted yet
generic/423	# symlink inode size is strlen() + 1 on scoutfs
generic/430	# xfs_io copy_range missing in el7
generic/431	# xfs_io copy_range missing in el7
generic/432	# xfs_io copy_range missing in el7
generic/433	# xfs_io copy_range missing in el7
generic/434	# xfs_io copy_range missing in el7
generic/441	# dm-mapper
generic/444	# el9's posix_acl_update_mode is buggy ?
generic/467	# open_by_handle ESTALE
generic/472	# swap
generic/484	# dm-mapper
generic/493	# swap
generic/494	# swap
generic/495	# swap
generic/496	# swap
generic/497	# swap
generic/532	# xfs_io statx attrib_mask missing in el7
generic/554	# swap
generic/563	# cgroup+loopdev
generic/564	# xfs_io copy_range missing in el7
generic/565	# xfs_io copy_range missing in el7
generic/568	# falloc not resulting in block count increase
generic/569	# swap
generic/570	# swap
generic/620	# dm-hugedisk
generic/633	# id-mapped mounts missing in el7
generic/636	# swap
generic/641	# swap
generic/643	# swap
EOF

t_restore_output
echo "  (showing output of xfstests)"

args="-E local.exclude ${T_XFSTESTS_ARGS:--g quick}"
./check $args
# the fs is unmounted when check finishes

#
# ./check writes the results of the run to check.log.  It lists
# the tests it ran, skipped, or failed.  Then it writes a line saying
# everything passed or some failed.  We scrape the most recent run and
# use it as the output to compare to make sure that we run the right
# tests and get the right results.
#
awk '
	/^(Ran|Not run|Failures):.*/ {
		if (pf) {
			res=""
			pf=""
		} res = res "\n" $0
	}
	/^(Passed|Failed).*tests$/ {
		pf=$0
	}
	END {
		print res "\n" pf
	}' < results/check.log  > "$T_TMPDIR/results"

# put a test per line so diff shows tests that differ
egrep "^(Ran|Not run|Failures):" "$T_TMPDIR/results" | \
	fmt -w 1 > "$T_TMPDIR/results.fmt"
egrep "^(Passed|Failed).*tests$" "$T_TMPDIR/results" >> "$T_TMPDIR/results.fmt"

t_compare_output cat "$T_TMPDIR/results.fmt"

t_pass
