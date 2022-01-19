#!/usr/bin/bash

echo_fail() {
	echo "$@" > /dev/stderr
	exit 1
}

rid="$SCOUTFS_FENCED_REQ_RID"

#
# Look for a local mount with the rid to fence.  Typically we'll at
# least find the mount with the server that requested the fence that
# we're processing.   But it's possible that mounts are unmounted
# before, or while, we're running.
#
mnts=$(findmnt -l -n -t scoutfs -o TARGET) || \
	echo_fail "findmnt -t scoutfs failed" > /dev/stderr

for mnt in $mnts; do
	mnt_rid=$(scoutfs statfs -p "$mnt" -s rid) || \
		echo_fail "scoutfs statfs $mnt failed"

	if [ "$mnt_rid" == "$rid" ]; then
		umount -f "$mnt" || \
			echo_fail "umout -f $mnt"

		exit 0
	fi
done

#
# If the mount doesn't exist on this host then it can't access the
# devices by definition and can be considered fenced.
#
exit 0