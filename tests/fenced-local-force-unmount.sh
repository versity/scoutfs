#!/usr/bin/bash

#
# This fencing script is used for testing clusters of multiple mounts on
# a single host.  It finds mounts to fence by looking for their rids and
# only knows how to "fence" by using forced unmount.
#

echo "$0 running rid '$SCOUTFS_FENCED_REQ_RID' ip '$SCOUTFS_FENCED_REQ_IP' args '$@'"

log() {
	echo "$@" >> /dev/stderr
	exit 1
}

echo_fail() {
	echo "$@" >> /dev/stderr
	exit 1
}

rid="$SCOUTFS_FENCED_REQ_RID"

for fs in /sys/fs/scoutfs/*; do
	[ ! -d "$fs" ] && continue

	fs_rid="$(cat $fs/rid)" || \
		[ ! -d "$fs" ] && continue || \
		echo_fail "failed to get rid in $fs"

	if [ "$fs_rid" != "$rid" ]; then
		continue
	fi

	nr="$(cat $fs/data_device_maj_min)" || \
		[ ! -d "$fs" ] && continue || \
		echo_fail "failed to get data device major:minor in $fs"

	mnts=$(findmnt -l -n -t scoutfs -o TARGET -S $nr) || \
		echo_fail "findmnt -t scoutfs -S $nr failed"
	for mnt in $mnts; do
		umount -f "$mnt" || \
			echo_fail "umout -f $mnt failed"
	done
done

exit 0
