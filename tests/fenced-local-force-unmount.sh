#!/usr/bin/bash

#
# This fencing script is used for testing clusters of multiple mounts on
# a single host.  It finds mounts to fence by looking for their rids and
# only knows how to "fence" by using forced unmount.
#

echo "$0 running rid '$SCOUTFS_FENCED_REQ_RID' ip '$SCOUTFS_FENCED_REQ_IP' args '$@'"

echo_fail() {
	echo "$@" >> /dev/stderr
	exit 1
}

# silence error messages
quiet_cat()
{
	cat "$@" 2>/dev/null
}

rid="$SCOUTFS_FENCED_REQ_RID"

shopt -s nullglob
for fs in /sys/fs/scoutfs/*; do
	fs_rid="$(quiet_cat $fs/rid)"
	nr="$(quiet_cat $fs/data_device_maj_min)"
	[ ! -d "$fs" -o "$fs_rid" != "$rid" ] && continue

	mnt=$(findmnt -l -n -t scoutfs -o TARGET -S $nr) || \
		echo_fail "findmnt -t scoutfs -S $nr failed"
	[ -z "$mnt" ] && continue

	if ! umount -qf "$mnt"; then
		if [ -d "$fs" ]; then
			echo_fail "umount -qf $mnt failed"
		fi
	fi
done

exit 0
