
# filter out device ids and mount paths
t_filter_fs()
{
	sed -e 's@mnt/test\.[0-9]*@mnt/test@g' \
	    -e 's@Device: [a-fA-F0-7]*h/[0-9]*d@Device: 0h/0d@g'
}

#
# Filter out expected messages.  Putting messages here implies that
# tests aren't relying on messages to discover failures.. they're
# directly testing the result of whatever it is that's generating the
# message.
#
t_filter_dmesg()
{
	local re

	# the kernel can just be noisy
	re=" used greatest stack depth: "

	# mkfs/mount checks partition tables
	re="$re|unknown partition table"

	# dm swizzling
	re="$re|device doesn't appear to be in the dev hash table"
	re="$re|device-mapper:.*uevent:.*version"
	re="$re|device-mapper:.*ioctl:.*initialised"

	# some tests try invalid devices
	re="$re|scoutfs .* error reading super block"
	re="$re| EXT4-fs (.*): get root inode failed"
	re="$re| EXT4-fs (.*): mount failed"
	re="$re| EXT4-fs (.*): no journal found"
	re="$re| EXT4-fs (.*): VFS: Can't find ext4 filesystem"

	# dropping caches is fine
	re="$re| drop_caches: "

	# mount and unmount spew a bunch
	re="$re|scoutfs.*client connected"
	re="$re|scoutfs.*client disconnected"
	re="$re|scoutfs.*server setting up"
	re="$re|scoutfs.*server ready"
	re="$re|scoutfs.*server accepted"
	re="$re|scoutfs.*server closing"
	re="$re|scoutfs.*server shutting down"
	re="$re|scoutfs.*server stopped"

	# xfstests records test execution in desg
	re="$re| run fstests "

	# tests that drop unmount io triggers fencing
	re="$re|scoutfs .* error: fencing "
	re="$re|scoutfs .*: waiting for .* lock clients"
	re="$re|scoutfs .*: all lock clients recovered"
	re="$re|scoutfs .* error: client rid.*lock recovery timed out"

	# some tests mount w/o options
	re="$re|scoutfs .* error: Required mount option \"metadev_path\" not found"

	egrep -v "($re)" 
}
