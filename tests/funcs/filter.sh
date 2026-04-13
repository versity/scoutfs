
# filter out device ids and mount paths
t_filter_fs()
{
	sed -e 's@mnt/test\.[0-9]*@mnt/test@g' \
	    -e 's@Device: [a-fA-F0-9]*h/[0-9]*d@Device: 0h/0d@g'
}

#
# We can hit a spurious kasan warning that was fixed upstream:
#
#  e504e74cc3a2 x86/unwind/orc: Disable KASAN checking in the ORC unwinder, part 2
#
# KASAN can get mad when the unwinder doesn't find ORC metadata and
# wanders up without using frames and hits the KASAN stack red zones.
# We can ignore these messages.
#
# They're bracketed by:
# [ 2687.690127] ==================================================================
# [ 2687.691366] BUG: KASAN: stack-out-of-bounds in get_reg+0x1bc/0x230
# ...
# [ 2687.706220] ==================================================================
#
ignore_harmless_unwind_kasan_stack_oob()
{
awk '
        BEGIN {
                in_soob = 0
                soob_nr = 0
        }
        ( !in_soob && $0 ~ /==================================================================/ ) {
                in_soob = 1
                soob_nr = NR
                saved = $0
        }
        ( in_soob == 1 && NR == (soob_nr + 1) ) {
                if (match($0, /KASAN: stack-out-of-bounds in get_reg/) != 0) {
                        in_soob = 2
                } else {
                        in_soob = 0
                        print saved
                }
		saved=""
        }
        ( in_soob == 2 && $0 ~ /==================================================================/ ) {
                in_soob = 0
        }
        ( !in_soob ) { print $0 }
        END {
                if (saved) {
                        print saved
                }
        }
'
}

#
# in el97+, XFS can generate a spurious lockdep circular dependency
# warning about reclaim. Fixed upstream in e.g. v5.7-rc4-129-g6dcde60efd94
#
ignore_harmless_xfs_lockdep_warning()
{
awk '
	BEGIN {
		in_block = 0
		block_nr = 0
		buf = ""
	}
	( !in_block && $0 ~ /======================================================/ ) {
		in_block = 1
		block_nr = NR
		buf = $0 "\n"
		next
	}
	( in_block == 1 && NR == (block_nr + 1) ) {
		if (match($0, /WARNING: possible circular locking dependency detected/) != 0) {
			in_block = 2
			buf = buf $0 "\n"
		} else {
			in_block = 0
			printf "%s", buf
			print $0
			buf = ""
		}
		next
	}
	( in_block == 2 ) {
		buf = buf $0 "\n"
		if ($0 ~ /<\/TASK>/) {
			if (buf ~ /xfs_(nondir_|dir_)?ilock_class/ && buf ~ /fs_reclaim/) {
				# known xfs lockdep false positive, discard
			} else {
				printf "%s", buf
			}
			in_block = 0
			buf = ""
		}
		next
	}
	{ print $0 }
	END {
		if (buf) {
			printf "%s", buf
		}
	}
'
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
	re="$re|sched: RT throttling activated"

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
	re="$re|scoutfs.*server starting"
	re="$re|scoutfs.*server ready"
	re="$re|scoutfs.*server accepted"
	re="$re|scoutfs.*server closing"
	re="$re|scoutfs.*server shutting down"
	re="$re|scoutfs.*server stopped"

	# xfstests records test execution in desg
	re="$re| run fstests "

	# tests that drop unmount io triggers fencing
	re="$re|scoutfs .* error: fencing "
	re="$re|scoutfs .*: waiting for .* clients"
	re="$re|scoutfs .*: all clients recovered"
	re="$re|scoutfs .* error: client rid.*lock recovery timed out"

	# we test bad devices and options
	re="$re|scoutfs .* error: Required mount option \"metadev_path\" not found"
	re="$re|scoutfs .* error: meta_super META flag not set"
	re="$re|scoutfs .* error: could not open metadev:.*"
	re="$re|scoutfs .* error: Unknown or malformed option,.*"
	re="$re|scoutfs .* error: invalid quorum_heartbeat_timeout_ms value"

	# in debugging kernels we can slow things down a bit
	re="$re|hrtimer: interrupt took .*"
	re="$re|clocksource: Long readout interval"

	# orphan log trees reclaim is handled, not an error
	re="$re|scoutfs .* reclaiming orphan log trees"

	# fencing tests force unmounts and trigger timeouts
	re="$re|scoutfs .* forcing unmount"
	re="$re|scoutfs .* reconnect timed out"
	re="$re|scoutfs .* recovery timeout expired"
	re="$re|scoutfs .* fencing previous leader"
	re="$re|scoutfs .* reclaimed resources"
	re="$re|scoutfs .* quorum .* error"
	re="$re|scoutfs .* error reading quorum block"
	re="$re|scoutfs .* error .* writing quorum block"
	re="$re|scoutfs .* error .* while checking to delete inode"
	re="$re|scoutfs .* error .*writing btree blocks.*"
	re="$re|scoutfs .* error .*writing super block.*"
	re="$re|scoutfs .* error .* freeing merged btree blocks.*.looping commit del.*upd freeing item"
	re="$re|scoutfs .* error .* freeing merged btree blocks.*.final commit del.upd freeing item"
	re="$re|scoutfs .* error .*reading quorum block.*to update event.*"
	re="$re|scoutfs .* error.*server failed to bind to.*"
	re="$re|scoutfs .* critical transaction commit failure.*"

	# ENOLINK (-67) indicates an expected forced unmount error
	re="$re|scoutfs .* error -67 .*"

	# change-devices causes loop device resizing
	re="$re|loop: module loaded"
	re="$re|loop[0-9].* detected capacity change from.*"
	re="$re|dm-[0-9].* detected capacity change from.*"

	# ignore systemd-journal rotating
	re="$re|systemd-journald.*"

	# process accounting can be noisy
	re="$re|Process accounting resumed.*"

	# format vers back/compat tries bad mounts
	re="$re|scoutfs .* error.*outside of supported version.*"
	re="$re|scoutfs .* error.*could not get .*super.*"

	# ignore "unsafe core pattern" when xfstests tries to disable cores"
	re="$re|Unsafe core_pattern used with fs.suid_dumpable=2.*"
	re="$re|Pipe handler or fully qualified core dump path required.*"
	re="$re|Set kernel.core_pattern before fs.suid_dumpable.*"

	# perf warning that it adjusted sample rate
	re="$re|perf: interrupt took too long.*lowering kernel.perf_event_max_sample_rate.*"

	# some ci test guests are unresponsive
	re="$re|longest quorum heartbeat .* delay"

	# creating block devices may trigger this
	re="$re|block device autoloading is deprecated and will be removed."

	# lockdep or kasan warnings can cause this
	re="$re|Disabling lock debugging due to kernel taint"

	egrep -v "($re)" | \
		ignore_harmless_unwind_kasan_stack_oob | \
		ignore_harmless_xfs_lockdep_warning
}
