#!/usr/bin/bash

#
# XXX
#  - could have helper functions for waiting for pids
#  - *always* be gathering traces?  just slow ones?
#  - would be nice to show running resource consumption
#  - sample quorum from super instead of option (wrong w/o -m mkfs)
#  - tracing options are not great, should be smarter
#

msg() {
	echo "[== $@ ==]"
}

die() {
	msg "$@, exiting"
	exit 1
}

# output a message with a timestamp to the run.log
log()
{
	echo "[$(date '+%F %T.%N')] $*" >> "$T_RESULTS/run.log"
}

# run a logged command, exiting if it fails
cmd() {
	log "$*"
	"$@" >> "$T_RESULTS/run.log" 2>&1 || \
		die "cmd failed (check the run.log)"
}

show_help()
{
cat << EOF
$(basename $0) options:
    -a        | Abort after the first test failure, leave fs mounted.
    -d <file> | Specify the storage device path that contains the
              | file system to be tested.  Will be clobbered by -m mkfs.
    -D        | Dump accumulated ftrace buffer to the console on oops.
    -E <re>   | Exclude tests whose file name matches the regular expression.
              | Can be provided multiple times
    -e <file> | Specify an extra storage device for testing.  Will be clobbered.
    -I <re>   | Include tests whose file name matches the regular expression.
              | By default all tests are run.  If this is provided then
              | only tests matching will be run.  Can be provided multiple
              | times
    -i        | Force removing and inserting the built scoutfs.ko module.
    -K        | scouts-kmod-dev git repo. Used to build kernel module.
    -k        | Branch to checkout in scoutfs-kmod-dev repo.
    -m        | Run mkfs on the device before mounting and running
              | tests.  Implies unmounting existing mounts first.
    -n        | The number of devices and mounts to test.
    -p        | Exit script after preparing mounts only, don't run tests.
    -P        | Output trace events with printk as they're generated.
    -q <nr>   | Specify the quorum count needed to mount.  This is 
              | used when running mkfs and is needed by a few tests.
    -r <dir>  | Specify the directory in which to store results of
              | test runs.  The directory will be created if it doesn't
              | exist.  Previous results will be deleted as each test runs.
    -s        | Skip git repo checkouts.
    -t        | Enabled trace events that match the given glob argument.
    -U        | scouts-utils-dev git repo. Used to build kernel module.
    -u        | Branch to checkout in scoutfs-utils-dev repo.
    -X        | xfstests git repo. Used by tests/xfstests.sh.
    -x        | xfstests git branch to checkout and track.
    -y        | xfstests ./check additional args
EOF
}

# unset all the T_ variables
for v in ${!T_*}; do
	eval unset $v
done

# set some T_ defaults
T_TRACE_DUMP="0"
T_TRACE_PRINTK="0"

while true; do
	case $1 in
	-a)
		T_ABORT="1"
		;;
	-d)
		test -n "$2" || die "-d must have device file argument"
		T_DEVICE="$2"
		shift
		;;
	-D)
		T_TRACE_DUMP="1"
		;;
	-E)
		test -n "$2" || die "-E must have test exclusion regex argument"
		T_EXCLUDE+="-e '$2' "
		shift
		;;
	-e)
		test -n "$2" || die "-e must have extra device file argument"
		T_EXDEV="$2"
		shift
		;;
	-I)
		test -n "$2" || die "-I must have test incusion regex argument"
		T_INCLUDE+="-e '$2' "
		shift
		;;
	-i)
		T_INSMOD="1"
		;;
	-K)
		test -n "$2" || die "-K must have kmod git repo dir argument"
		T_KMOD_REPO="$2"
		shift
		;;
	-k)
		test -n "$2" || die "-k must have kmod git branch argument"
		T_KMOD_BRANCH="$2"
		shift
		;;
	-m)
		T_MKFS="1"
		;;
	-n)
		test -n "$2" || die "-n must have nr mounts argument"
		T_NR_MOUNTS="$2"
		shift
		;;
	-p)
		T_PREPARE="1"
		;;
	-P)
		T_TRACE_PRINTK="1"
		;;
	-q)
		test -n "$2" || die "-q must have quorum count argument"
		T_QUORUM="$2"
		shift
		;;
	-r)
		test -n "$2" || die "-r must have results dir argument"
		T_RESULTS="$2"
		shift
		;;
	-s)
	        T_SKIP_CHECKOUT="1"
		;;
	-t)
		test -n "$2" || die "-t must have trace glob argument"
		T_TRACE_GLOB="$2"
		shift
		;;
	-U)
		test -n "$2" || die "-U must have utils git repo dir argument"
		T_UTILS_REPO="$2"
		shift
		;;
	-u)
		test -n "$2" || die "-u must have utils git branch argument"
		T_UTILS_BRANCH="$2"
		shift
		;;
	-X)
		test -n "$2" || die "-X requires xfstests git repo dir argument"
		T_XFSTESTS_REPO="$2"
		shift
		;;
	-x)
		test -n "$2" || die "-x requires xfstests git branch argument"
		T_XFSTESTS_BRANCH="$2"
		shift
		;;
	-y)
		test -n "$2" || die "-x requires xfstests ./check args argument"
		T_XFSTESTS_ARGS="$2"
		shift
		;;
	-h|-\?|--help)
		show_help
		exit 1
		;;
	--)	
		break
		;;
	-?*)
		printf 'WARN: Unknown option: %s\n' "$1" >&2
		show_help
		exit 1
		;;
	*)
		break
		;;
	esac

	shift
done

test -n "$T_DEVICE" || die "must specify -d fs device"
test -e "$T_DEVICE" || die "fs device -d '$T_DEVICE' doesn't exist"
test -n "$T_EXDEV" || die "must specify -e extra device"
test -e "$T_EXDEV" || die "fs device -d '$T_EXDEV' doesn't exist"
test -n "$T_KMOD_REPO" || die "must specify -K kmod repo dir"
test -n "$T_KMOD_BRANCH" -a -z "T_SKIP_CHECKOUT" && \
        die "must specify -k kmod branch"
test -n "$T_MKFS" -a -z "$T_QUORUM" && die "mkfs (-m) requires quorum (-q)"
test -n "$T_RESULTS" || die "must specify -r results dir"
test -n "$T_UTILS_REPO" || die "must specify -U utils repo dir"
test -n "$T_UTILS_BRANCH" -a -z "T_SKIP_CHECKOUT" &&
        die "must specify -u utils branch"
test -n "$T_XFSTESTS_REPO" -a -z "$T_XFSTESTS_BRANCH" -a -z "T_SKIP_CHECKOUT" && \
	die "-X xfstests repo requires -x xfstests branch"
test -n "$T_XFSTESTS_BRANCH" -a -z "$T_XFSTESTS_REPO" -a -z "T_SKIP_CHECKOUT" && \
	die "-X xfstests branch requires -x xfstests repo"

test -n "$T_NR_MOUNTS" || die "must specify -n nr mounts"
test "$T_NR_MOUNTS" -ge 1 -a "$T_NR_MOUNTS" -le 8 || \
	 die "-n nr mounts must be >= 1 and <= 8"

# canonicalize paths
for e in T_DEVICE T_EXDEV T_KMOD_REPO T_RESULTS T_UTILS_REPO T_XFSTESTS_REPO; do
	eval $e=\"$(readlink -f "${!e}")\"
done

# include everything by default
test -z "$T_INCLUDE" && T_INCLUDE="-e '.*'"
# (quickly) exclude nothing by default
test -z "$T_EXCLUDE" && T_EXCLUDE="-e '\Zx'"

# eval to strip re ticks but not expand
tests=$(grep -v "^#" sequence |
	eval grep "$T_INCLUDE" | eval grep -v "$T_EXCLUDE")
test -z "$tests" && \
	die "no tests found by including $T_INCLUDE and excluding $T_EXCLUDE"

# create results dir 
test -e "$T_RESULTS" || mkdir -p "$T_RESULTS"
test -d "$T_RESULTS" || \
	 die "$T_RESULTS dir is not a directory"

# checkout and build kernel module
if [ -n "$T_KMOD_REPO" ]; then
	msg "building kmod repo $T_KMOD_REPO branch $T_KMOD_BRANCH"
	cmd cd "$T_KMOD_REPO"

	if [ -n "$T_KMOD_BRANCH" ]; then
	    cmd git fetch
	    cmd git rev-parse --verify "origin/$T_KMOD_BRANCH"
	    cmd git checkout -B "$T_KMOD_BRANCH" --track origin/$T_KMOD_BRANCH
	    cmd git pull --rebase
	fi
	cmd make
	cmd sync
	cmd cd -

	kmod="$T_KMOD_REPO/src/scoutfs.ko"
fi

# checkout and build utils
if [ -n "$T_UTILS_REPO" ]; then
	msg "building utils repo $T_UTILS_REPO branch $T_UTILS_BRANCH"
	cmd cd "$T_UTILS_REPO"

	if [ -n "$T_UTILS_BRANCH" ]; then
	    cmd git fetch
	    cmd git rev-parse --verify "origin/$T_UTILS_BRANCH"
	    cmd git checkout -B "$T_UTILS_BRANCH" --track origin/$T_UTILS_BRANCH
	    cmd git pull --rebase
	    # might need git clean to remove stale src/*.o after update
	fi
	cmd make
	cmd sync
	cmd cd -

	# we can now run the built scoutfs binary, prefer over installed
	PATH="$T_UTILS_REPO/src:$PATH"
fi

# verify xfstests branch
if [ -n "$T_XFSTESTS_REPO" ] && [ -z "T_SKIP_CHECKOUT" ]; then
	msg "verifying xfstests repo $T_XFSTESTS_REPO branch $T_XFSTESTS_BRANCH"
	cmd cd "$T_XFSTESTS_REPO"
	cmd git rev-parse --verify "$T_XFSTESTS_BRANCH"
	cmd cd -
fi

# building our test binaries
msg "building test binaries"
cmd make

# set any options implied by others 
test -n "$T_MKFS" && T_UNMOUNT=1
test -n "$T_INSMOD" && T_UNMOUNT=1

#
# unmount concurrently because the final quorum can only unmount once
# they're all unmounting.  We unmount all mounts because we might be
# removing the module.
#
unmount_all() {
	msg "unmounting all scoutfs mounts"
	pids=""
	for m in $(findmnt -t scoutfs -o TARGET); do
		if [ -d "$m" ]; then
			cmd umount "$m" &
			p="$!"
			pids="$pids $!"
		fi
	done
	for p in $pids; do
		cmd wait $p
	done

	# delete all temp devices
	for dev in $(losetup --associated "$T_DEVICE" | cut -d : -f 1); do
		if [ -e "$dev" ]; then
			cmd losetup -d "$dev"
		fi
	done
}
if [ -n "$T_UNMOUNT" ]; then
	unmount_all
fi

if [ -n "$T_MKFS" ]; then
	cmd scoutfs mkfs -Q "$T_QUORUM" "$T_DEVICE"
fi

if [ -n "$T_INSMOD" ]; then
	msg "removing and reinserting scoutfs module"
	test -e /sys/module/scoutfs && cmd rmmod scoutfs
	cmd modprobe libcrc32c
	cmd insmod "$T_KMOD_REPO/src/scoutfs.ko"
fi

if [ -n "$T_TRACE_GLOB" ]; then
	msg "enabling trace events"
	echo 0 > /sys/kernel/debug/tracing/events/scoutfs/enable
	for g in $T_TRACE_GLOB; do
		for e in /sys/kernel/debug/tracing/events/scoutfs/$g/enable; do
			echo 1 > $e
		done
	done

	echo "$T_TRACE_DUMP" > /proc/sys/kernel/ftrace_dump_on_oops
	echo "$T_TRACE_PRINTK" > /sys/kernel/debug/tracing/options/trace_printk

	cmd cat /sys/kernel/debug/tracing/set_event
	cmd grep .  /sys/kernel/debug/tracing/options/trace_printk \
		    /proc/sys/kernel/ftrace_dump_on_oops
fi

#
# mount concurrently so that a quorum is present to elect the leader and
# start a server.
#
msg "mounting $T_NR_MOUNTS mounts on $T_DEVICE"
pids=""
for i in $(seq 0 $((T_NR_MOUNTS - 1))); do
	opts="-o server_addr=127.0.0.1"

	dev=$(losetup --find --show $T_DEVICE)
	test -b "$dev" || die "failed to create temp device $dev"

	dir="/mnt/test.$i"
	test -d "$dir" || cmd mkdir -p "$dir"

	msg "mounting $dev on $dir"
	cmd mount -t scoutfs $opts "$dev" "$dir" &
	p="$!"
	pids="$pids $!"
	log "background mount $i pid $p"

	eval T_O$i=\"$opts\"
	T_O[$i]="$opts"
	T_OS+="$opts "

	eval T_B$i=$dev
	T_B[$i]=$dev
	T_BS+="$dev "

	eval T_M$i=\"$dir\"
	T_M[$i]=$dir
	T_MS+="$dir "

done
for p in $pids; do
	log "waiting for background mount pid $p"
	cmd wait $p
done

if [ -n "$T_PREPARE" ]; then
	findmnt -t scoutfs
	msg "-p given, exiting after preparing mounts"
	exit 0
fi

# we need the STATUS definitions and filters
. funcs/exec.sh
. funcs/filter.sh

# give tests access to built binaries in src/, prefer over installed
PATH="$PWD/src:$PATH"

msg "running tests"
> "$T_RESULTS/skip.log"
> "$T_RESULTS/fail.log"

passed=0
skipped=0
failed=0
for t in $tests; do
	# tests has basenames from sequence, get path and name
	t="tests/$t"
	test_name=$(basename "$t" | sed -e 's/.sh$//')

	# create a temporary dir and file path for the test
	T_TMPDIR="$T_RESULTS/tmp/$test_name"
	T_TMP="$T_TMPDIR/tmp"
	cmd rm -rf "$T_TMPDIR"
	cmd mkdir -p "$T_TMPDIR"

	# create a test name dir in the fs
	T_DS=""
	for i in $(seq 0 $((T_NR_MOUNTS - 1))); do
		dir="${T_M[$i]}/test/$test_name"

		test $i == 0 && cmd mkdir -p "$dir"

		eval T_D$i=$dir
		T_D[$i]=$dir
		T_DS+="$dir "
	done

	# export all our T_ variables
	for v in ${!T_*}; do
		eval export $v
	done
	export PATH # give test access to scoutfs binary

	# prepare to compare output to golden output
	test -e "$T_RESULTS/output" || cmd mkdir -p "$T_RESULTS/output"
	out="$T_RESULTS/output/$test_name"
	> "$T_TMPDIR/status.msg"
	golden="golden/$test_name"

	# get stats from previous pass
	last="$T_RESULTS/last-passed-test-stats"
	stats=$(grep -s "^$test_name" "$last" | cut -d " " -f 2-)
	test -n "$stats" && stats="last: $stats"

	printf "  %-30s $stats" "$test_name"

	# record dmesg before
	dmesg | t_filter_dmesg > "$T_TMPDIR/dmesg.before"

	# give tests stdout and compared output on specific fds
	exec 6>&1
	exec 7>$out

	# run the test with access to our functions
	start_secs=$SECONDS
	bash -c "for f in funcs/*.sh; do . \$f; done; . $t" >&7 2>&1
	sts="$?"
	log "test $t exited with status $sts"
	stats="$((SECONDS - start_secs))s"

	# close our weird descriptors
	exec 6>&-
	exec 7>&-

	# compare output if the test returned passed status
	if [ "$sts" == "$T_PASS_STATUS" ]; then
		if [ ! -e "$golden" ]; then
			message="no golden output"
			sts=$T_FAIL_STATUS
		elif ! cmp -s "$golden" "$out"; then 
			message="output differs"
			sts=$T_FAIL_STATUS
			diff -u "$golden" "$out" >> "$T_RESULTS/fail.log"
		fi
	else
		# get message from t_*() functions
		message=$(cat "$T_TMPDIR/status.msg")
	fi

	# see if anything unexpected was added to dmesg
	if [ "$sts" == "$T_PASS_STATUS" ]; then
		dmesg | t_filter_dmesg > "$T_TMPDIR/dmesg.after"
		diff --old-line-format="" --unchanged-line-format="" \
			"$T_TMPDIR/dmesg.before" "$T_TMPDIR/dmesg.after" > \
			"$T_TMPDIR/dmesg.new"

		if [ -s "$T_TMPDIR/dmesg.new" ]; then
			message="unexpected messages in dmesg"
			sts=$T_FAIL_STATUS
			cat "$T_TMPDIR/dmesg.new" >> "$T_RESULTS/fail.log"
		fi
	fi

	# record unknown exit status
	if [ "$sts" -lt "$T_FIRST_STATUS" -o "$sts" -gt "$T_LAST_STATUS" ]; then
		message="unknown status: $sts"
		sts=$T_FAIL_STATUS
	fi

	# show and record the result of the test
	if [ "$sts" == "$T_PASS_STATUS" ]; then
		echo "  passed: $stats"
		((passed++))
		# save stats for passed test
		grep -s -v "^$test_name" "$last" > "$last.tmp"
		echo "$test_name $stats" >> "$last.tmp"
		mv -f "$last.tmp" "$last"
	elif [ "$sts" == "$T_SKIP_STATUS" ]; then
		echo "  [ skipped: $message ]"
		echo "$test_name $message" >> "$T_RESULTS/skip.log"
		((skipped++))
	elif [ "$sts" == "$T_FAIL_STATUS" ]; then
		echo "  [ failed: $message ]"
		echo "$test_name $message" >> "$T_RESULTS/fail.log"
		((failed++))

		test -n "$T_ABORT" && die "aborting after first failure"
	fi
done

msg "all tests run: $passed passed, $skipped skipped, $failed failed"

unmount_all

if [ -n "$T_TRACE_GLOB" ]; then
	msg "saving traces and disabling tracing"
	echo 0 > /sys/kernel/debug/tracing/events/scoutfs/enable
	cat /sys/kernel/debug/tracing/trace > "$T_RESULTS/traces"
fi

if [ "$skipped" == 0 -a "$failed" == 0 ]; then
	msg "all tests passed"
	exit 0
fi

if [ "$skipped" != 0 ]; then
	msg "$skipped tests skipped, check skip.log"
fi
if [ "$failed" != 0 ]; then
	msg "$failed tests failed, check fail.log"
fi
exit 1
