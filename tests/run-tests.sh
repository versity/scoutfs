#!/usr/bin/bash

# Force system tools to use ASCII quotes
export LC_ALL=C

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

timestamp()
{
	date '+%F %T.%N'
}

# output a message with a timestamp to the run.log
log()
{
	echo "[$(timestamp)] $*" >> "$T_RESULTS/run.log"
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
    -D <file> | Specify the filesystem's data device path that contains the
              | file system to be tested.  Will be clobbered by -m mkfs.
    -E <re>   | Exclude tests whose file name matches the regular expression.
              | Can be provided multiple times
    -e <file> | Specify an extra storage data device for testing.  Will be clobbered.
    -f <file> | Specify an extra storage meta device for testing.  Will be clobbered.
    -F        | Dump accumulated ftrace buffer to the console on oops.
    -I <re>   | Include tests whose file name matches the regular expression.
              | By default all tests are run.  If this is provided then
              | only tests matching will be run.  Can be provided multiple
              | times
    -i        | Force removing and inserting the built scoutfs.ko module.
    -M <file> | Specify the filesystem's meta data device path that contains
              | the file system to be tested.  Will be clobbered by -m mkfs.
    -m        | Run mkfs on the device before mounting and running
              | tests.  Implies unmounting existing mounts first.
    -n <nr>   | The number of devices and mounts to test.
    -o <opts> | Add option string to all mounts during all tests.
    -P        | Enable trace_printk.
    -p        | Exit script after preparing mounts only, don't run tests.
    -q <nr>   | The first <nr> mounts will be quorum members.  Must be
              | at least 1 and no greater than -n number of mounts.
    -r <dir>  | Specify the directory in which to store results of
              | test runs.  The directory will be created if it doesn't
              | exist.  Previous results will be deleted as each test runs.
    -s        | Skip git repo checkouts.
    -t        | Enabled trace events that match the given glob argument.
              | Multiple options enable multiple globbed events.
    -T <nr>   | Multiply the original trace buffer size by nr during the run.
    -V <nr>   | Set mkfs device format version.
    -X        | xfstests git repo. Used by tests/xfstests.sh.
    -x        | xfstests git branch to checkout and track.
    -y        | xfstests ./check additional args
    -z <nr>   | set data-alloc-zone-blocks in mkfs
EOF
}

# unset all the T_ variables
for v in ${!T_*}; do
	eval unset $v
done

# set some T_ defaults
T_TRACE_DUMP="0"
T_TRACE_PRINTK="0"

# array declarations to be able to use array ops
declare -a T_TRACE_GLOB

while true; do
	case $1 in
	-a)
		T_ABORT="1"
		;;
	-D)
		test -n "$2" || die "-d must have device file argument"
		T_DATA_DEVICE="$2"
		shift
		;;
	-E)
		test -n "$2" || die "-E must have test exclusion regex argument"
		T_EXCLUDE+="-e '$2' "
		shift
		;;
	-e)
		test -n "$2" || die "-e must have extra device file argument"
		T_EX_DATA_DEV="$2"
		shift
		;;
	-f)
		test -n "$2" || die "-e must have extra device file argument"
		T_EX_META_DEV="$2"
		shift
		;;
	-F)
		T_TRACE_DUMP="1"
		;;
	-I)
		test -n "$2" || die "-I must have test incusion regex argument"
		T_INCLUDE+="-e '$2' "
		shift
		;;
	-i)
		T_INSMOD="1"
		;;
	-M)
	        test -n "$2" || die "-z must have meta device file argument"
	        T_META_DEVICE="$2"
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
	-o)
		test -n "$2" || die "-o must have option string argument"
		# always appending to existing options
		T_MNT_OPTIONS+=",$2"
		shift
		;;
	-P)
		T_TRACE_PRINTK="1"
		;;
	-p)
		T_PREPARE="1"
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
		T_TRACE_GLOB+=("$2")
		shift
		;;
	-T)
		test -n "$2" || die "-T must have trace buffer size multiplier argument"
		T_TRACE_MULT="$2"
		shift
		;;
	-V)
		test -n "$2" || die "-V must have a format version argument"
		T_MKFS_FORMAT_VERSION="-V $2"
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
	-z)
		test -n "$2" || die "-z must have nr mounts argument"
		T_DATA_ALLOC_ZONE_BLOCKS="-z $2"
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

test -n "$T_DATA_DEVICE" || die "must specify -D data device"
test -e "$T_DATA_DEVICE" || die "data device -D '$T_DATA_DEVICE' doesn't exist"
test -n "$T_META_DEVICE" || die "must specify -M meta device"
test -e "$T_META_DEVICE" || die "meta device -M '$T_META_DEVICE' doesn't exist"

test -n "$T_EX_META_DEV" || die "must specify -f extra meta device"
test -e "$T_EX_META_DEV" || die "extra meta device -f '$T_EX_META_DEV' doesn't exist"
test -n "$T_EX_DATA_DEV" || die "must specify -e extra data device"
test -e "$T_EX_DATA_DEV" || die "extra data device -e '$T_EX_DATA_DEV' doesn't exist"

test -n "$T_RESULTS" || die "must specify -r results dir"
test -n "$T_XFSTESTS_REPO" -a -z "$T_XFSTESTS_BRANCH" -a -z "$T_SKIP_CHECKOUT" && \
	die "-X xfstests repo requires -x xfstests branch"
test -n "$T_XFSTESTS_BRANCH" -a -z "$T_XFSTESTS_REPO" -a -z "$T_SKIP_CHECKOUT" && \
	die "-X xfstests branch requires -x xfstests repo"

test -n "$T_NR_MOUNTS" || die "must specify -n nr mounts"
test "$T_NR_MOUNTS" -ge 1 -a "$T_NR_MOUNTS" -le 8 || \
	 die "-n nr mounts must be >= 1 and <= 8"
test -n "$T_QUORUM" || \
	 die "must specify -q number of mounts that are quorum members"
test "$T_QUORUM" -ge "1" || \
	 die "-q quorum mmembers must be at least 1"
test "$T_QUORUM" -le "$T_NR_MOUNTS" || \
	 die "-q quorum mmembers must not be greater than -n mounts"

# top level paths
T_TESTS=$(realpath "$(dirname $0)")
T_KMOD=$(realpath "$T_TESTS/../kmod")
T_UTILS=$(realpath "$T_TESTS/../utils")

test -d "$T_KMOD" || die "kmod/ repo dir $T_KMOD not directory"
test -d "$T_UTILS" || die "utils/ repo dir $T_UTILS not directory"

# canonicalize paths
for e in T_META_DEVICE T_DATA_DEVICE T_EX_META_DEV T_EX_DATA_DEV T_KMOD T_RESULTS T_UTILS T_XFSTESTS_REPO; do
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

# might as well build our stuff with all cpus, assuming idle system
MAKE_ARGS="-j $(getconf _NPROCESSORS_ONLN)"

# build kernel module
msg "building kmod/ dir $T_KMOD"
cmd cd "$T_KMOD"
cmd make $MAKE_ARGS
cmd sync
cmd cd -

# build utils
msg "building utils/ dir $T_UTILS"
cmd cd "$T_UTILS"
cmd make $MAKE_ARGS
cmd sync
cmd cd -

# we can now run the built scoutfs binary, prefer over installed
PATH="$T_UTILS/src:$PATH"

# verify xfstests branch
if [ -n "$T_XFSTESTS_REPO" ] && [ -z "$T_SKIP_CHECKOUT" ]; then
	msg "verifying xfstests repo $T_XFSTESTS_REPO branch $T_XFSTESTS_BRANCH"
	cmd cd "$T_XFSTESTS_REPO"
	cmd git rev-parse --verify "$T_XFSTESTS_BRANCH"
	cmd cd -
fi

# building our test binaries
msg "building test binaries"
cmd make $MAKE_ARGS

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
	for dev in /dev/mapper/_scoutfs_test_*; do
		if [ -b "$dev" ]; then
			cmd dmsetup remove $dev
		fi
	done
}
if [ -n "$T_UNMOUNT" ]; then
	unmount_all
fi

quo=""
if [ -n "$T_MKFS" ]; then
	for i in $(seq -0 $((T_QUORUM - 1))); do
		quo="$quo -Q $i,127.0.0.1,$((42000 + i))"
	done

	msg "making new filesystem with $T_QUORUM quorum members"
	cmd scoutfs mkfs -f $quo $T_DATA_ALLOC_ZONE_BLOCKS $T_MKFS_FORMAT_VERSION \
		"$T_META_DEVICE" "$T_DATA_DEVICE"
fi

if [ -n "$T_INSMOD" ]; then
	msg "removing and reinserting scoutfs module"
	test -e /sys/module/scoutfs && cmd rmmod scoutfs
	cmd modprobe libcrc32c
	T_MODULE="$T_KMOD/src/scoutfs.ko"
	cmd insmod "$T_MODULE"
fi

if [ -n "$T_TRACE_MULT" ]; then
	orig_trace_size=$(cat /sys/kernel/debug/tracing/buffer_size_kb)
	mult_trace_size=$((orig_trace_size * T_TRACE_MULT))
	msg "increasing trace buffer size from $orig_trace_size KiB to $mult_trace_size KiB"
	echo $mult_trace_size > /sys/kernel/debug/tracing/buffer_size_kb
fi

nr_globs=${#T_TRACE_GLOB[@]}
if [ $nr_globs -gt 0 ]; then
	echo 0 > /sys/kernel/debug/tracing/events/scoutfs/enable

	for g in "${T_TRACE_GLOB[@]}"; do
		for e in /sys/kernel/debug/tracing/events/scoutfs/$g/enable; do
			if test -w "$e"; then
				echo 1 > "$e"
			else
				die "-t glob '$g' matched no scoutfs events"
			fi
		done
	done

	nr_events=$(cat /sys/kernel/debug/tracing/set_event | wc -l)
	msg "enabled $nr_events trace events from $nr_globs -t globs"
fi

if [ -n "$T_TRACE_PRINTK" ]; then
	echo "$T_TRACE_PRINTK" > /sys/kernel/debug/tracing/options/trace_printk
fi

if [ -n "$T_TRACE_DUMP" ]; then
	echo "$T_TRACE_DUMP" > /proc/sys/kernel/ftrace_dump_on_oops
fi

# always describe tracing in the logs
cmd cat /sys/kernel/debug/tracing/set_event
cmd grep .  /sys/kernel/debug/tracing/options/trace_printk \
	    /sys/kernel/debug/tracing/buffer_size_kb \
	    /proc/sys/kernel/ftrace_dump_on_oops

#
# Build a fenced config that runs scripts out of the repository rather
# than the default system directory
#
conf="$T_RESULTS/scoutfs-fenced.conf"
cat > $conf << EOF
SCOUTFS_FENCED_DELAY=1
SCOUTFS_FENCED_RUN=$T_TESTS/fenced-local-force-unmount.sh
SCOUTFS_FENCED_RUN_ARGS="ignored run args"
EOF
export SCOUTFS_FENCED_CONFIG_FILE="$conf"
T_FENCED_LOG="$T_RESULTS/fenced.log"

#
# Run the agent in the background, log its output, an kill it if we
# exit
#
fenced_log()
{
	echo "[$(timestamp)] $*" >> "$T_FENCED_LOG"
}
fenced_pid=""
kill_fenced()
{
	if test -n "$fenced_pid" -a -d "/proc/$fenced_pid" ; then
		fenced_log "killing fenced pid $fenced_pid"
		kill "$fenced_pid"
	fi
}
trap kill_fenced EXIT
$T_UTILS/fenced/scoutfs-fenced > "$T_FENCED_LOG" 2>&1 &
fenced_pid=$!
fenced_log "started fenced pid $fenced_pid in the background"

# setup dm tables
echo "0 $(blockdev --getsz $T_META_DEVICE) linear $T_META_DEVICE 0" > \
	$T_RESULTS/dmtable.meta
echo "0 $(blockdev --getsz $T_DATA_DEVICE) linear $T_DATA_DEVICE 0" > \
	$T_RESULTS/dmtable.data

#
# mount concurrently so that a quorum is present to elect the leader and
# start a server.
#
msg "mounting $T_NR_MOUNTS mounts on meta $T_META_DEVICE data $T_DATA_DEVICE"
pids=""
for i in $(seq 0 $((T_NR_MOUNTS - 1))); do

	name="_scoutfs_test_meta_$i"
	cmd dmsetup create "$name" --table "$(cat $T_RESULTS/dmtable.meta)"
	meta_dev="/dev/mapper/$name"

	name="_scoutfs_test_data_$i"
	cmd dmsetup create "$name" --table "$(cat $T_RESULTS/dmtable.data)"
	data_dev="/dev/mapper/$name"

	dir="/mnt/test.$i"
	test -d "$dir" || cmd mkdir -p "$dir"

	opts="-o metadev_path=$meta_dev"
	if [ "$i" -lt "$T_QUORUM" ]; then
		opts="$opts,quorum_slot_nr=$i"
	fi
	opts="${opts}${T_MNT_OPTIONS}"

	msg "mounting $meta_dev|$data_dev on $dir"
	cmd mount -t scoutfs $opts "$data_dev" "$dir" &

	p="$!"
	pids="$pids $!"
	log "background mount $i pid $p"

	eval T_O$i=\"$opts\"
	T_O[$i]="$opts"
	T_OS+="$opts "

	eval T_MB$i=$meta_dev
	T_MB[$i]=$meta_dev
	T_MBS+="$meta_dev "

	eval T_DB$i=$data_dev
	T_DB[$i]=$data_dev
	T_DBS+="$data_dev "

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
skipped_permitted=0
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
	stats=$(grep -s "^$test_name " "$last" | cut -d " " -f 2-)
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
		grep -s -v "^$test_name " "$last" > "$last.tmp"
		echo "$test_name $stats" >> "$last.tmp"
		mv -f "$last.tmp" "$last"
	elif [ "$sts" == "$T_SKIP_PERMITTED_STATUS" ]; then
		echo "  [ skipped (permitted): $message ]"
		echo "$test_name skipped (permitted) $message " >> "$T_RESULTS/skip.log"
		((skipped_permitted++))
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

msg "all tests run: $passed passed, $skipped skipped, $skipped_permitted skipped (permitted), $failed failed"


if [ -n "$T_TRACE_GLOB" -o -n "$T_TRACE_PRINTK" ]; then
	msg "saving traces and disabling tracing"
	echo 0 > /sys/kernel/debug/tracing/events/scoutfs/enable
	echo 0 > /sys/kernel/debug/tracing/options/trace_printk
	cat /sys/kernel/debug/tracing/trace > "$T_RESULTS/traces"
	if [ -n "$orig_trace_size" ]; then
		echo $orig_trace_size > /sys/kernel/debug/tracing/buffer_size_kb
	fi
fi

if [ "$skipped" == 0 -a "$failed" == 0 ]; then
	msg "all tests passed"
	unmount_all
	exit 0
fi

if [ "$skipped" != 0 ]; then
	msg "$skipped tests skipped, check skip.log, still mounted"
fi
if [ "$failed" != 0 ]; then
	msg "$failed tests failed, check fail.log, still mounted"
fi
exit 1
