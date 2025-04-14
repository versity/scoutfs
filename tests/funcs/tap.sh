
#
# Generate TAP format test results
#

t_tap_header()
{
	local runid=$1
	local sequence=( $(echo $tests) )
	local count=${#sequence[@]}

	# avoid recreating the same TAP result over again - harness sets this
	[[ -z "$runid" ]] && runid="*test*"

	cat > $T_RESULTS/scoutfs.tap <<TAPEOF
TAP version 14
1..${count}
#
# TAP results for run ${runid}
#
# host/run info:
#
#   hostname: ${HOSTNAME}
#   test start time: $(date --utc)
#   uname -r: $(uname -r)
#   scoutfs commit id: $(git describe --tags)
#
# sequence for this run:
#
TAPEOF

	# Sequence
	for t in ${tests}; do
		 echo ${t/.sh/}
	done | cat -n | expand | column -c 120 | expand | sed 's/^ /#/' >> $T_RESULTS/scoutfs.tap
	echo "#" >> $T_RESULTS/scoutfs.tap
}

t_tap_progress()
{
(
	local i=$(( testcount + 1 ))
	local testname=$1
	local result=$2

	local diff=""
	local dmsg=""

	if [[ -s "$T_RESULTS/tmp/${testname}/dmesg.new" ]]; then
		dmsg="1"
	fi

	if ! cmp -s golden/${testname} $T_RESULTS/output/${testname}; then
		diff="1"
	fi

	if [[ "${result}" == "100" ]] && [[ -z "${dmsg}" ]] && [[ -z "${diff}" ]]; then
		echo "ok ${i} - ${testname}"
	elif [[ "${result}" == "103" ]]; then
		echo "ok ${i} - ${testname}"
		echo "# ${testname} ** skipped - permitted **"
	else
		echo "not ok ${i} - ${testname}"
		case ${result} in
		101)
			echo "# ${testname} ** skipped **"
			;;
		102)
			echo "# ${testname} ** failed **"
			;;
		esac

		if [[ -n "${diff}" ]]; then
			echo "#"
			echo "# diff:"
			echo "#"
			diff -u golden/${testname} $T_RESULTS/output/${testname} | expand | sed 's/^/#   /'
		fi

		if [[ -n "${dmsg}" ]]; then
			echo "#"
			echo "# dmesg:"
			echo "#"
			cat "$T_RESULTS/tmp/${testname}/dmesg.new" | sed 's/^/#   /'
		fi
	fi
) >> $T_RESULTS/scoutfs.tap
}
