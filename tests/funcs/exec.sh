
t_status_msg()
{
	echo "$*" > "$T_TMPDIR/status.msg"
}

export T_PASS_STATUS=100
export T_SKIP_STATUS=101
export T_FAIL_STATUS=102
export T_FIRST_STATUS="$T_PASS_STATUS"
export T_LAST_STATUS="$T_FAIL_STATUS"

t_pass()
{
	exit $T_PASS_STATUS
}

t_skip()
{
	t_status_msg "$@"
	exit $T_SKIP_STATUS
}

t_fail()
{
	t_status_msg "$@"
	exit $T_FAIL_STATUS
}

#
# Quietly run a command during a test.  If it succeeds then we have a
# log of its execution but its output isn't included in the test's
# compared output.  If it fails then the test fails.
#
t_quiet()
{
	echo "# $*" >> "$T_TMPDIR/quiet.log"
	"$@" > "$T_TMPDIR/quiet.log" 2>&1 || \
		t_fail "quiet command failed"
}

#
# redirect test output back to the output of the invoking script intead
# of the compared output.
#
t_restore_output()
{
	exec >&6 2>&1
}

#
# redirect a command's output back to the compared output after the
# test has restored its output
#
t_compare_output()
{
	"$@" >&7 2>&1
}
