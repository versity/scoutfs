
t_status_msg()
{
	echo "$*" > "$T_TMPDIR/status.msg"
}

export T_PASS_STATUS=100
export T_SKIP_STATUS=101
export T_FAIL_STATUS=102
export T_SKIP_PERMITTED_STATUS=103
export T_FIRST_STATUS="$T_PASS_STATUS"
export T_LAST_STATUS="$T_SKIP_PERMITTED_STATUS"

t_pass()
{
	exit $T_PASS_STATUS
}

t_skip()
{
	t_status_msg "$@"
	exit $T_SKIP_STATUS
}

#
# This exit code is *reserved* for tests that are up-front never going to work
# in certain cases. This should be expressly documented per-case and made
# abundantly clear before merging. The test itself should document its case.
#
t_skip_permitted()
{
	t_status_msg "$@"
	exit $T_SKIP_PERMITTED_STATUS
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
	"$@" >> "$T_TMPDIR/quiet.log" 2>&1 || \
		t_fail "quiet command failed"
}

#
# Quietly run a command during a test.  The output is logged but only
# the return code is printed, presumably because the output contains
# a lot of invocation specific text that is difficult to filter.
#
t_rc()
{
	echo "# $*" >> "$T_TMP.rc.log"
	"$@" >> "$T_TMP.rc.log" 2>&1
	echo "rc: $?"
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
