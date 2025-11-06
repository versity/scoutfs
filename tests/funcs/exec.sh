
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
# As run, stdout/err are redirected to a file that will be compared with
# the stored expected golden output of the test.  This redirects
# stdout/err in the script to stdout of the invoking run-test.  It's
# intended to give visible output of tests without being included in the
# golden output.
#
# (see the goofy "exec" fd manipulation in the main run-tests as it runs
# each test)
#
t_stdout_invoked()
{
	exec >&6 2>&1
}

#
# This undoes t_stdout_invokved, returning the test's stdout/err to the
# output file as it was when it was launched.
#
t_stdout_compare()
{
	exec >&7 2>&1
}

#
# usually bash prints an annoying output message when jobs
# are killed.  We can avoid that by redirecting stderr for
# the bash process when it reaps the jobs that are killed.
#
t_silent_kill() {
	exec {ERR}>&2 2>/dev/null
	kill "$@"
	wait "$@"
	exec 2>&$ERR {ERR}>&-
}
