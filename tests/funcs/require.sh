
#
# Make sure that all the base command arguments are found in the path.
# This isn't strictly necessary as the test will naturally fail if the
# command isn't found, but it's nice to fail fast and clearly
# communicate why.
#
t_require_commands() {
	local c

	for c in "$@"; do
		which "$c" >/dev/null 2>&1 || \
			t_fail "command $c not found in path"
	done
}

#
# make sure that we have at least this many mounts
#
t_require_mounts() {
	local req="$1"

	test "$T_NR_MOUNTS" -ge "$req" || \
		t_skip "$req mounts required, only have $T_NR_MOUNTS"
}
