#!/bin/bash

#
# Unfortunately, kernels can ship which contain sparse errors that are
# unrelated to us.
#
# The exit status of this filtering wrapper will indicate an error if
# sparse wasn't found or if there were any unfiltered output lines.  It
# can hide error exit status from sparse or grep if they don't produce
# output that makes it past the filters.
#

# must have sparse.  Fail with error message, mask success path.
which sparse > /dev/null || exit 1

# initial unmatchable, additional added as RE+="|..."
RE="$^"

sparse "$@" |& \
	grep -E -v "($RE)" |& \
	awk '{ print $0 } END { exit NR > 0 }'
exit $?
