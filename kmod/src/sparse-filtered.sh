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

#
# Darn.  sparse has multi-line error messages, and I'd rather not bother
# with multi-line filters.  So we'll just drop this context.
#
# command-line: note: in included file (through include/linux/netlink.h, include/linux/ethtool.h, include/linux/netdevice.h, include/net/sock.h, /root/scoutfs/kmod/src/kernelcompat.h, builtin): 
#         fprintf(stderr, "%s: note: in included file%s:\n",
#
RE+="|: note: in included file"

# 3.10.0-1160.119.1.el7.x86_64.debug
# include/linux/posix_acl.h:138:9: warning: incorrect type in assignment (different address spaces)
# include/linux/posix_acl.h:138:9:    expected struct posix_acl *<noident>
# include/linux/posix_acl.h:138:9:    got struct posix_acl [noderef] <asn:4>*<noident>
RE+="|include/linux/posix_acl.h:"

# 3.10.0-1160.119.1.el7.x86_64.debug
#include/uapi/linux/perf_event.h:146:56: warning: cast truncates bits from constant value (8000000000000000 becomes 0)
RE+="|include/uapi/linux/perf_event.h:"

# 4.18.0-513.24.1.el8_9.x86_64+debug'
#./include/linux/skbuff.h:824:1: warning: directive in macro's argument list
RE+="|include/linux/skbuff.h:"

sparse "$@" |& \
	grep -E -v "($RE)" |& \
	awk '{ print $0 } END { exit NR > 0 }'
exit $?
