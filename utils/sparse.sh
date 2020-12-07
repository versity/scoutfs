#!/bin/bash

# can we find sparse?  If not, we're done.
which sparse > /dev/null 2>&1 || exit 0

# 
# one of the problems with using sparse in userspace is that it picks up
# things in system headers that we don't care about.  We're willing to
# take on the burden of filtering them out so that we can have it tell
# us about problems in our code.
#
# system headers using __transparent_union__
RE="^/.*error: ignoring attribute __transparent_union__"

# we don't care if system headers have gcc attributes sparse doesn't
# know about
RE="$RE|error: attribute '__leaf__': unknown attribute"

# yes, sparse, that's the size of memseting a 4 meg buffer all right
RE="$RE|warning: memset with byte count of 4194304"

# some sparse versions don't know about some builtins
RE="$RE|error: undefined identifier '__builtin_fpclassify'"

#
# don't filter out 'too many errors' here, it can signify that
# sparse doesn't understand something and is throwing a *ton*
# of useless errors before giving up and existing.  Check
# unfiltered sparse output.
#

#
# I'm not sure this is needed.
#
search=$(gcc -print-search-dirs | awk '($1 == "install:"){print "-I" $2}')

#
# We're trying to use sparse against glibc headers which go wild trying to
# use internal compiler macros to test features.  We copy gcc's and give
# them to sparse.  But not __SIZE_TYPE__ 'cause sparse defines that one.
#
defines=".sparse.gcc-defines.h"
gcc -dM -E -x c - < /dev/null | grep -v __SIZE_TYPE__ > $defines
include="-include $defines"

#
# sparse doesn't seem to notice when it's on a 64bit host.  It warns that
# 64bit values don't fit in 'unsigned long' without this.
#
if grep -q "__LP64__ 1" $defines; then
	m64="-m64"
else
	m64=""
fi

sparse $m64 $include $search/include "$@" 2>&1 | egrep -v "($RE)" | tee .sparse.output
if  [ -s .sparse.output ]; then
	exit 1
else
	exit 0
fi
