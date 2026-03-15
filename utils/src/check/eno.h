#ifndef _SCOUTFS_UTILS_CHECK_ENO_H_
#define _SCOUTFS_UTILS_CHECK_ENO_H_

#include <errno.h>

#define ENO_FMT		"%d (%s)"
#define ENO_ARG(eno)	eno, strerror(eno)

#endif
