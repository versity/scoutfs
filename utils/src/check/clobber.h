
#ifndef _SCOUTFS_UTILS_CHECK_CLOBBER_H
#define _SCOUTFS_UTILS_CHECK_CLOBBER_H

#include "problem.h"

struct clobber_function {
	prob_t problem;
	char *description;
	int (*do_clobber)(char *);
};

extern struct clobber_function *clobber_functions[];

#endif
