#ifndef _SCOUTFS_UTILS_CHECK_SNS_H_
#define _SCOUTFS_UTILS_CHECK_SNS_H_

#include <assert.h>

#include "sparse.h"

#define SNS_MAX_STR_LEN 20

#define sns_push(str, a, b)					\
do {								\
	build_assert(sizeof(str) - 1 <= SNS_MAX_STR_LEN);	\
	_sns_push((str), sizeof(str) - 1, a, b);		\
} while (0)

void _sns_push(char *str, size_t len, u64 a, u64 b);
void sns_pop(void);
char *sns_str(void);

#endif
