#ifndef _SCOUTFS_UTILS_CHECK_DEBUG_H_
#define _SCOUTFS_UTILS_CHECK_DEBUG_H_

#include <stdio.h>

#define debug(fmt, args...)				\
do {							\
	if (debug_fd >= 0)				\
		dprintf(debug_fd, fmt"\n", ##args);	\
} while (0)

extern int debug_fd;

void debug_enable(int fd);
void debug_disable(void);

#endif
