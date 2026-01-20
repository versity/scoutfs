#include <stdlib.h>

#include "debug.h"

int debug_fd = -1;

void debug_enable(int fd)
{
	debug_fd = fd;
}

void debug_disable(void)
{
	if (debug_fd >= 0)
		debug_fd = -1;
}
