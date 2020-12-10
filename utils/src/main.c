#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <argp.h>

#include "cmd.h"
#include "util.h"

/*
 * Ensure no compiler-added padding sneaks into structs defined in these
 * headers.
 */
#pragma GCC diagnostic error "-Wpadded"
#include "format.h"
#include "ioctl.h"
#pragma GCC diagnostic pop

int main(int argc, char **argv)
{
	/*
	 * XXX parse global options, env, configs, etc.
	 */

	return cmd_execute(argc, argv);
}
