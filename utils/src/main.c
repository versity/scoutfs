#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "cmd.h"
#include "util.h"

int main(int argc, char **argv)
{
	int ret;

	/*
	 * XXX parse global options, env, configs, etc.
	 */

	ret = cmd_execute(argc, argv);
	if (ret < 0)
		return 1;

	return 0;
}
