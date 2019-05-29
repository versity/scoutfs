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
	/*
	 * XXX parse global options, env, configs, etc.
	 */

	return cmd_execute(argc, argv);
}
