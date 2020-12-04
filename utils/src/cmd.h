#ifndef _CMD_H_
#define _CMD_H_

#define GROUP_CORE 0
#define GROUP_INFO 1
#define GROUP_SEARCH 2
#define GROUP_AGENT 3
#define GROUP_DEBUG 4

void cmd_register_argp(char *name, struct argp *argp, int group,
		  int (*func)(int argc, char **argv));

char cmd_execute(int argc, char **argv);

#endif
