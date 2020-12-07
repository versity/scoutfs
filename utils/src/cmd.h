#ifndef _CMD_H_
#define _CMD_H_

void cmd_register(char *name, char *opts, char *summary,
		  int (*func)(int argc, char **argv));

char cmd_execute(int argc, char **argv);

#endif
