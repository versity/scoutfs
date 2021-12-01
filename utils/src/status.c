#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <argp.h>

#include "util.h"
#include "cmd.h"
#include "parse.h"

#define SCOUTFS_STATUS_PATH "/usr/lib/python3.6/site-packages/scoutfs_status/scoutfs.py"

struct status_args {
    char *cmd;
    char *function;
    char *options;
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
    struct status_args *args = state->input;
    
    switch(key) {
        case 'j':
            args->options = strdup_or_error(state, "--json");
            break;
        case 's':
            args->options = strdup_or_error(state, "--summary");
            break;
        case 'd':
            args->options = strdup_or_error(state, "--detail");
            break;
        case ARGP_KEY_ARG:
            if (args->cmd) {
                args->function = strdup_or_error(state, arg);
            } else {
                args->cmd = strdup_or_error(state, arg);
            }
            break;
        default:
            break;
        }
    return 0;
}

static struct argp_option options[] = {
    { "json", 'j', NULL, 0, "Print in JSON Format"},
    { "summary", 's', NULL, 0, "Print in Table Format"},
    { "detail", 'd', NULL, 0, "Print in Multiline Format"},
    { NULL }
};

static struct argp argp = {
    options,
    parse_opt,
    "",
    "Status of ScoutFS filesystem"
};

static int status_cmd(int argc, char **argv)
{
    struct status_args args = {NULL};
    char str[100] = "python3 ";
    int ret = 0;

    strcat(strcat(str,SCOUTFS_STATUS_PATH), " ");

    ret = argp_parse(&argp, argc, argv, 0, NULL, &args);
    if (ret)
        return ret;

    if (args.options) {
        strcat(str, args.options);
        strcat(str, " ");
    }
    if (args.cmd)
        strcat(str,args.cmd);
    if (args.function)
        strcat(strcat(str, " "),args.function);
    system(str);

    return 0;
}

static void __attribute__((constructor)) status_ctor(void)
{
    if(access(SCOUTFS_STATUS_PATH, F_OK) == 0) {
        cmd_register_argp("status", &argp, GROUP_CORE, status_cmd);
    } else {
        return;
    }
}
