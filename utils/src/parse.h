#ifndef _PARSE_H_
#define _PARSE_H_

#include <sys/time.h>
#include <argp.h>

struct scoutfs_quorum_slot;

int parse_human(char* str, u64 *val_ret);
int parse_u64(char *str, u64 *val_ret);
int parse_s64(char *str, s64 *val_ret);
int parse_u32(char *str, u32 *val_ret);
int parse_timespec(char *str, struct timespec *ts);
int parse_quorum_slot(struct scoutfs_quorum_slot *slot, char *arg);

static inline char* strdup_or_error(const struct argp_state *state, char *str)
{
	char *new = strdup(str);
	if (!new)
		argp_error(state, "memory allocation failed");

	return new;
}

#endif
