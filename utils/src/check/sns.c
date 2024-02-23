#include <stdlib.h>
#include <string.h>

#include "sns.h"

/*
 * This "str num stack" is used to describe our location in metadata at
 * any given time.
 *
 * As we descend into structures we pop a string on decribing them,
 * perhaps with associated numbers.  Pushing and popping is very cheap
 * and only rarely do we format the stack into a string, as an arbitrary
 * example:
 *   super.fs_root.btree_parent:1231.btree_leaf:3231"
 */

#define SNS_MAX_DEPTH	1000
#define SNS_STR_SIZE	(SNS_MAX_DEPTH * (SNS_MAX_STR_LEN + 1 + 16 + 1))

static struct sns_data {
	unsigned int depth;

	struct sns_entry {
		char *str;
		size_t len;
		u64 a;
		u64 b;
	} ents[SNS_MAX_DEPTH];

	char str[SNS_STR_SIZE];

} global_lsdat;

void _sns_push(char *str, size_t len, u64 a, u64 b)
{
	struct sns_data *lsdat = &global_lsdat;

	if (lsdat->depth < SNS_MAX_DEPTH) {
		lsdat->ents[lsdat->depth++] = (struct sns_entry) {
			.str = str,
			.len = len,
			.a = a,
			.b = b,
		};
	}
}

void sns_pop(void)
{
	struct sns_data *lsdat = &global_lsdat;

	if (lsdat->depth > 0)
		lsdat->depth--;
}

static char *append_str(char *pos, char *str, size_t len)
{
	memcpy(pos, str, len);
	return pos + len;
}

/*
 * This is not called for x = 0 so we don't need to emit an initial 0.
 * We could by using do {} while instead of while {}.
 */
static char *append_u64x(char *pos, u64 x)
{
	static char hex[] = "0123456789abcdef";

	while (x) {
		*pos++ = hex[x & 0xf];
		x >>= 4;
	}

	return pos;
}

static char *append_char(char *pos, char c)
{
	*(pos++) = c;
	return pos;
}

/*
 * Return a pointer to a null terminated string that describes the
 * current location stack.  The string buffer is global.
 */
char *sns_str(void)
{
	struct sns_data *lsdat = &global_lsdat;
	struct sns_entry *ent;
	char *pos;
	int i;

	pos = lsdat->str;
	for (i = 0; i < lsdat->depth; i++) {
		ent = &lsdat->ents[i];

		if (i)
			pos = append_char(pos, '.');

		pos = append_str(pos, ent->str, ent->len);

		if (ent->a) {
			pos = append_char(pos, ':');
			pos = append_u64x(pos, ent->a);
		}

		if (ent->b) {
			pos = append_char(pos, ':');
			pos = append_u64x(pos, ent->b);
		}
	}

	*pos = '\0';

	return lsdat->str;
}
