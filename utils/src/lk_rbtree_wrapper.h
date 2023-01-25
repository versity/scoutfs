#ifndef _LK_RBTREE_WRAPPER_H_
#define _LK_RBTREE_WRAPPER_H_

/*
 * We're using this lame hack to build and use the kernel's rbtree in
 * userspace.  We drop the kernel's rbtree*[ch] implementation in and
 * use them with this wrapper.  We only have to remove the kernel
 * includes from the imported files.
 */

#include <stdbool.h>
#include "util.h"

#define rcu_assign_pointer(a, b)	do { a = b; } while (0)
#define READ_ONCE(a)			({ a; })
#define WRITE_ONCE(a, b)		do { a = b; } while (0)
#define unlikely(a)			({ a; })
#define EXPORT_SYMBOL(a)		/* nop */

#include "rbtree_types.h"
#include "rbtree.h"
#include "rbtree_augmented.h"

#endif
