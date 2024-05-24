/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2010 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef BABELTRACE_COMPAT_COMPILER_H
#define BABELTRACE_COMPAT_COMPILER_H

#include <stddef.h>	/* for offsetof */

#define MAYBE_BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))

#ifndef container_of
#define container_of(ptr, type, member)					\
	({								\
		const __typeof__(((type *)NULL)->member) * __ptr = (ptr);	\
		(type *)((char *)__ptr - offsetof(type, member));	\
	})
#endif

#define BT_ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#endif /* BABELTRACE_COMPAT_COMPILER_H */
