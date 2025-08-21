/*
 * Copyright (c) 2011-2014, Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BABELTRACE_COMMON_ZEPHYR_UTIL_H
#define BABELTRACE_COMMON_ZEPHYR_UTIL_H

#define CONTAINER_OF(ptr, type, field)                               \
        ({                                                           \
                ((type *)(((char *)(ptr)) - offsetof(type, field))); \
        })

#endif /* BABELTRACE_COMMON_ZEPHYR_UTIL_H */
