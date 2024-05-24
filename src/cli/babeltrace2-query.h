/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2019 EfficiOS Inc.
 */

#ifndef BABELTRACE_CLI_BABELTRACE2_QUERY_H
#define BABELTRACE_CLI_BABELTRACE2_QUERY_H

#include <babeltrace2/babeltrace.h>
#include "common/macros.h"

bt_query_executor_query_status cli_query(const bt_component_class *comp_cls,
		const char *obj, const bt_value *params,
		bt_logging_level log_level, const bt_interrupter *interrupter,
		const bt_value **user_result, const char **fail_reason);

#endif /* BABELTRACE_CLI_BABELTRACE2_QUERY_H */
