/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 EfficiOS, Inc.
 */

#ifndef BABELTRACE_STRING_FORMAT_FORMAT_ERROR_H
#define BABELTRACE_STRING_FORMAT_FORMAT_ERROR_H

#include <babeltrace2/babeltrace.h>
#include <common/common.h>
#include <common/macros.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

gchar *format_bt_error_cause(
		const bt_error_cause *error_cause,
		unsigned int columns,
		bt_logging_level log_level,
		enum bt_common_color_when use_colors);

gchar *format_bt_error(
		const bt_error *error,
		unsigned int columns,
		bt_logging_level log_level,
		enum bt_common_color_when use_colors);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_STRING_FORMAT_FORMAT_ERROR_H */
