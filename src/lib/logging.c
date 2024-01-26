/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 Philippe Proulx <pproulx@efficios.com>
 */

#include <babeltrace2/babeltrace.h>

#define BT_LOG_TAG "LIB/LOGGING"
#include "lib/logging.h"

/*
 * This is exported because even though the Python plugin provider is a
 * different shared object for packaging purposes, it's still considered
 * part of the library and therefore needs the library's run-time log
 * level.
 *
 * The default log level is NONE: we don't print logging statements for
 * any executable which links with the library. The executable must call
 * bt_logging_set_global_level() or the executable's user must set the
 * `LIBBABELTRACE2_INIT_LOG_LEVEL` environment variable to enable
 * logging.
 */
BT_EXPORT
int bt_lib_log_level = BT_LOG_NONE;

BT_EXPORT
enum bt_logging_level bt_logging_get_minimal_level(void)
{
	return BT_LOG_MINIMAL_LEVEL;
}

BT_EXPORT
enum bt_logging_level bt_logging_get_global_level(void)
{
	return bt_lib_log_level;
}

BT_EXPORT
void bt_logging_set_global_level(enum bt_logging_level log_level)
{
	bt_lib_log_level = log_level;
}

static
void __attribute__((constructor)) bt_logging_ctor(void)
{
	const char *v_extra = bt_version_get_development_stage() ?
		bt_version_get_development_stage() : "";

	bt_logging_set_global_level(
		(int) bt_log_get_level_from_env("LIBBABELTRACE2_INIT_LOG_LEVEL"));
	BT_LOGI("Babeltrace %u.%u.%u%s library loaded: "
		"major=%u, minor=%u, patch=%u, extra=\"%s\"",
		bt_version_get_major(), bt_version_get_minor(),
		bt_version_get_patch(), v_extra,
		bt_version_get_major(), bt_version_get_minor(),
		bt_version_get_patch(), v_extra);
}
