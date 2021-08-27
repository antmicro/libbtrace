/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright 2017 Philippe Proulx <pproulx@efficios.com>
 */

#include <glib.h>

#include <babeltrace2/babeltrace.h>
#include "babeltrace2-cfg.h"
#include "babeltrace2-cfg-cli-args.h"
#include "babeltrace2-cfg-cli-args-default.h"

#ifdef BT_SET_DEFAULT_IN_TREE_CONFIGURATION

enum bt_config_cli_args_status bt_config_cli_args_create_with_default(int argc,
		const char *argv[], struct bt_config **cfg,
		const bt_interrupter *interrupter)
{
	enum bt_config_cli_args_status status;
	bt_value *initial_plugin_paths;
	int ret;

	initial_plugin_paths = bt_value_array_create();
	if (!initial_plugin_paths) {
		goto error;
	}

	ret = bt_config_append_plugin_paths(initial_plugin_paths,
		CONFIG_IN_TREE_PLUGIN_PATH);
	if (ret) {
		goto error;
	}

#ifdef CONFIG_IN_TREE_PROVIDER_DIR
	/*
	 * Set LIBBABELTRACE2_PLUGIN_PROVIDER_DIR to load the in-tree Python
	 * plugin provider, if the env variable is already set, do not overwrite
	 * it.
	 */
	g_setenv("LIBBABELTRACE2_PLUGIN_PROVIDER_DIR", CONFIG_IN_TREE_PROVIDER_DIR, 0);
#else
	/*
	 * If the Pyhton plugin provider is disabled, use a non-exitent path to avoid
	 * loading the system installed provider if it exit, if the env variable is
	 * already set, do not overwrite it.
	 */
	g_setenv("LIBBABELTRACE2_PLUGIN_PROVIDER_DIR", "/nonexistent", 0);
#endif

	status = bt_config_cli_args_create(argc, argv, cfg, true, true,
		initial_plugin_paths, interrupter);
	goto end;

error:
	status = BT_CONFIG_CLI_ARGS_STATUS_ERROR;

end:
	bt_value_put_ref(initial_plugin_paths);
	return status;
}

#else /* BT_SET_DEFAULT_IN_TREE_CONFIGURATION */

enum bt_config_cli_args_status bt_config_cli_args_create_with_default(int argc,
		const char *argv[], struct bt_config **cfg,
		const bt_interrupter *interrupter)
{
	return bt_config_cli_args_create(argc, argv, cfg, false, false,
		NULL, interrupter);
}

#endif /* BT_SET_DEFAULT_IN_TREE_CONFIGURATION */
