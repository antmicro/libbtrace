#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
#

if [ -n "${BT_TESTS_SRCDIR:-}" ]; then
	UTILSSH="$BT_TESTS_SRCDIR/utils/utils.sh"
else
	UTILSSH="$(dirname "$0")/../utils/utils.sh"
fi

# shellcheck source=../utils/utils.sh
source "$UTILSSH"

export PYTHON_PLUGIN_PROVIDER_TEST_PLUGIN_PATH="${BT_TESTS_SRCDIR}/python-plugin-provider/bt_plugin_test_python_plugin_provider.py"

run_python_bt2_test \
	"${BT_TESTS_SRCDIR}/python-plugin-provider" \
	test_python_plugin_provider.py
