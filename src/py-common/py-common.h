/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2019 EfficiOS Inc. and Linux Foundation
 * Copyright (c) 2019 Philippe Proulx <pproulx@efficios.com>
 * Copyright (c) 2019 Simon Marchi <simon.marchi@efficios.com>
 */

#ifndef BABELTRACE_PY_COMMON_PY_COMMON_H
#define BABELTRACE_PY_COMMON_PY_COMMON_H

#include <glib.h>
#include <Python.h>
#include <stdbool.h>

#include "common/macros.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Formats the Python traceback `py_exc_tb` using traceback.format_tb, from the
 * Python standard library, and return it as a Gstring.
 */
GString *bt_py_common_format_tb(PyObject *py_exc_tb, int log_level);

/*
 * Formats the Python exception described by `py_exc_type`, `py_exc_value`
 * and `py_exc_tb` and returns the formatted string, or `NULL` on error. The
 * returned string does NOT end with a newline.
 *
 * If `chain` is true, include all exceptions in the causality chain
 * (see parameter `chain` of Python's traceback.format_exception).
 */
GString *bt_py_common_format_exception(PyObject *py_exc_type,
	        PyObject *py_exc_value, PyObject *py_exc_tb,
		int log_level, bool chain);

/*
 * Wrapper for `bt_py_common_format_exception` that passes the Python error
 * indicator (the exception currently being raised).  Always include the
 * full exception chain.
 *
 * You must ensure that the error indicator is set with PyErr_Occurred()
 * before you call this function.
 *
 * This function does not modify the error indicator, that is, anything
 * that is fetched is always restored.
 */
GString *bt_py_common_format_current_exception(int log_level);

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE_PY_COMMON_PY_COMMON_H */
