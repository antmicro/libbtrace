/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2016 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef SWIGPYTHON
# error Unsupported output language
#endif

%module native_bt

%{
#define BT_LOG_TAG "BT2-PY"
#include "logging.hpp"

/*
 * Include before `<babeltrace2/func-status.h>` because
 * `<babeltrace2/babeltrace.h>` removes the `__BT_IN_BABELTRACE_H`
 * definition.
 */
#include <babeltrace2/babeltrace.h>

/*
 * This is not part of the API, but because those bindings reside within
 * the project, we take the liberty to use them.
 */
#define __BT_IN_BABELTRACE_H
#include <babeltrace2/func-status.h>

#include "common/assert.h"

/* Used by some interface files */
#include "native_bt_bt2_objects.hpp"
#include "native_bt_log_and_append_error.hpp"
%}

typedef int bt_bool;
typedef uint64_t bt_listener_id;

/* For uint*_t/int*_t */
%include "stdint.i"

/*
 * Remove `bt_` and `BT_` prefixes from function names, global variables and
 * enumeration items
 */
%rename("%(strip:[bt_])s", %$isfunction) "";
%rename("%(strip:[bt_])s", %$isvariable) "";
%rename("%(strip:[BT_])s", %$isenumitem) "";

/*
 * Output argument typemap for string output (always appends)
 *
 * We initialize the output parameter `temp_value` to an invalid but non-zero
 * pointer value.  This is to make sure we don't rely on its initial value in
 * the epilogue (where we call SWIG_Python_str_FromChar).  When they fail,
 * functions on which we apply this typemap don't guarantee that the value of
 * `temp_value` will be unchanged or valid.
 */
%typemap(in, numinputs=0) (const char **) (char *temp_value = reinterpret_cast<char *>(1)) {
	$1 = &temp_value;
}

%typemap(argout) (const char **) {
	if (*$1) {
		/* SWIG_AppendOutput() steals the created object */
		$result = SWIG_AppendOutput($result, SWIG_Python_str_FromChar(*$1));
	} else {
		/* SWIG_AppendOutput() steals Py_None */
		Py_INCREF(Py_None);
		$result = SWIG_AppendOutput($result, Py_None);
	}
}

/* Output argument typemap for value output (always appends) */
%typemap(in, numinputs=0) (bt_value **) (struct bt_value *temp_value = NULL) {
	$1 = &temp_value;
}

%typemap(argout) (bt_value **) {
	if (*$1) {
		/* SWIG_AppendOutput() steals the created object */
		$result = SWIG_AppendOutput($result,
				SWIG_NewPointerObj(SWIG_as_voidptr(*$1),
					SWIGTYPE_p_bt_value, 0));
	} else {
		/* SWIG_AppendOutput() steals Py_None */
		Py_INCREF(Py_None);
		$result = SWIG_AppendOutput($result, Py_None);
	}
}

/* Output argument typemap for initialized uint64_t output parameter (always appends) */
%typemap(in, numinputs=0) (uint64_t *) (uint64_t temp) {
	$1 = &temp;
}

%typemap(argout) uint64_t * {
	$result = SWIG_AppendOutput(resultobj,
			SWIG_From_unsigned_SS_long_SS_long((*$1)));
}

/* Output argument typemap for initialized int64_t output parameter (always appends) */
%typemap(in, numinputs=0) (int64_t *) (int64_t temp) {
	$1 = &temp;
}

%typemap(argout) (int64_t *) {
	$result = SWIG_AppendOutput(resultobj, SWIG_From_long_SS_long((*$1)));
}

/* Output argument typemap for initialized unsigned int output parameter (always appends) */
%typemap(in, numinputs=0) (unsigned int *) (unsigned int temp) {
	$1 = &temp;
}

%typemap(argout) (unsigned int *) {
	$result = SWIG_AppendOutput(resultobj,
			SWIG_From_unsigned_SS_long_SS_long((uint64_t) (*$1)));
}

/* Output argument typemap for initialized bt_boot output parameter (always appends) */
%typemap(in, numinputs=0) (bt_bool *) (bt_bool temp) {
	$1 = &temp;
}

%typemap(argout) bt_bool * {
	$result = SWIG_AppendOutput(resultobj,
			SWIG_From_bool(*$1));
}

/* Input argument typemap for UUID bytes */
%typemap(in) bt_uuid {
	$1 = (unsigned char *) PyBytes_AsString($input);
}

/* Output argument typemap for UUID bytes */
%typemap(out) bt_uuid {
	if (!$1) {
		Py_INCREF(Py_None);
		$result = Py_None;
	} else {
		$result = PyBytes_FromStringAndSize((const char *) $1, 16);
	}
}

/* Input argument typemap for bt_bool */
%typemap(in) bt_bool {
	$1 = PyObject_IsTrue($input);
}

/* Output argument typemap for bt_bool */
%typemap(out) bt_bool {
	if ($1 > 0) {
		$result = Py_True;
	} else {
		$result = Py_False;
	}
	Py_INCREF($result);
}

/*
 * Input and output argument typemaps for raw Python objects (direct).
 *
 * Those typemaps honor the convention of Python C function calls with
 * respect to reference counting: parameters are passed as borrowed
 * references, and objects are returned as new references. The wrapped
 * C function must ensure that the return value is always a new
 * reference, and never steal parameter references.
 */
%typemap(in) PyObject * {
	$1 = $input;
}

%typemap(out) PyObject * {
	$result = $1;
}

/* Native part initialization and finalization */
void bt_bt2_init_from_bt2(void);
void bt_bt2_exit_handler(void);

/*
 * These functions cause some -Wformat-nonliteral warnings, but we don't need
 * them.  Ignore them, so that we can keep the warning turned on.
 */
%ignore bt_current_thread_error_append_cause_from_component;
%ignore bt_current_thread_error_append_cause_from_component_class;
%ignore bt_current_thread_error_append_cause_from_message_iterator;
%ignore bt_current_thread_error_append_cause_from_unknown;

/*
 * Define `__BT_IN_BABELTRACE_H` to allow specific headers to be
 * included. This remains defined as long as we don't include the main
 * header, `<babeltrace2/babeltrace.h>`.
 */
#define __BT_IN_BABELTRACE_H

/*
 * Define `__BT_ATTR_FORMAT_PRINTF` and `__BT_NOEXCEPT` to nothing,
 * otherwise SWIG fails to parse the included header files that use it.
 */
#define __BT_ATTR_FORMAT_PRINTF(_string_index, _first_to_check)
#define __BT_NOEXCEPT

/* Common types */
%include <babeltrace2/types.h>

/* Common function status codes */
%include <babeltrace2/func-status.h>

/* Per-module interface files */
%include "native_bt_autodisc.i"
%include "native_bt_clock_class.i"
%include "native_bt_clock_snapshot.i"
%include "native_bt_component.i"
%include "native_bt_component_class.i"
%include "native_bt_connection.i"
%include "native_bt_error.i"
%include "native_bt_event.i"
%include "native_bt_event_class.i"
%include "native_bt_field.i"
%include "native_bt_field_class.i"
%include "native_bt_field_path.i"
%include "native_bt_graph.i"
%include "native_bt_integer_range_set.i"
%include "native_bt_interrupter.i"
%include "native_bt_logging.i"
%include "native_bt_message.i"
%include "native_bt_message_iterator.i"
%include "native_bt_mip.i"
%include "native_bt_packet.i"
%include "native_bt_plugin.i"
%include "native_bt_port.i"
%include "native_bt_query_exec.i"
%include "native_bt_stream.i"
%include "native_bt_stream_class.i"
%include "native_bt_trace.i"
%include "native_bt_trace_class.i"
%include "native_bt_value.i"
%include "native_bt_version.i"

%{

/*
 * This function is defined by SWIG.  Declare here to avoid a
 * -Wmissing-prototypes warning.
 */
extern "C" {
	PyObject *SWIG_init(void);
}

%}
