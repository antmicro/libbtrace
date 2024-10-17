/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>
 */

/* Output argument typemap for self port output (always appends) */
%typemap(in, numinputs=0)
	(bt_self_component_port_input **)
	(bt_self_component_port_input *temp_self_port = NULL) {
	$1 = &temp_self_port;
}

%typemap(argout) bt_self_component_port_input ** {
	if (*$1) {
		/* SWIG_AppendOutput() steals the created object */
		$result = SWIG_AppendOutput($result,
				SWIG_NewPointerObj(SWIG_as_voidptr(*$1),
					SWIGTYPE_p_bt_self_component_port_input, 0));
	} else {
		/* SWIG_AppendOutput() steals Py_None */
		Py_INCREF(Py_None);
		$result = SWIG_AppendOutput($result, Py_None);
	}
}

/* Output argument typemap for self port output (always appends) */
%typemap(in, numinputs=0)
	(bt_self_component_port_output **)
	(bt_self_component_port_output *temp_self_port = NULL) {
	$1 = &temp_self_port;
}

%typemap(argout) (bt_self_component_port_output **) {
	if (*$1) {
		/* SWIG_AppendOutput() steals the created object */
		$result = SWIG_AppendOutput($result,
				SWIG_NewPointerObj(SWIG_as_voidptr(*$1),
					SWIGTYPE_p_bt_self_component_port_output, 0));
	} else {
		/* SWIG_AppendOutput() steals Py_None */
		Py_INCREF(Py_None);
		$result = SWIG_AppendOutput($result, Py_None);
	}
}

/* Typemaps used for user data attached to self component ports. */

/*
 * The user data Python object is kept as the user data of the port, we pass
 * the PyObject pointer directly to the port creation function.
 */
%typemap(in) void *user_data {
	$1 = $input;
}

/*
 * The port, if created successfully, now owns a reference to the Python object,
 * we reflect that here.
 */
%typemap(argout) void *user_data {
	if (PyLong_AsLong($result) == __BT_FUNC_STATUS_OK) {
		Py_INCREF($1);
	}
}

%include <babeltrace2/graph/component.h>
%include <babeltrace2/graph/self-component.h>

/*
 * This type map relies on the rather common "user_data" name, so don't pollute
 * the typemap namespace.
 */
%clear void *user_data;
