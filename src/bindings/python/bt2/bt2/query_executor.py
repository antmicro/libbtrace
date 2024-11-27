# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>


from bt2 import error as bt2_error
from bt2 import utils as bt2_utils
from bt2 import value as bt2_value
from bt2 import object as bt2_object
from bt2 import native_bt
from bt2 import interrupter as bt2_interrupter

typing = bt2_utils._typing_mod

if typing.TYPE_CHECKING:
    from bt2 import component as bt2_component


def _bt2_component():
    from bt2 import component as bt2_component

    return bt2_component


class _QueryExecutorCommon:
    @property
    def _common_ptr(self):
        return self._as_query_executor_ptr()

    @property
    def is_interrupted(self) -> bool:
        return bool(native_bt.query_executor_is_interrupted(self._common_ptr))

    @property
    def logging_level(self) -> int:
        return native_bt.query_executor_get_logging_level(self._common_ptr)


class QueryExecutor(bt2_object._SharedObject, _QueryExecutorCommon):
    @staticmethod
    def _get_ref(ptr):
        native_bt.query_executor_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.query_executor_put_ref(ptr)

    def _as_query_executor_ptr(self):
        return self._ptr

    def __init__(
        self,
        component_class: "bt2_component._ComponentClassConst",
        object_name: str,
        params=None,
        method_obj: object = None,
    ):
        if not isinstance(component_class, _bt2_component()._ComponentClassConst):
            err = False

            try:
                if not issubclass(component_class, _bt2_component()._UserComponent):
                    err = True
            except TypeError:
                err = True

            if err:
                o = component_class
                raise TypeError("'{}' is not a component class object".format(o))

        bt2_utils._check_str(object_name)

        if params is None:
            params_ptr = native_bt.value_null
        else:
            params = bt2_value.create_value(params)
            params_ptr = params._ptr

        cc_ptr = component_class._bt_component_class_ptr()

        if method_obj is not None and not native_bt.bt2_is_python_component_class(
            cc_ptr
        ):
            raise ValueError(
                "cannot pass a Python object to a non-Python component class"
            )

        ptr = native_bt.bt2_query_executor_create(
            cc_ptr, object_name, params_ptr, method_obj
        )

        if ptr is None:
            raise bt2_error._MemoryError("cannot create query executor object")

        super().__init__(ptr)

        # Keep a reference of `method_obj` as the native query executor
        # does not have any. This ensures that, when this object's
        # query() method is called, the Python object still exists.
        self._method_obj = method_obj

    def add_interrupter(self, interrupter: bt2_interrupter.Interrupter):
        bt2_utils._check_type(interrupter, bt2_interrupter.Interrupter)
        native_bt.query_executor_add_interrupter(self._ptr, interrupter._ptr)

    @property
    def default_interrupter(self) -> bt2_interrupter.Interrupter:
        return bt2_interrupter.Interrupter._create_from_ptr_and_get_ref(
            native_bt.query_executor_borrow_default_interrupter(self._ptr)
        )

    def _set_logging_level(self, log_level):
        bt2_utils._check_log_level(log_level)
        bt2_utils._handle_func_status(
            native_bt.query_executor_set_logging_level(self._ptr, log_level),
            "cannot set query executor's logging level",
        )

    logging_level = property(
        fget=_QueryExecutorCommon.logging_level, fset=_set_logging_level
    )

    def query(self) -> typing.Optional[bt2_value._ValueConst]:
        status, result_ptr = native_bt.query_executor_query(self._ptr)
        bt2_utils._handle_func_status(status, "cannot query component class")
        return bt2_value._create_from_const_ptr(result_ptr)


class _PrivateQueryExecutor(_QueryExecutorCommon):
    def __init__(self, ptr):
        self._ptr = ptr

    def _check_validity(self):
        if self._ptr is None:
            raise RuntimeError("this object is not valid anymore")

    def _as_query_executor_ptr(self):
        self._check_validity()
        return native_bt.private_query_executor_as_query_executor_const(self._ptr)

    def _invalidate(self):
        self._ptr = None
