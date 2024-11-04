# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>

from bt2 import utils as bt2_utils
from bt2 import value as bt2_value
from bt2 import object as bt2_object
from bt2 import native_bt
from bt2 import field_class as bt2_field_class
from bt2 import user_attributes as bt2_user_attrs

typing = bt2_utils._typing_mod

if typing.TYPE_CHECKING:
    from bt2 import stream_class as bt2_stream_class


def _bt2_stream_class():
    from bt2 import stream_class as bt2_stream_class

    return bt2_stream_class


class EventClassLogLevel:
    EMERGENCY = native_bt.EVENT_CLASS_LOG_LEVEL_EMERGENCY
    ALERT = native_bt.EVENT_CLASS_LOG_LEVEL_ALERT
    CRITICAL = native_bt.EVENT_CLASS_LOG_LEVEL_CRITICAL
    ERROR = native_bt.EVENT_CLASS_LOG_LEVEL_ERROR
    WARNING = native_bt.EVENT_CLASS_LOG_LEVEL_WARNING
    NOTICE = native_bt.EVENT_CLASS_LOG_LEVEL_NOTICE
    INFO = native_bt.EVENT_CLASS_LOG_LEVEL_INFO
    DEBUG_SYSTEM = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_SYSTEM
    DEBUG_PROGRAM = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_PROGRAM
    DEBUG_PROCESS = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_PROCESS
    DEBUG_MODULE = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_MODULE
    DEBUG_UNIT = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_UNIT
    DEBUG_FUNCTION = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_FUNCTION
    DEBUG_LINE = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_LINE
    DEBUG = native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG


class _EventClassConst(bt2_object._SharedObject, bt2_user_attrs._WithUserAttrsConst):
    @staticmethod
    def _get_ref(ptr):
        native_bt.event_class_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.event_class_put_ref(ptr)

    _borrow_stream_class_ptr = staticmethod(
        native_bt.event_class_borrow_stream_class_const
    )
    _borrow_specific_context_field_class_ptr = staticmethod(
        native_bt.event_class_borrow_specific_context_field_class_const
    )
    _borrow_payload_field_class_ptr = staticmethod(
        native_bt.event_class_borrow_payload_field_class_const
    )
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.event_class_borrow_user_attributes_const
    )
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        bt2_field_class._create_field_class_from_const_ptr_and_get_ref
    )
    _stream_class_pycls = property(lambda s: _bt2_stream_class()._StreamClassConst)

    @property
    def stream_class(self) -> "bt2_stream_class._StreamClassConst":
        sc_ptr = self._borrow_stream_class_ptr(self._ptr)

        if sc_ptr is not None:
            return self._stream_class_pycls._create_from_ptr_and_get_ref(sc_ptr)

    @property
    def name(self) -> typing.Optional[str]:
        return native_bt.event_class_get_name(self._ptr)

    @property
    def id(self) -> int:
        id = native_bt.event_class_get_id(self._ptr)
        return id if id >= 0 else None

    @property
    def log_level(self) -> typing.Optional[EventClassLogLevel]:
        is_available, log_level = native_bt.event_class_get_log_level(self._ptr)

        if is_available != native_bt.PROPERTY_AVAILABILITY_AVAILABLE:
            return None

        return _EVENT_CLASS_LOG_LEVEL_TO_OBJ[log_level]

    @property
    def emf_uri(self) -> typing.Optional[str]:
        return native_bt.event_class_get_emf_uri(self._ptr)

    @property
    def specific_context_field_class(
        self,
    ) -> typing.Optional[bt2_field_class._StructureFieldClassConst]:
        fc_ptr = self._borrow_specific_context_field_class_ptr(self._ptr)

        if fc_ptr is None:
            return

        return self._create_field_class_from_ptr_and_get_ref(fc_ptr)

    @property
    def payload_field_class(
        self,
    ) -> typing.Optional[bt2_field_class._StructureFieldClassConst]:
        fc_ptr = self._borrow_payload_field_class_ptr(self._ptr)

        if fc_ptr is None:
            return

        return self._create_field_class_from_ptr_and_get_ref(fc_ptr)


class _EventClass(bt2_user_attrs._WithUserAttrs, _EventClassConst):
    _borrow_stream_class_ptr = staticmethod(native_bt.event_class_borrow_stream_class)
    _borrow_specific_context_field_class_ptr = staticmethod(
        native_bt.event_class_borrow_specific_context_field_class
    )
    _borrow_payload_field_class_ptr = staticmethod(
        native_bt.event_class_borrow_payload_field_class
    )
    _borrow_user_attributes_ptr = staticmethod(
        native_bt.event_class_borrow_user_attributes
    )
    _create_field_class_from_ptr_and_get_ref = staticmethod(
        bt2_field_class._create_field_class_from_ptr_and_get_ref
    )
    _stream_class_pycls = property(lambda s: _bt2_stream_class()._StreamClass)

    @staticmethod
    def _set_user_attributes_ptr(obj_ptr, value_ptr):
        native_bt.event_class_set_user_attributes(obj_ptr, value_ptr)

    def _set_name(self, name):
        return native_bt.event_class_set_name(self._ptr, name)

    def _set_log_level(self, log_level):
        native_bt.event_class_set_log_level(self._ptr, log_level)

    def _set_emf_uri(self, emf_uri):
        status = native_bt.event_class_set_emf_uri(self._ptr, emf_uri)
        bt2_utils._handle_func_status(status, "cannot set event class object's EMF URI")

    def _set_specific_context_field_class(self, context_field_class):
        status = native_bt.event_class_set_specific_context_field_class(
            self._ptr, context_field_class._ptr
        )
        bt2_utils._handle_func_status(
            status, "cannot set event class object's context field class"
        )

    def _set_payload_field_class(self, payload_field_class):
        status = native_bt.event_class_set_payload_field_class(
            self._ptr, payload_field_class._ptr
        )
        bt2_utils._handle_func_status(
            status, "cannot set event class object's payload field class"
        )

    @staticmethod
    def _validate_create_params(
        name,
        user_attributes,
        log_level,
        emf_uri,
        specific_context_field_class,
        payload_field_class,
    ):
        if name is not None:
            bt2_utils._check_str(name)

        if user_attributes is not None:
            value = bt2_value.create_value(user_attributes)
            bt2_utils._check_type(value, bt2_value.MapValue)

        if log_level is not None:
            log_levels = (
                EventClassLogLevel.EMERGENCY,
                EventClassLogLevel.ALERT,
                EventClassLogLevel.CRITICAL,
                EventClassLogLevel.ERROR,
                EventClassLogLevel.WARNING,
                EventClassLogLevel.NOTICE,
                EventClassLogLevel.INFO,
                EventClassLogLevel.DEBUG_SYSTEM,
                EventClassLogLevel.DEBUG_PROGRAM,
                EventClassLogLevel.DEBUG_PROCESS,
                EventClassLogLevel.DEBUG_MODULE,
                EventClassLogLevel.DEBUG_UNIT,
                EventClassLogLevel.DEBUG_FUNCTION,
                EventClassLogLevel.DEBUG_LINE,
                EventClassLogLevel.DEBUG,
            )

            if log_level not in log_levels:
                raise ValueError("'{}' is not a valid log level".format(log_level))

        if emf_uri is not None:
            bt2_utils._check_str(emf_uri)

        if specific_context_field_class is not None:
            bt2_utils._check_type(
                specific_context_field_class, bt2_field_class._StructureFieldClass
            )

        if payload_field_class is not None:
            bt2_utils._check_type(
                payload_field_class, bt2_field_class._StructureFieldClass
            )


_EVENT_CLASS_LOG_LEVEL_TO_OBJ = {
    native_bt.EVENT_CLASS_LOG_LEVEL_EMERGENCY: EventClassLogLevel.EMERGENCY,
    native_bt.EVENT_CLASS_LOG_LEVEL_ALERT: EventClassLogLevel.ALERT,
    native_bt.EVENT_CLASS_LOG_LEVEL_CRITICAL: EventClassLogLevel.CRITICAL,
    native_bt.EVENT_CLASS_LOG_LEVEL_ERROR: EventClassLogLevel.ERROR,
    native_bt.EVENT_CLASS_LOG_LEVEL_WARNING: EventClassLogLevel.WARNING,
    native_bt.EVENT_CLASS_LOG_LEVEL_NOTICE: EventClassLogLevel.NOTICE,
    native_bt.EVENT_CLASS_LOG_LEVEL_INFO: EventClassLogLevel.INFO,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_SYSTEM: EventClassLogLevel.DEBUG_SYSTEM,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_PROGRAM: EventClassLogLevel.DEBUG_PROGRAM,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_PROCESS: EventClassLogLevel.DEBUG_PROCESS,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_MODULE: EventClassLogLevel.DEBUG_MODULE,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_UNIT: EventClassLogLevel.DEBUG_UNIT,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_FUNCTION: EventClassLogLevel.DEBUG_FUNCTION,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG_LINE: EventClassLogLevel.DEBUG_LINE,
    native_bt.EVENT_CLASS_LOG_LEVEL_DEBUG: EventClassLogLevel.DEBUG,
}
