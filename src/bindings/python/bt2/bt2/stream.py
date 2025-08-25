# SPDX-License-Identifier: MIT
#
# Copyright (c) 2016-2017 Philippe Proulx <pproulx@efficios.com>

from bt2 import error as bt2_error
from bt2 import native_bt, typing_mod
from bt2 import object as bt2_object
from bt2 import packet as bt2_packet
from bt2 import stream_class as bt2_stream_class
from bt2 import user_attributes as bt2_user_attrs
from bt2 import utils as bt2_utils

typing = typing_mod._typing_mod

if typing.TYPE_CHECKING:
    from bt2 import trace as bt2_trace


def _bt2_trace():
    from bt2 import trace as bt2_trace

    return bt2_trace


class _StreamConst(bt2_object._SharedObject, bt2_user_attrs._WithUserAttrsConst):
    @staticmethod
    def _get_ref(ptr):
        native_bt.stream_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.stream_put_ref(ptr)

    _borrow_class_ptr = staticmethod(native_bt.stream_borrow_class_const)

    @staticmethod
    def _borrow_user_attributes_ptr(ptr):
        return native_bt.stream_borrow_user_attributes_const(ptr)

    _borrow_trace_ptr = staticmethod(native_bt.stream_borrow_trace_const)
    _stream_class_pycls = bt2_stream_class._StreamClassConst
    _trace_pycls = property(lambda _: _bt2_trace()._TraceConst)

    @property
    def cls(self) -> bt2_stream_class._StreamClassConst:
        return self._stream_class_pycls._create_from_ptr_and_get_ref(
            self._borrow_class_ptr(self._ptr)
        )

    @property
    def name(self) -> typing.Optional[str]:
        return native_bt.stream_get_name(self._ptr)

    @property
    def id(self) -> int:
        return native_bt.stream_get_id(self._ptr)

    @property
    def trace(self) -> "bt2_trace._TraceConst":
        return self._trace_pycls._create_from_ptr_and_get_ref(self._borrow_trace_ptr(self._ptr))


class _Stream(bt2_user_attrs._WithUserAttrs, _StreamConst):
    _borrow_class_ptr = staticmethod(native_bt.stream_borrow_class)

    @staticmethod
    def _borrow_user_attributes_ptr(ptr):
        return native_bt.stream_borrow_user_attributes(ptr)

    _borrow_trace_ptr = staticmethod(native_bt.stream_borrow_trace)
    _stream_class_pycls = bt2_stream_class._StreamClass
    _trace_pycls = property(lambda _: _bt2_trace()._Trace)

    def create_packet(self) -> bt2_packet._Packet:
        if not self.cls.supports_packets:
            raise ValueError("cannot create packet: stream class does not support packets")

        packet_ptr = native_bt.packet_create(self._ptr)

        if packet_ptr is None:
            raise bt2_error._MemoryError("cannot create packet object")

        return bt2_packet._Packet._create_from_ptr(packet_ptr)

    @staticmethod
    def _set_user_attributes_ptr(obj_ptr, value_ptr):
        native_bt.stream_set_user_attributes(obj_ptr, value_ptr)

    def _set_name(self, name):
        bt2_utils._check_str(name)
        native_bt.stream_set_name(self._ptr, name)
