# SPDX-License-Identifier: MIT
#
# Copyright (c) 2016-2017 Philippe Proulx <pproulx@efficios.com>


from bt2 import field as bt2_field
from bt2 import native_bt, typing_mod
from bt2 import object as bt2_object

typing = typing_mod._typing_mod

if typing.TYPE_CHECKING:
    from bt2 import stream as bt2_stream


def _bt2_stream():
    from bt2 import stream as bt2_stream

    return bt2_stream


class _PacketConst(bt2_object._SharedObject):
    @staticmethod
    def _get_ref(ptr):
        native_bt.packet_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.packet_put_ref(ptr)

    _borrow_stream_ptr = staticmethod(native_bt.packet_borrow_stream_const)
    _borrow_context_field_ptr = staticmethod(native_bt.packet_borrow_context_field_const)
    _stream_pycls = property(lambda _: _bt2_stream()._StreamConst)
    _create_field_from_ptr = staticmethod(bt2_field._create_field_from_const_ptr)

    @property
    def stream(self) -> "bt2_stream._StreamConst":
        return self._stream_pycls._create_from_ptr_and_get_ref(self._borrow_stream_ptr(self._ptr))

    @property
    def context_field(self) -> typing.Optional[bt2_field._StructureFieldConst]:
        field_ptr = self._borrow_context_field_ptr(self._ptr)

        if field_ptr is None:
            return

        return self._create_field_from_ptr(field_ptr, self._ptr, self._get_ref, self._put_ref)


class _Packet(_PacketConst):
    _borrow_stream_ptr = staticmethod(native_bt.packet_borrow_stream)
    _borrow_context_field_ptr = staticmethod(native_bt.packet_borrow_context_field)
    _stream_pycls = property(lambda _: _bt2_stream()._Stream)
    _create_field_from_ptr = staticmethod(bt2_field._create_field_from_ptr)
