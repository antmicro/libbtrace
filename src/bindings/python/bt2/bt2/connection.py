# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>

from bt2 import native_bt
from bt2 import object as bt2_object
from bt2 import port as bt2_port


class _ConnectionConst(bt2_object._SharedObject):
    @staticmethod
    def _get_ref(ptr):
        native_bt.connection_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.connection_put_ref(ptr)

    @property
    def downstream_port(self) -> bt2_port._InputPortConst:
        return bt2_port._create_from_const_ptr_and_get_ref(
            native_bt.connection_borrow_downstream_port_const(self._ptr),
            native_bt.PORT_TYPE_INPUT,
        )

    @property
    def upstream_port(self) -> bt2_port._OutputPortConst:
        return bt2_port._create_from_const_ptr_and_get_ref(
            native_bt.connection_borrow_upstream_port_const(self._ptr),
            native_bt.PORT_TYPE_OUTPUT,
        )
