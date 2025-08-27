# SPDX-License-Identifier: MIT
#
# Copyright (c) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>

import collections
import enum

from bt2 import native_bt, typing_mod
from bt2 import object as bt2_object

typing = typing_mod._typing_mod


class FieldPathScope(enum.Enum):
    PACKET_CONTEXT = native_bt.FIELD_PATH_SCOPE_PACKET_CONTEXT
    EVENT_COMMON_CONTEXT = native_bt.FIELD_PATH_SCOPE_EVENT_COMMON_CONTEXT
    EVENT_SPECIFIC_CONTEXT = native_bt.FIELD_PATH_SCOPE_EVENT_SPECIFIC_CONTEXT
    EVENT_PAYLOAD = native_bt.FIELD_PATH_SCOPE_EVENT_PAYLOAD


class _FieldPathItem:
    pass


class _IndexFieldPathItem(_FieldPathItem):
    def __init__(self, index):
        self._index = index

    @property
    def index(self) -> int:
        return self._index


class _CurrentArrayElementFieldPathItem(_FieldPathItem):
    pass


class _CurrentOptionContentFieldPathItem(_FieldPathItem):
    pass


class _FieldPathConst(bt2_object._SharedObject, collections.abc.Iterable):
    @staticmethod
    def _get_ref(ptr):
        native_bt.field_path_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.field_path_put_ref(ptr)

    @property
    def root_scope(self) -> FieldPathScope:
        return FieldPathScope(native_bt.field_path_get_root_scope(self._ptr))

    def __len__(self) -> int:
        return native_bt.field_path_get_item_count(self._ptr)

    def __iter__(
        self,
    ) -> typing.Iterator[_FieldPathItem]:
        for idx in range(len(self)):
            item_ptr = native_bt.field_path_borrow_item_by_index_const(self._ptr, idx)
            item_type = native_bt.field_path_item_get_type(item_ptr)
            if item_type == native_bt.FIELD_PATH_ITEM_TYPE_INDEX:
                yield _IndexFieldPathItem(native_bt.field_path_item_index_get_index(item_ptr))
            elif item_type == native_bt.FIELD_PATH_ITEM_TYPE_CURRENT_ARRAY_ELEMENT:
                yield _CurrentArrayElementFieldPathItem()
            elif item_type == native_bt.FIELD_PATH_ITEM_TYPE_CURRENT_OPTION_CONTENT:
                yield _CurrentOptionContentFieldPathItem()
            else:
                assert False
