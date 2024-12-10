# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>

from bt2 import event as bt2_event
from bt2 import utils as bt2_utils
from bt2 import object as bt2_object
from bt2 import packet as bt2_packet
from bt2 import stream as bt2_stream
from bt2 import native_bt, typing_mod
from bt2 import clock_snapshot as bt2_clock_snapshot

typing = typing_mod._typing_mod


def _create_from_ptr(ptr):
    msg_type = native_bt.message_get_type(ptr)
    return _MESSAGE_TYPE_TO_CLS[msg_type]._create_from_ptr(ptr)


class _MessageConst(bt2_object._SharedObject):
    @staticmethod
    def _get_ref(ptr):
        native_bt.message_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.message_put_ref(ptr)

    @staticmethod
    def _check_has_default_clock_class(clock_class):
        if clock_class is None:
            raise ValueError(
                "cannot get default clock snapshot: stream class has no default clock class"
            )


class _Message(_MessageConst):
    pass


class _MessageWithDefaultClockSnapshot:
    def _get_default_clock_snapshot(self, borrow_clock_snapshot_ptr):
        return bt2_clock_snapshot._ClockSnapshotConst._create_from_ptr_and_get_ref(
            borrow_clock_snapshot_ptr(self._ptr),
            self._ptr,
            self._get_ref,
            self._put_ref,
        )


class _EventMessageConst(_MessageConst, _MessageWithDefaultClockSnapshot):
    _borrow_default_clock_snapshot = staticmethod(
        native_bt.message_event_borrow_default_clock_snapshot_const
    )
    _borrow_event = staticmethod(native_bt.message_event_borrow_event_const)
    _event_pycls = property(lambda _: bt2_event._EventConst)

    @property
    def default_clock_snapshot(self) -> bt2_clock_snapshot._ClockSnapshotConst:
        self._check_has_default_clock_class(self.event.stream.cls.default_clock_class)
        return self._get_default_clock_snapshot(self._borrow_default_clock_snapshot)

    @property
    def _event(self):
        return self._event_pycls._create_from_ptr_and_get_ref(
            self._borrow_event(self._ptr), self._ptr, self._get_ref, self._put_ref
        )

    @property
    def event(self) -> bt2_event._EventConst:
        return self._event


class _EventMessage(_EventMessageConst, _Message):
    _borrow_event = staticmethod(native_bt.message_event_borrow_event)
    _stream_pycls = property(lambda _: bt2_stream._Stream)
    _event_pycls = property(lambda _: bt2_event._Event)

    @property
    def event(self) -> bt2_event._Event:
        return self._event


class _PacketMessageConst(_MessageConst, _MessageWithDefaultClockSnapshot):
    _packet_pycls = bt2_packet._PacketConst

    @property
    def default_clock_snapshot(self) -> bt2_clock_snapshot._ClockSnapshotConst:
        self._check_has_default_clock_class(self.packet.stream.cls.default_clock_class)
        return self._get_default_clock_snapshot(self._borrow_default_clock_snapshot_ptr)

    @property
    def packet(self) -> bt2_packet._PacketConst:
        return self._packet_pycls._create_from_ptr_and_get_ref(
            self._borrow_packet(self._ptr)
        )


class _PacketMessage(_PacketMessageConst, _Message):
    _packet_pycls = bt2_packet._Packet


class _PacketBeginningMessageConst(_PacketMessageConst):
    _borrow_packet = staticmethod(
        native_bt.message_packet_beginning_borrow_packet_const
    )
    _borrow_default_clock_snapshot_ptr = staticmethod(
        native_bt.message_packet_beginning_borrow_default_clock_snapshot_const
    )


class _PacketBeginningMessage(_PacketMessage):
    _borrow_packet = staticmethod(native_bt.message_packet_beginning_borrow_packet)


class _PacketEndMessageConst(_PacketMessageConst):
    _borrow_packet = staticmethod(native_bt.message_packet_end_borrow_packet_const)
    _borrow_default_clock_snapshot_ptr = staticmethod(
        native_bt.message_packet_end_borrow_default_clock_snapshot_const
    )


class _PacketEndMessage(_PacketMessage):
    _borrow_packet = staticmethod(native_bt.message_packet_end_borrow_packet)


class _StreamMessageConst(_MessageConst, _MessageWithDefaultClockSnapshot):
    _stream_pycls = property(lambda _: bt2_stream._StreamConst)

    @property
    def stream(self) -> bt2_stream._StreamConst:
        return self._stream_pycls._create_from_ptr_and_get_ref(
            self._borrow_stream_ptr(self._ptr)
        )

    @property
    def default_clock_snapshot(self) -> bt2_clock_snapshot._ClockSnapshotConst:
        self._check_has_default_clock_class(self.stream.cls.default_clock_class)

        status, snapshot_ptr = self._borrow_default_clock_snapshot_ptr(self._ptr)

        if status == native_bt.MESSAGE_STREAM_CLOCK_SNAPSHOT_STATE_UNKNOWN:
            return bt2_clock_snapshot._UnknownClockSnapshot()

        return bt2_clock_snapshot._ClockSnapshotConst._create_from_ptr_and_get_ref(
            snapshot_ptr, self._ptr, self._get_ref, self._put_ref
        )


class _StreamMessage(_StreamMessageConst, _Message):
    def _set_default_clock_snapshot(self, raw_value):
        bt2_utils._check_uint64(raw_value)
        self._bt_set_default_clock_snapshot(self._ptr, raw_value)

    _stream_pycls = property(lambda _: bt2_stream._Stream)


class _StreamBeginningMessageConst(_StreamMessageConst):
    _borrow_stream_ptr = staticmethod(
        native_bt.message_stream_beginning_borrow_stream_const
    )
    _borrow_default_clock_snapshot_ptr = staticmethod(
        native_bt.message_stream_beginning_borrow_default_clock_snapshot_const
    )


class _StreamBeginningMessage(_StreamMessage):
    _borrow_stream_ptr = staticmethod(native_bt.message_stream_beginning_borrow_stream)
    _bt_set_default_clock_snapshot = staticmethod(
        native_bt.message_stream_beginning_set_default_clock_snapshot
    )


class _StreamEndMessageConst(_StreamMessageConst):
    _borrow_stream_ptr = staticmethod(native_bt.message_stream_end_borrow_stream_const)
    _borrow_default_clock_snapshot_ptr = staticmethod(
        native_bt.message_stream_end_borrow_default_clock_snapshot_const
    )


class _StreamEndMessage(_StreamMessage):
    _borrow_stream_ptr = staticmethod(native_bt.message_stream_end_borrow_stream)
    _bt_set_default_clock_snapshot = staticmethod(
        native_bt.message_stream_end_set_default_clock_snapshot
    )


class _MessageIteratorInactivityMessageConst(
    _MessageConst, _MessageWithDefaultClockSnapshot
):
    _borrow_clock_snapshot_ptr = staticmethod(
        native_bt.message_message_iterator_inactivity_borrow_clock_snapshot_const
    )

    @property
    def clock_snapshot(self) -> bt2_clock_snapshot._ClockSnapshotConst:
        # This kind of message always has a clock class: no
        # need to call self._check_has_default_clock_class() here.
        return self._get_default_clock_snapshot(self._borrow_clock_snapshot_ptr)


class _MessageIteratorInactivityMessage(
    _MessageIteratorInactivityMessageConst, _Message
):
    pass


class _DiscardedMessageConst(_MessageConst, _MessageWithDefaultClockSnapshot):
    _stream_pycls = property(lambda _: bt2_stream._StreamConst)

    @property
    def stream(self) -> bt2_stream._StreamConst:
        return self._stream_pycls._create_from_ptr_and_get_ref(
            self._borrow_stream_ptr(self._ptr)
        )

    @property
    def count(self) -> typing.Optional[int]:
        avail, count = self._get_count(self._ptr)
        if avail is native_bt.PROPERTY_AVAILABILITY_AVAILABLE:
            return count

    def _check_has_default_clock_snapshots(self):
        if not self._has_default_clock_snapshots:
            raise ValueError(
                "cannot get default clock snapshot: such a message has no clock snapshots for this stream class"
            )

    @property
    def beginning_default_clock_snapshot(
        self,
    ) -> bt2_clock_snapshot._ClockSnapshotConst:
        self._check_has_default_clock_snapshots()
        return self._get_default_clock_snapshot(
            self._borrow_beginning_clock_snapshot_ptr
        )

    @property
    def end_default_clock_snapshot(self) -> bt2_clock_snapshot._ClockSnapshotConst:
        self._check_has_default_clock_snapshots()
        return self._get_default_clock_snapshot(self._borrow_end_clock_snapshot_ptr)


class _DiscardedMessage(_DiscardedMessageConst, _Message):
    _stream_pycls = property(lambda _: bt2_stream._Stream)

    def _set_count(self, count):
        bt2_utils._check_uint64(count)

        if count == 0:
            raise ValueError("discarded {} count is 0".format(self._item_name))

        self._bt_set_count(self._ptr, count)


class _DiscardedEventsMessageConst(_DiscardedMessageConst):
    _borrow_stream_ptr = staticmethod(
        native_bt.message_discarded_events_borrow_stream_const
    )
    _get_count = staticmethod(native_bt.message_discarded_events_get_count)
    _borrow_beginning_clock_snapshot_ptr = staticmethod(
        native_bt.message_discarded_events_borrow_beginning_default_clock_snapshot_const
    )
    _borrow_end_clock_snapshot_ptr = staticmethod(
        native_bt.message_discarded_events_borrow_end_default_clock_snapshot_const
    )

    @property
    def _has_default_clock_snapshots(self):
        return self.stream.cls.discarded_events_have_default_clock_snapshots


class _DiscardedEventsMessage(_DiscardedEventsMessageConst, _DiscardedMessage):
    _borrow_stream_ptr = staticmethod(native_bt.message_discarded_events_borrow_stream)
    _bt_set_count = staticmethod(native_bt.message_discarded_events_set_count)
    _item_name = "event"


class _DiscardedPacketsMessageConst(_DiscardedMessageConst):
    _borrow_stream_ptr = staticmethod(
        native_bt.message_discarded_packets_borrow_stream_const
    )
    _get_count = staticmethod(native_bt.message_discarded_packets_get_count)
    _borrow_beginning_clock_snapshot_ptr = staticmethod(
        native_bt.message_discarded_packets_borrow_beginning_default_clock_snapshot_const
    )
    _borrow_end_clock_snapshot_ptr = staticmethod(
        native_bt.message_discarded_packets_borrow_end_default_clock_snapshot_const
    )

    @property
    def _has_default_clock_snapshots(self):
        return self.stream.cls.discarded_packets_have_default_clock_snapshots


class _DiscardedPacketsMessage(_DiscardedPacketsMessageConst, _DiscardedMessage):
    _borrow_stream_ptr = staticmethod(native_bt.message_discarded_packets_borrow_stream)
    _bt_set_count = staticmethod(native_bt.message_discarded_packets_set_count)
    _item_name = "packet"


_MESSAGE_TYPE_TO_CLS = {
    native_bt.MESSAGE_TYPE_EVENT: _EventMessage,
    native_bt.MESSAGE_TYPE_MESSAGE_ITERATOR_INACTIVITY: _MessageIteratorInactivityMessage,
    native_bt.MESSAGE_TYPE_STREAM_BEGINNING: _StreamBeginningMessage,
    native_bt.MESSAGE_TYPE_STREAM_END: _StreamEndMessage,
    native_bt.MESSAGE_TYPE_PACKET_BEGINNING: _PacketBeginningMessage,
    native_bt.MESSAGE_TYPE_PACKET_END: _PacketEndMessage,
    native_bt.MESSAGE_TYPE_DISCARDED_EVENTS: _DiscardedEventsMessage,
    native_bt.MESSAGE_TYPE_DISCARDED_PACKETS: _DiscardedPacketsMessage,
}

_MESSAGE_TYPE_TO_CLS = {
    native_bt.MESSAGE_TYPE_EVENT: _EventMessageConst,
    native_bt.MESSAGE_TYPE_MESSAGE_ITERATOR_INACTIVITY: _MessageIteratorInactivityMessageConst,
    native_bt.MESSAGE_TYPE_STREAM_BEGINNING: _StreamBeginningMessageConst,
    native_bt.MESSAGE_TYPE_STREAM_END: _StreamEndMessageConst,
    native_bt.MESSAGE_TYPE_PACKET_BEGINNING: _PacketBeginningMessageConst,
    native_bt.MESSAGE_TYPE_PACKET_END: _PacketEndMessageConst,
    native_bt.MESSAGE_TYPE_DISCARDED_EVENTS: _DiscardedEventsMessageConst,
    native_bt.MESSAGE_TYPE_DISCARDED_PACKETS: _DiscardedPacketsMessageConst,
}
