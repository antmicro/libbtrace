# SPDX-License-Identifier: MIT
#
# Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>

from bt2 import native_bt
from bt2 import object as bt2_object
from bt2 import utils as bt2_utils
from bt2 import message as bt2_message
import collections.abc
from bt2 import stream as bt2_stream
from bt2 import event_class as bt2_event_class
from bt2 import packet as bt2_packet
from bt2 import port as bt2_port
from bt2 import clock_class as bt2_clock_class
import bt2


class _MessageIterator(collections.abc.Iterator):
    def __next__(self):
        raise NotImplementedError


class _UserComponentInputPortMessageIterator(
    bt2_object._SharedObject, _MessageIterator
):
    @staticmethod
    def _get_ref(ptr):
        native_bt.message_iterator_get_ref(ptr)

    @staticmethod
    def _put_ref(ptr):
        native_bt.message_iterator_put_ref(ptr)

    def __init__(self, ptr):
        self._current_msgs = []
        self._at = 0
        super().__init__(ptr)

    def __next__(self):
        if len(self._current_msgs) == self._at:
            status, msgs = native_bt.bt2_self_component_port_input_get_msg_range(
                self._ptr
            )
            bt2_utils._handle_func_status(
                status, "unexpected error: cannot advance the message iterator"
            )
            self._current_msgs = msgs
            self._at = 0

        msg_ptr = self._current_msgs[self._at]
        self._at += 1

        return bt2_message._create_from_ptr(msg_ptr)

    def can_seek_beginning(self):
        (status, res) = native_bt.message_iterator_can_seek_beginning(self._ptr)
        bt2_utils._handle_func_status(
            status,
            "cannot check whether or not message iterator can seek its beginning",
        )
        return res != 0

    def seek_beginning(self):
        # Forget about buffered messages, they won't be valid after seeking.
        self._current_msgs.clear()
        self._at = 0

        status = native_bt.message_iterator_seek_beginning(self._ptr)
        bt2_utils._handle_func_status(status, "cannot seek message iterator beginning")

    def can_seek_ns_from_origin(self, ns_from_origin):
        bt2_utils._check_int64(ns_from_origin)
        (status, res) = native_bt.message_iterator_can_seek_ns_from_origin(
            self._ptr, ns_from_origin
        )
        bt2_utils._handle_func_status(
            status,
            "cannot check whether or not message iterator can seek given ns from origin",
        )
        return res != 0

    def seek_ns_from_origin(self, ns_from_origin):
        bt2_utils._check_int64(ns_from_origin)

        # Forget about buffered messages, they won't be valid after seeking.
        self._current_msgs.clear()
        self._at = 0

        status = native_bt.message_iterator_seek_ns_from_origin(
            self._ptr, ns_from_origin
        )
        bt2_utils._handle_func_status(
            status, "message iterator cannot seek given ns from origin"
        )

    @property
    def can_seek_forward(self):
        return native_bt.message_iterator_can_seek_forward(self._ptr)


class _MessageIteratorConfiguration:
    def __init__(self, ptr):
        self._ptr = ptr

    def can_seek_forward(self, value):
        bt2_utils._check_bool(value)
        native_bt.self_message_iterator_configuration_set_can_seek_forward(
            self._ptr, value
        )

    can_seek_forward = property(fset=can_seek_forward)


# This is extended by the user to implement component classes in Python.  It
# is created for a given output port when an input port message iterator is
# created on the input port on the other side of the connection.
#
# Its purpose is to feed the messages that should go out through this output
# port.
class _UserMessageIterator(_MessageIterator):
    def __new__(cls, ptr):
        # User iterator objects are always created by the native side,
        # that is, never instantiated directly by Python code.
        #
        # The native code calls this, then manually calls
        # self.__init__() without the `ptr` argument. The user has
        # access to self.component during this call, thanks to this
        # self._bt_ptr argument being set.
        #
        # self._bt_ptr is NOT owned by this object here, so there's nothing
        # to do in __del__().
        self = super().__new__(cls)
        self._bt_ptr = ptr
        return self

    def _bt_init_from_native(self, config_ptr, self_output_port_ptr):
        self_output_port = bt2_port._create_self_from_ptr_and_get_ref(
            self_output_port_ptr, native_bt.PORT_TYPE_OUTPUT
        )
        config = _MessageIteratorConfiguration(config_ptr)
        self.__init__(config, self_output_port)

    def __init__(self, config, self_output_port):
        pass

    @property
    def _component(self):
        return native_bt.bt2_get_user_component_from_user_msg_iter(self._bt_ptr)

    @property
    def _port(self):
        port_ptr = native_bt.self_message_iterator_borrow_port(self._bt_ptr)
        assert port_ptr is not None
        return bt2_port._create_self_from_ptr_and_get_ref(
            port_ptr, native_bt.PORT_TYPE_OUTPUT
        )

    @property
    def addr(self):
        return int(self._bt_ptr)

    @property
    def _is_interrupted(self):
        return bool(native_bt.self_message_iterator_is_interrupted(self._bt_ptr))

    def _user_finalize(self):
        pass

    def __next__(self):
        raise bt2.Stop

    def _bt_next_from_native(self):
        # this can raise anything: it's catched by the native part
        try:
            msg = next(self)
        except StopIteration:
            raise bt2.Stop
        except Exception:
            raise

        bt2_utils._check_type(msg, bt2_message._MessageConst)

        # The reference we return will be given to the message array.
        # However, the `msg` Python object may stay alive, if the user has kept
        # a reference to it.  Acquire a new reference to account for that.
        msg._get_ref(msg._ptr)
        return int(msg._ptr)

    def _bt_can_seek_beginning_from_native(self):
        # Here, we mimic the behavior of the C API:
        #
        # - If the iterator has a _user_can_seek_beginning method,
        #   read it and use that result.
        # - Otherwise, the presence or absence of a `_user_seek_beginning`
        #   method indicates whether the iterator can seek beginning.
        if hasattr(self, "_user_can_seek_beginning"):
            can_seek_beginning = self._user_can_seek_beginning()
            bt2_utils._check_bool(can_seek_beginning)
            return can_seek_beginning
        else:
            return hasattr(self, "_user_seek_beginning")

    def _bt_seek_beginning_from_native(self):
        self._user_seek_beginning()

    def _bt_can_seek_ns_from_origin_from_native(self, ns_from_origin):
        # Return whether the iterator can seek ns from origin using the
        # user-implemented seek_ns_from_origin method.  We mimic the behavior
        # of the C API:
        #
        # - If the iterator has a _user_can_seek_ns_from_origin method,
        #   call it and use its return value.
        # - Otherwise, if there is a `_user_seek_ns_from_origin` method,
        #   we presume it's possible.

        if hasattr(self, "_user_can_seek_ns_from_origin"):
            can_seek_ns_from_origin = self._user_can_seek_ns_from_origin(ns_from_origin)
            bt2_utils._check_bool(can_seek_ns_from_origin)
            return can_seek_ns_from_origin
        else:
            return hasattr(self, "_user_seek_ns_from_origin")

    def _bt_seek_ns_from_origin_from_native(self, ns_from_origin):
        self._user_seek_ns_from_origin(ns_from_origin)

    def _create_message_iterator(self, input_port):
        bt2_utils._check_type(input_port, bt2_port._UserComponentInputPort)

        if not input_port.is_connected:
            raise ValueError("input port is not connected")

        (
            status,
            msg_iter_ptr,
        ) = native_bt.bt2_message_iterator_create_from_message_iterator(
            self._bt_ptr, input_port._ptr
        )
        bt2_utils._handle_func_status(status, "cannot create message iterator object")
        assert msg_iter_ptr is not None

        return _UserComponentInputPortMessageIterator(msg_iter_ptr)

    def _create_event_message(self, event_class, parent, default_clock_snapshot=None):
        bt2_utils._check_type(event_class, bt2_event_class._EventClass)

        if event_class.stream_class.supports_packets:
            bt2_utils._check_type(parent, bt2_packet._Packet)
        else:
            bt2_utils._check_type(parent, bt2_stream._Stream)

        if default_clock_snapshot is not None:
            if event_class.stream_class.default_clock_class is None:
                raise ValueError(
                    "event messages in this stream must not have a default clock snapshot"
                )

            bt2_utils._check_uint64(default_clock_snapshot)

            if event_class.stream_class.supports_packets:
                ptr = native_bt.message_event_create_with_packet_and_default_clock_snapshot(
                    self._bt_ptr, event_class._ptr, parent._ptr, default_clock_snapshot
                )
            else:
                ptr = native_bt.message_event_create_with_default_clock_snapshot(
                    self._bt_ptr, event_class._ptr, parent._ptr, default_clock_snapshot
                )
        else:
            if event_class.stream_class.default_clock_class is not None:
                raise ValueError(
                    "event messages in this stream must have a default clock snapshot"
                )

            if event_class.stream_class.supports_packets:
                ptr = native_bt.message_event_create_with_packet(
                    self._bt_ptr, event_class._ptr, parent._ptr
                )
            else:
                ptr = native_bt.message_event_create(
                    self._bt_ptr, event_class._ptr, parent._ptr
                )

        if ptr is None:
            raise bt2._MemoryError("cannot create event message object")

        return bt2_message._EventMessage(ptr)

    def _create_message_iterator_inactivity_message(self, clock_class, clock_snapshot):
        bt2_utils._check_type(clock_class, bt2_clock_class._ClockClass)
        ptr = native_bt.message_message_iterator_inactivity_create(
            self._bt_ptr, clock_class._ptr, clock_snapshot
        )

        if ptr is None:
            raise bt2._MemoryError("cannot create inactivity message object")

        return bt2_message._MessageIteratorInactivityMessage(ptr)

    def _create_stream_beginning_message(self, stream, default_clock_snapshot=None):
        bt2_utils._check_type(stream, bt2_stream._Stream)

        ptr = native_bt.message_stream_beginning_create(self._bt_ptr, stream._ptr)
        if ptr is None:
            raise bt2._MemoryError("cannot create stream beginning message object")

        msg = bt2_message._StreamBeginningMessage(ptr)

        if default_clock_snapshot is not None:
            msg._default_clock_snapshot = default_clock_snapshot

        return msg

    def _create_stream_end_message(self, stream, default_clock_snapshot=None):
        bt2_utils._check_type(stream, bt2_stream._Stream)

        ptr = native_bt.message_stream_end_create(self._bt_ptr, stream._ptr)
        if ptr is None:
            raise bt2._MemoryError("cannot create stream end message object")

        msg = bt2_message._StreamEndMessage(ptr)

        if default_clock_snapshot is not None:
            msg._default_clock_snapshot = default_clock_snapshot

        return msg

    def _create_packet_beginning_message(self, packet, default_clock_snapshot=None):
        bt2_utils._check_type(packet, bt2_packet._Packet)

        if packet.stream.cls.packets_have_beginning_default_clock_snapshot:
            if default_clock_snapshot is None:
                raise ValueError(
                    "packet beginning messages in this stream must have a default clock snapshot"
                )

            bt2_utils._check_uint64(default_clock_snapshot)
            ptr = native_bt.message_packet_beginning_create_with_default_clock_snapshot(
                self._bt_ptr, packet._ptr, default_clock_snapshot
            )
        else:
            if default_clock_snapshot is not None:
                raise ValueError(
                    "packet beginning messages in this stream must not have a default clock snapshot"
                )

            ptr = native_bt.message_packet_beginning_create(self._bt_ptr, packet._ptr)

        if ptr is None:
            raise bt2._MemoryError("cannot create packet beginning message object")

        return bt2_message._PacketBeginningMessage(ptr)

    def _create_packet_end_message(self, packet, default_clock_snapshot=None):
        bt2_utils._check_type(packet, bt2_packet._Packet)

        if packet.stream.cls.packets_have_end_default_clock_snapshot:
            if default_clock_snapshot is None:
                raise ValueError(
                    "packet end messages in this stream must have a default clock snapshot"
                )

            bt2_utils._check_uint64(default_clock_snapshot)
            ptr = native_bt.message_packet_end_create_with_default_clock_snapshot(
                self._bt_ptr, packet._ptr, default_clock_snapshot
            )
        else:
            if default_clock_snapshot is not None:
                raise ValueError(
                    "packet end messages in this stream must not have a default clock snapshot"
                )

            ptr = native_bt.message_packet_end_create(self._bt_ptr, packet._ptr)

        if ptr is None:
            raise bt2._MemoryError("cannot create packet end message object")

        return bt2_message._PacketEndMessage(ptr)

    def _create_discarded_events_message(
        self, stream, count=None, beg_clock_snapshot=None, end_clock_snapshot=None
    ):
        bt2_utils._check_type(stream, bt2_stream._Stream)

        if not stream.cls.supports_discarded_events:
            raise ValueError("stream class does not support discarded events")

        if stream.cls.discarded_events_have_default_clock_snapshots:
            if beg_clock_snapshot is None or end_clock_snapshot is None:
                raise ValueError(
                    "discarded events have default clock snapshots for this stream class"
                )

            bt2_utils._check_uint64(beg_clock_snapshot)
            bt2_utils._check_uint64(end_clock_snapshot)

            if beg_clock_snapshot > end_clock_snapshot:
                raise ValueError(
                    "beginning default clock snapshot value ({}) is greater than end default clock snapshot value ({})".format(
                        beg_clock_snapshot, end_clock_snapshot
                    )
                )

            ptr = (
                native_bt.message_discarded_events_create_with_default_clock_snapshots(
                    self._bt_ptr, stream._ptr, beg_clock_snapshot, end_clock_snapshot
                )
            )
        else:
            if beg_clock_snapshot is not None or end_clock_snapshot is not None:
                raise ValueError(
                    "discarded events have no default clock snapshots for this stream class"
                )

            ptr = native_bt.message_discarded_events_create(self._bt_ptr, stream._ptr)

        if ptr is None:
            raise bt2._MemoryError("cannot discarded events message object")

        msg = bt2_message._DiscardedEventsMessage(ptr)

        if count is not None:
            msg._count = count

        return msg

    def _create_discarded_packets_message(
        self, stream, count=None, beg_clock_snapshot=None, end_clock_snapshot=None
    ):
        bt2_utils._check_type(stream, bt2_stream._Stream)

        if not stream.cls.supports_discarded_packets:
            raise ValueError("stream class does not support discarded packets")

        if stream.cls.discarded_packets_have_default_clock_snapshots:
            if beg_clock_snapshot is None or end_clock_snapshot is None:
                raise ValueError(
                    "discarded packets have default clock snapshots for this stream class"
                )

            bt2_utils._check_uint64(beg_clock_snapshot)
            bt2_utils._check_uint64(end_clock_snapshot)

            if beg_clock_snapshot > end_clock_snapshot:
                raise ValueError(
                    "beginning default clock snapshot value ({}) is greater than end default clock snapshot value ({})".format(
                        beg_clock_snapshot, end_clock_snapshot
                    )
                )

            ptr = (
                native_bt.message_discarded_packets_create_with_default_clock_snapshots(
                    self._bt_ptr, stream._ptr, beg_clock_snapshot, end_clock_snapshot
                )
            )
        else:
            if beg_clock_snapshot is not None or end_clock_snapshot is not None:
                raise ValueError(
                    "discarded packets have no default clock snapshots for this stream class"
                )

            ptr = native_bt.message_discarded_packets_create(self._bt_ptr, stream._ptr)

        if ptr is None:
            raise bt2._MemoryError("cannot discarded packets message object")

        msg = bt2_message._DiscardedPacketsMessage(ptr)

        if count is not None:
            msg._count = count

        return msg
