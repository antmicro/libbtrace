/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2019 EfficiOS Inc. and Linux Foundation
 */

#ifndef BABELTRACE2_TRACE_IR_EVENT_H
#define BABELTRACE2_TRACE_IR_EVENT_H

/* IWYU pragma: private, include <babeltrace2/babeltrace.h> */

#ifndef __BT_IN_BABELTRACE_H
# error "Please include <babeltrace2/babeltrace.h> instead."
#endif

#include <babeltrace2/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@defgroup api-tir-ev Event
@ingroup api-tir

@brief
    Trace event.

An <strong><em>event</em></strong> represents a trace event record.

An event is an instance of an \bt_ev_cls:

@image html trace-structure.png

In the illustration above, notice that:

- A \bt_stream is a conceptual \ref api-msg-seq "sequence of messages",
  some of which are \bt_p_ev_msg.
- An event message contains an \bt_ev.
- An event is an instance of an event class.
- The \ref api-tir-ev-prop-payload "payload field" of an event is an
  instance of the \ref api-tir-ev-cls-prop-p-fc "payload field class"
  which an event class contains.

Borrow the class of an event with bt_event_borrow_class() and
bt_event_borrow_class_const().

An event is a \ref api-tir "trace IR" data object.

You cannot directly create an event: there's no
<code>bt_event_create()</code> function. The \bt_name library
creates an event within an \bt_ev_msg from an \bt_ev_cls.
Therefore, to fill the fields of an event, you must first
borrow the event from an event message with
bt_message_event_borrow_event().

An event is a \ref api-fund-unique-object "unique object": it belongs to
an \bt_ev_msg.

Some library functions \ref api-fund-freezing "freeze" events on
success. The documentation of those functions indicate this
postcondition.

The type of an event is #bt_event.

An event conceptually belongs to a \bt_stream. Borrow the stream of an
event with bt_event_borrow_stream() and bt_event_borrow_stream_const().

If the stream class of the event
\ref api-tir-stream-cls-prop-supports-pkt "supports packets",
the event also belongs to a \bt_pkt. In that case, borrow the packet of
an event with bt_event_borrow_packet() and
bt_event_borrow_packet_const().

Because a stream or a packet could contain millions of events, there are
no actual links from a stream or from a packet to its events.

<h1>Properties</h1>

An event has the following properties:

<dl>
  <dt>\anchor api-tir-ev-prop-payload Payload field</dt>
  <dd>
    Payload \bt_field of the event.

    The payload of an event contains its main trace data.

    The \ref api-tir-fc "class" of the payload field of an event is set
    at the level of the \ref api-tir-ev-cls "class" of the event. See
    bt_event_class_set_payload_field_class(),
    bt_event_class_borrow_payload_field_class(), and
    bt_event_class_borrow_payload_field_class_const().

    Use bt_event_borrow_payload_field() and
    bt_event_borrow_payload_field_const().
  </dd>

  <dt>\anchor api-tir-ev-prop-spec-ctx Specific context field</dt>
  <dd>
    Specific context \bt_field of the event.

    The specific context of an event contains
    any contextual data of which the layout is specific to the
    \ref api-tir-ev-cls "class" of the event and which does not belong
    to the payload.

    The \ref api-tir-fc "class" of the specific context field of an
    event is set at the level of the \ref api-tir-ev-cls "class" of
    the event. See bt_event_class_set_specific_context_field_class()
    bt_event_class_borrow_specific_context_field_class(), and
    bt_event_class_borrow_specific_context_field_class_const()

    Use bt_event_borrow_specific_context_field() and
    bt_event_borrow_specific_context_field_const().
  </dd>

  <dt>\anchor api-tir-ev-prop-common-ctx Common context field</dt>
  <dd>
    Common context \bt_field of the event.

    The common context of an event contains contextual data of which the
    layout is common to all the \bt_p_ev_cls of the
    \ref api-tir-stream-cls "stream class" of the event.

    The \ref api-tir-fc "class" of the common context field of an event
    is set at the level of the \bt_stream_cls of the event. See
    bt_stream_class_set_event_common_context_field_class()
    bt_stream_class_borrow_event_common_context_field_class(),
    and bt_stream_class_borrow_event_common_context_field_class_const().

    Use bt_event_borrow_common_context_field() and
    bt_event_borrow_common_context_field_const().
  </dd>
</dl>
*/

/*! @{ */

/*!
@name Type
@{

@typedef struct bt_event bt_event;

@brief
    Event.

@}
*/

/*!
@name Class access
@{
*/

/*!
@brief
    Borrows the \ref api-tir-ev-cls "class" of the event \bt_p{event}.

@param[in] event
    Event of which to borrow the class.

@returns
    \em Borrowed reference of the class of \bt_p{event}.

@bt_pre_not_null{event}

@sa bt_event_borrow_class_const() &mdash;
    \c const version of this function.
*/
extern bt_event_class *bt_event_borrow_class(bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the \ref api-tir-ev-cls "class" of the event \bt_p{event}
    (\c const version).

See bt_event_borrow_class().
*/
extern const bt_event_class *bt_event_borrow_class_const(
		const bt_event *event) __BT_NOEXCEPT;

/*! @} */

/*!
@name Stream access
@{
*/

/*!
@brief
    Borrows the \bt_stream conceptually containing the event
    \bt_p{event}.

@param[in] event
    Event of which to borrow the stream conceptually containing it.

@returns
    \em Borrowed reference of the stream conceptually containing
    \bt_p{event}.

@bt_pre_not_null{event}

@sa bt_event_borrow_stream_const() &mdash;
    \c const version of this function.
*/
extern bt_stream *bt_event_borrow_stream(bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the \bt_stream conceptually containing the event
    \bt_p{event} (\c const version).

See bt_event_borrow_stream().
*/
extern const bt_stream *bt_event_borrow_stream_const(
		const bt_event *event) __BT_NOEXCEPT;

/*! @} */

/*!
@name Packet access
@{
*/

/*!
@brief
    Borrows the \bt_pkt conceptually containing the event
    \bt_p{event}.

@attention
    Only call this function if bt_stream_class_supports_packets()
    returns #BT_TRUE for the \bt_stream_cls of \bt_p{event}.

@param[in] event
    Event of which to borrow the packet conceptually containing it.

@returns
    \em Borrowed reference of the packet conceptually containing
    \bt_p{event}.

@bt_pre_not_null{event}

@sa bt_event_borrow_packet_const() &mdash;
    \c const version of this function.
*/
extern bt_packet *bt_event_borrow_packet(bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the \bt_pkt conceptually containing the event
    \bt_p{event} (\c const version).

See bt_event_borrow_packet().
*/
extern const bt_packet *bt_event_borrow_packet_const(
		const bt_event *event) __BT_NOEXCEPT;

/*! @} */

/*!
@name Properties
@{
*/

/*!
@brief
    Borrows the payload \bt_field of the event \bt_p{event}.

See the \ref api-tir-ev-prop-payload "payload field" property.

@param[in] event
    Event of which to borrow the payload field.

@returns
    \em Borrowed reference of the payload field of \bt_p{event},
    or \c NULL if none.

@bt_pre_not_null{event}

@sa bt_event_borrow_payload_field_const() &mdash;
    \c const version of this function.
*/
extern bt_field *bt_event_borrow_payload_field(bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the payload \bt_field of the event \bt_p{event}
    (\c const version).

See bt_event_borrow_payload_field().
*/
extern const bt_field *bt_event_borrow_payload_field_const(
		const bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the specific context \bt_field of the event \bt_p{event}.

See the \ref api-tir-ev-prop-spec-ctx "specific context field" property.

@param[in] event
    Event of which to borrow the specific context field.

@returns
    \em Borrowed reference of the specific context field of
    \bt_p{event}, or \c NULL if none.

@bt_pre_not_null{event}

@sa bt_event_borrow_specific_context_field_const() &mdash;
    \c const version of this function.
*/
extern bt_field *
bt_event_borrow_specific_context_field(bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the specific context \bt_field of the event \bt_p{event}
    (\c const version).

See bt_event_borrow_specific_context_field().
*/
extern const bt_field *bt_event_borrow_specific_context_field_const(
		const bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the common context \bt_field of the event \bt_p{event}.

See the \ref api-tir-ev-prop-common-ctx "common context field" property.

@param[in] event
    Event of which to borrow the common context field.

@returns
    \em Borrowed reference of the common context field of
    \bt_p{event}, or \c NULL if none.

@bt_pre_not_null{event}

@sa bt_event_borrow_specific_context_field_const() &mdash;
    \c const version of this function.
*/
extern bt_field *
bt_event_borrow_common_context_field(bt_event *event) __BT_NOEXCEPT;

/*!
@brief
    Borrows the common context \bt_field of the event \bt_p{event}
    (\c const version).

See bt_event_borrow_common_context_field().
*/
extern const bt_field *bt_event_borrow_common_context_field_const(
		const bt_event *event) __BT_NOEXCEPT;

/*! @} */

/*! @} */

#ifdef __cplusplus
}
#endif

#endif /* BABELTRACE2_TRACE_IR_EVENT_H */
