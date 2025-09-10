/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Simon Marchi <simon.marchi@efficios.com>
 * Copyright (c) 2015-2024 Philippe Proulx <pproulx@efficios.com>
 */

#include <algorithm>

#include "common/assert.h"
#include "common/common.h"
#include "cpp-common/bt2/message.hpp"
#include "cpp-common/bt2/trace-ir.hpp"
#include "cpp-common/bt2c/aliases.hpp"
#include "cpp-common/bt2c/call.hpp"
#include "cpp-common/bt2c/fmt.hpp" /* IWYU pragma: keep */
#include "cpp-common/vendor/fmt/format.h"

#include "item-seq/item.hpp"
#include "metadata/ctf-ir.hpp"
#include "msg-iter.hpp"

namespace ctf {
namespace src {

using namespace bt2c::literals::datalen;

MsgIter::MsgIter(const bt2::SelfMessageIterator selfMsgIter, const ctf::src::TraceCls& traceCls,
                 bt2s::optional<bt2c::Uuid> expectedMetadataStreamUuid, const bt2::Stream stream,
                 Medium::UP medium, const MsgIterQuirks& quirks, const bt2c::Logger& parentLogger) :
    _mLogger {parentLogger, "PLUGIN/CTF/MSG-ITER"}, _mSelfMsgIter {selfMsgIter}, _mStream {stream},
    _mExpectedMetadataStreamUuid {std::move(expectedMetadataStreamUuid)}, _mQuirks {quirks},
    _mItemSeqIter {std::move(medium), traceCls, _mLogger}, _mUnicodeConv {_mLogger},
    _mLoggingVisitor {"Handling item", _mLogger}, _mShouldWork {true}, _mCurStreamClassId {0}
{
    BT_CPPLOGD("Created CTF plugin message iterator: "
               "addr={}, trace-cls-addr={}, log-level={}",
               fmt::ptr(this), fmt::ptr(&traceCls), _mLogger.level());
}

bt2::ConstMessage::Shared MsgIter::next()
{
    BT_CPPLOGD("Getting next message: addr={}", fmt::ptr(this));

    if (_mIsDone) {
        return bt2::ConstMessage::Shared {};
    }

    /*
     * Return any message that's already in the queue (one iteration of
     * the underlying item sequence iterator may yield more than one
     * message, but we return one at a time).
     */
    if (auto msg = this->_releaseNextMsg()) {
        return msg;
    }

    try {
        while (true) {
            /*
             * Get the next item from the underlying item
             * sequence iterator.
             */
            if (const auto item = _mItemSeqIter.next()) {
                if (item->type() == Item::Type::PktBegin) {
                    _mShouldWork = true;
                }

                /* Handle item if needed */
                if (_mShouldWork && (!_mSkipItemsUntilScopeEndItem || item->isScopeEnd())) {
                    this->_handleItem(*item);

                    if (item->type() == Item::Type::DataStreamInfo &&
                        (_mStream.cls().id() != _mCurStreamClassId)) {
                        _mShouldWork = false;
                    }

                    if (auto msg = this->_releaseNextMsg()) {
                        return msg;
                    }
                }
            } else {
                /* No more items: this is the end! */
                break;
            }
        }

        /* We're done! */
        _mIsDone = true;
        return _mSelfMsgIter.createStreamEndMessage(_mStream);
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("Failed to create the next message: addr={}",
                                            fmt::ptr(this));
    }
}

void MsgIter::_handleItem(const Item& item)
{
    /* Log item details */
    if (_mLogger.wouldLogT()) {
        item.accept(_mLoggingVisitor);
    }

    /* Defer to specific handler */
    switch (item.type()) {
    case Item::Type::PktBegin:
        this->_handleItem(item.asPktBegin());
        break;
    case Item::Type::PktEnd:
        this->_handleItem(item.asPktEnd());
        break;
    case Item::Type::ScopeBegin:
        this->_handleItem(item.asScopeBegin());
        break;
    case Item::Type::ScopeEnd:
        this->_handleItem(item.asScopeEnd());
        break;
    case Item::Type::PktContentEnd:
        this->_handleItem(item.asPktContentEnd());
        break;
    case Item::Type::EventRecordEnd:
        this->_handleItem(item.asEventRecordEnd());
        break;
    case Item::Type::PktMagicNumber:
        this->_handleItem(item.asPktMagicNumber());
        break;
    case Item::Type::MetadataStreamUuid:
        this->_handleItem(item.asMetadataStreamUuid());
        break;
    case Item::Type::DataStreamInfo:
        this->_handleItem(item.asDataStreamInfo());
        break;
    case Item::Type::PktInfo:
        this->_handleItem(item.asPktInfo());
        break;
    case Item::Type::EventRecordInfo:
        this->_handleItem(item.asEventRecordInfo());
        break;
    case Item::Type::FixedLenBitArrayField:
    case Item::Type::FixedLenBitMapField:
        this->_handleItem(item.asFixedLenBitArrayField());
        break;
    case Item::Type::FixedLenBoolField:
        this->_handleItem(item.asFixedLenBoolField());
        break;
    case Item::Type::FixedLenSIntField:
        this->_handleItem(item.asFixedLenSIntField());
        break;
    case Item::Type::FixedLenUIntField:
        this->_handleItem(item.asFixedLenUIntField());
        break;
    case Item::Type::FixedLenFloatField:
        this->_handleItem(item.asFixedLenFloatField());
        break;
    case Item::Type::VarLenSIntField:
        this->_handleItem(item.asVarLenSIntField());
        break;
    case Item::Type::VarLenUIntField:
        this->_handleItem(item.asVarLenUIntField());
        break;
    case Item::Type::NullTerminatedStrFieldBegin:
        this->_handleItem(item.asNullTerminatedStrFieldBegin());
        break;
    case Item::Type::NullTerminatedStrFieldEnd:
        this->_handleItem(item.asNullTerminatedStrFieldEnd());
        break;
    case Item::Type::RawData:
        this->_handleItem(item.asRawData());
        break;
    case Item::Type::StructFieldBegin:
        this->_handleItem(item.asStructFieldBegin());
        break;
    case Item::Type::StructFieldEnd:
        this->_handleItem(item.asStructFieldEnd());
        break;
    case Item::Type::StaticLenArrayFieldBegin:
        this->_handleItem(item.asStaticLenArrayFieldBegin());
        break;
    case Item::Type::StaticLenArrayFieldEnd:
    case Item::Type::DynLenArrayFieldEnd:
        this->_handleItem(item.asArrayFieldEnd());
        break;
    case Item::Type::DynLenArrayFieldBegin:
        this->_handleItem(item.asDynLenArrayFieldBegin());
        break;
    case Item::Type::StaticLenBlobFieldBegin:
        this->_handleItem(item.asStaticLenBlobFieldBegin());
        break;
    case Item::Type::StaticLenBlobFieldEnd:
    case Item::Type::DynLenBlobFieldEnd:
        this->_handleItem(item.asBlobFieldEnd());
        break;
    case Item::Type::DynLenBlobFieldBegin:
        this->_handleItem(item.asDynLenBlobFieldBegin());
        break;
    case Item::Type::StaticLenStrFieldBegin:
    case Item::Type::DynLenStrFieldBegin:
        this->_handleItem(item.asNonNullTerminatedStrFieldBegin());
        break;
    case Item::Type::StaticLenStrFieldEnd:
    case Item::Type::DynLenStrFieldEnd:
        this->_handleItem(item.asNonNullTerminatedStrFieldEnd());
        break;
    case Item::Type::VariantFieldWithSIntSelBegin:
    case Item::Type::VariantFieldWithUIntSelBegin:
        this->_handleItem(item.asVariantFieldBegin());
        break;
    case Item::Type::VariantFieldWithSIntSelEnd:
    case Item::Type::VariantFieldWithUIntSelEnd:
        this->_handleItem(item.asVariantFieldEnd());
        break;
    case Item::Type::OptionalFieldWithBoolSelBegin:
    case Item::Type::OptionalFieldWithSIntSelBegin:
    case Item::Type::OptionalFieldWithUIntSelBegin:
        this->_handleItem(item.asOptionalFieldBegin());
        break;
    case Item::Type::OptionalFieldWithBoolSelEnd:
    case Item::Type::OptionalFieldWithSIntSelEnd:
    case Item::Type::OptionalFieldWithUIntSelEnd:
        this->_handleItem(item.asOptionalFieldEnd());
        break;
    default:
        BT_CPPLOGT("Skipping item.");
        return;
    }
}

void MsgIter::_handleItem(const PktBeginItem&)
{
    BT_ASSERT_DBG(!_mCurPkt);
    this->_curPkt(_mStream.createPacket());
}

bt2::Message::Shared MsgIter::_createPktEndMsgAndUpdateCurDefClkVal()
{
    BT_ASSERT_DBG(_mCurPkt);

    if (_mPktEndDefClkVal) {
        const auto pktEndDefClkValZeroBug = _mQuirks.pktEndDefClkValZero && _mPktBeginDefClkVal &&
                                            _mPktEndDefClkVal && *_mPktBeginDefClkVal != 0 &&
                                            *_mPktEndDefClkVal == 0;
        const auto eventRecordDefClkValGtNextPktBeginDefClkValBug =
            _mQuirks.eventRecordDefClkValGtNextPktBeginDefClkVal && _mCurDefClkVal &&
            _mPktEndDefClkVal && *_mPktEndDefClkVal < _mCurDefClkVal;
        const auto anyBug =
            pktEndDefClkValZeroBug || eventRecordDefClkValGtNextPktBeginDefClkValBug;
        const auto defClkVal = anyBug ? *_mCurDefClkVal : *_mPktEndDefClkVal;

        if (!anyBug) {
            _mCurDefClkVal = _mPktEndDefClkVal;
        }

        return _mSelfMsgIter.createPacketEndMessage(*_mCurPkt, defClkVal);
    } else {
        return _mSelfMsgIter.createPacketEndMessage(*_mCurPkt);
    }
}

void MsgIter::_handleItem(const PktEndItem&)
{
    BT_ASSERT_DBG(!_mCurMsg);
    BT_ASSERT_DBG(_mCurPkt);

    /* Emit a packet beginning message now if required to fix a quirk */
    if (_mDelayPktBeginMsgEmission) {
        this->_emitDelayedPktBeginMsg(_mPktEndDefClkVal);
    }

    /* Emit a packet end message */
    this->_addMsgToQueue(this->_createPktEndMsgAndUpdateCurDefClkVal());

    /* No more current packet */
    this->_resetCurPkt();
}

void MsgIter::_handleItem(const ScopeBeginItem& item)
{
    BT_ASSERT(_mStack.empty());
    BT_ASSERT(!_mCurScopeField);

    /* Handle specific scope */
    switch (item.scope()) {
    case Scope::PktHeader:
        /* Nothing needed from the packet header: fast-forward */
        _mSkipItemsUntilScopeEndItem = true;
        break;
    case Scope::PktCtx:
    {
        BT_ASSERT_DBG(_mCurPkt);

        if (const auto pktCtxField = _mCurPkt->contextField()) {
            _mCurScopeField = pktCtxField;
        } else {
            /* Nothing needed from the packet context: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    case Scope::EventRecordHeader:
        /* Nothing needed from the event record header: fast-forward */
        _mSkipItemsUntilScopeEndItem = true;
        break;
    case Scope::CommonEventRecordCtx:
    {
        BT_ASSERT_DBG(_mCurMsg);

        if (const auto commonCtxField = _mCurMsg->asEvent().event().commonContextField()) {
            _mCurScopeField = commonCtxField;
        } else {
            /* Nothing needed from the common context: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    case Scope::SpecEventRecordCtx:
    {
        BT_ASSERT_DBG(_mCurMsg);

        if (const auto specCtxField = _mCurMsg->asEvent().event().specificContextField()) {
            _mCurScopeField = specCtxField;
        } else {
            /* Nothing needed from the specific context: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    case Scope::EventRecordPayload:
    {
        BT_ASSERT_DBG(_mCurMsg);

        if (const auto payloadField = _mCurMsg->asEvent().event().payloadField()) {
            _mCurScopeField = payloadField;
        } else {
            /* Nothing needed from the payload: fast-forward */
            _mSkipItemsUntilScopeEndItem = true;
        }

        break;
    }
    default:
        bt_common_abort();
    }
}

void MsgIter::_handleItem(const ScopeEndItem&)
{
    /*
     * The last stack frame was removed by the `StructFieldEndItem`
     * handler.
     */
    BT_ASSERT_DBG(_mStack.empty());

    /* No more current scope root field */
    _mCurScopeField.reset();

    /* Reset this flag */
    _mSkipItemsUntilScopeEndItem = false;
}

void MsgIter::_handleItem(const PktContentEndItem&)
{
    BT_ASSERT_DBG(_mCurPkt);
}

void MsgIter::_handleItem(const EventRecordEndItem&)
{
    BT_ASSERT_DBG(_mStack.empty());
    BT_ASSERT_DBG(_mCurMsg);

    /* Emit current message (move to message queue) */
    this->_addMsgToQueue(std::move(_mCurMsg));
    BT_ASSERT_DBG(!_mCurMsg);
}

void MsgIter::_handleItem(const PktMagicNumberItem& item)
{
    if (!item.isValid()) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error, "Invalid packet magic number: val={:#x}, expected-val={:#x}", item.val(),
            item.expectedVal());
    }
}

void MsgIter::_handleItem(const MetadataStreamUuidItem& item)
{
    BT_ASSERT_DBG(_mExpectedMetadataStreamUuid);

    if (item.uuid() != *_mExpectedMetadataStreamUuid) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error,
                                          "Invalid metadata stream UUID: uuid={}, expected-uuid={}",
                                          item.uuid(), *_mExpectedMetadataStreamUuid);
    }
}

void MsgIter::_handleItem(const DataStreamInfoItem& item)
{
    /*
     * `_mItemSeqIter` doesn't care about contiguous packets from the
     * same medium belonging to different data streams, but this message
     * iterator does because it manages a single libbabeltrace2 stream.
     */
    BT_ASSERT_DBG(item.cls());

    _mCurStreamClassId = item.cls()->id();

    if (item.cls()->id() != _mStream.cls().id()) {
        return;
    }

    if (item.id() && *item.id() != _mStream.id()) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "Two contiguous packets belong to different data streams: "
            "expected-data-stream-id={}, data-stream-id={}",
            *item.id(), _mStream.id());
    }

    if (!_mEmittedStreamBeginMsg) {
        this->_addMsgToQueue(_mSelfMsgIter.createStreamBeginningMessage(_mStream));
        _mEmittedStreamBeginMsg = true;
    }
}

bt2::Message::Shared MsgIter::_createInitDiscEventsMsg(const _OptUll& prevPktEndDefClkVal)
{
    if (_mStream.cls().discardedEventsHaveDefaultClockSnapshots()) {
        /*
         * We know there was a previous packet since we can't reach this
         * point for the first packet.
         */
        BT_ASSERT_DBG(prevPktEndDefClkVal);
        return _mSelfMsgIter.createDiscardedEventsMessage(_mStream, *prevPktEndDefClkVal,
                                                          *_mPktEndDefClkVal);
    } else {
        return _mSelfMsgIter.createDiscardedEventsMessage(_mStream);
    }
}

bt2::Message::Shared MsgIter::_createInitDiscPktsMsg(const _OptUll& prevPktEndDefClkVal)
{
    if (_mStream.cls().discardedPacketsHaveDefaultClockSnapshots()) {
        /*
         * We know there was a previous packet since we can't reach this
         * point for the first packet.
         */
        BT_ASSERT_DBG(prevPktEndDefClkVal);
        return _mSelfMsgIter.createDiscardedPacketsMessage(_mStream, *prevPktEndDefClkVal,
                                                           *_mPktBeginDefClkVal);
    } else {
        return _mSelfMsgIter.createDiscardedPacketsMessage(_mStream);
    }
}

void MsgIter::_emitPktBeginMsg(const _OptUll& defClkVal)
{
    BT_ASSERT_DBG(_mCurPkt);

    /* Add new message to queue */
    this->_addMsgToQueue(bt2c::call([this, &defClkVal] {
        if (defClkVal) {
            _mCurDefClkVal = defClkVal;
            return _mSelfMsgIter.createPacketBeginningMessage(*_mCurPkt, *defClkVal);
        } else {
            return _mSelfMsgIter.createPacketBeginningMessage(*_mCurPkt);
        }
    }));
}

void MsgIter::_emitDelayedPktBeginMsg(const _OptUll& otherDefClkVal)
{
    BT_ASSERT_DBG(_mDelayPktBeginMsgEmission);

    /* Reset the flag */
    _mDelayPktBeginMsgEmission = false;

    /*
     * Only fix the beginning timestamp of the packet if it's larger
     * than the timestamp of its first event record.
     *
     * Emit a packet beginning message now.
     */
    this->_emitPktBeginMsg(bt2c::call([this, &otherDefClkVal]() -> _OptUll {
        if (_mPktBeginDefClkVal && otherDefClkVal) {
            return std::min(*_mPktBeginDefClkVal, *otherDefClkVal);
        } else if (_mPktBeginDefClkVal) {
            return _mPktBeginDefClkVal;
        } else if (otherDefClkVal) {
            return otherDefClkVal;
        }

        return bt2s::nullopt;
    }));
}

void MsgIter::_handleItem(const PktInfoItem& item)
{
    /*
     * Save the packet beginning and end timestamps.
     *
     * Also keep the end timestamp of the previous packet: we might need
     * it if there are discarded event records.
     */
    const auto prevPktEndDefClkVal = _mPktEndDefClkVal;

    _mPktBeginDefClkVal = item.beginDefClkVal();
    _mPktEndDefClkVal = item.endDefClkVal();

    /*
     * Emit a discarded events message if the count of discarded event
     * records went up since the previous packet.
     *
     * For the first packet, `_mCurDiscErCounterSnap` isn't set: we
     * don't have anything to compare to.
     */
    {
        const auto& discErCounterSnap = item.discEventRecordCounterSnap();

        if (_mCurDiscErCounterSnap) {
            /*
             * If the previous packet of this same stream had a discarded
             * event record counter snapshot, then this one must have one
             * too.
             */
            BT_ASSERT_DBG(discErCounterSnap);

            // TODO: handle `*discErCounterSnap` being <= `*_mCurDiscErCounterSnap`
            if (*discErCounterSnap > *_mCurDiscErCounterSnap) {
                /* Create and initialize the message */
                auto msg = this->_createInitDiscEventsMsg(prevPktEndDefClkVal);

                /* Set its count */
                msg->asDiscardedEvents().count(*discErCounterSnap - *_mCurDiscErCounterSnap);

                /* Add to queue */
                this->_addMsgToQueue(std::move(msg));
            }
        }

        /* Set new current discarded event record counter snapshot */
        _mCurDiscErCounterSnap = discErCounterSnap;
    }

    /*
     * Emit a discarded packets message if there's a gap between the
     * previous packet sequence number and the sequence number of this
     * new packet.
     */
    {
        const auto& seqNum = item.seqNum();

        if (_mCurPktSeqNum) {
            /*
             * If the previous packet of this same stream had a sequence
             * number, then this one must have one too.
             */
            BT_ASSERT_DBG(seqNum);

            // TODO: handle `*seqNum` being <= `*_mCurPktSeqNum`
            if (*_mCurPktSeqNum + 1 < *seqNum) {
                /* Create and initialize the message */
                auto msg = this->_createInitDiscPktsMsg(prevPktEndDefClkVal);

                /* Set its count */
                msg->asDiscardedPackets().count(*seqNum - *_mCurPktSeqNum - 1);

                /* Add to queue */
                this->_addMsgToQueue(std::move(msg));
            }
        }

        /* Set new packet sequence number */
        _mCurPktSeqNum = seqNum;
    }

    /* There's no pending message */
    BT_ASSERT_DBG(!_mCurMsg);

    /*
     * Depending on a quirk to handle, emit a packet beginning message
     * now or delay said emission.
     */
    if (_mQuirks.eventRecordDefClkValLtPktBeginDefClkVal) {
        _mDelayPktBeginMsgEmission = true;
    } else {
        /* No quirk to handle: emit the message now */
        this->_emitPktBeginMsg(_mPktBeginDefClkVal);
    }
}

bt2::Message::Shared MsgIter::_createEventMsg(const bt2::EventClass cls, const _OptUll& defClkVal)
{
    if (defClkVal) {
        if (_mCurPkt) {
            return _mSelfMsgIter.createEventMessage(cls, *_mCurPkt, *defClkVal);
        } else {
            return _mSelfMsgIter.createEventMessage(cls, _mStream, *defClkVal);
        }
    } else {
        if (_mCurPkt) {
            return _mSelfMsgIter.createEventMessage(cls, *_mCurPkt);
        } else {
            return _mSelfMsgIter.createEventMessage(cls, _mStream);
        }
    }
}

void MsgIter::_handleItem(const EventRecordInfoItem& item)
{
    // TODO: Test having a trace with only event record headers
    BT_ASSERT_DBG(item.cls());
    BT_ASSERT_DBG(item.cls()->libCls());
    BT_ASSERT_DBG(!_mCurMsg);

    /* Emit a packet beginning message now if required to fix a quirk */
    if (_mDelayPktBeginMsgEmission) {
        this->_emitDelayedPktBeginMsg(item.defClkVal());
    }

    /* Update the default clock value if needed */
    if (item.defClkVal()) {
        _mCurDefClkVal = *item.defClkVal();
    }

    /*
     * Set as current message.
     *
     * The following items will gradually fill this message.
     *
     * This message will be emitted (added to the message queue) when
     * handling the next `EventRecordEndItem`.
     */
    _mCurMsg = this->_createEventMsg(*item.cls()->libCls(), item.defClkVal());
}

void MsgIter::_handleItem(const FixedLenBitArrayFieldItem& item)
{
    if (_ignoreFieldItem(item)) {
        return;
    }

    this->_stackTopCurSubFieldAndGoToNextSubField().asBitArray().valueAsInteger(item.uIntVal());
}

void MsgIter::_handleItem(const FixedLenBoolFieldItem& item)
{
    if (_ignoreFieldItem(item)) {
        return;
    }

    this->_stackTopCurSubFieldAndGoToNextSubField().asBool().value(item.val());
}

void MsgIter::_handleItem(const FixedLenSIntFieldItem& item)
{
    this->_handleSIntFieldItem(item);
}

void MsgIter::_handleItem(const FixedLenUIntFieldItem& item)
{
    this->_handleUIntFieldItem(item);
}

void MsgIter::_handleItem(const FixedLenFloatFieldItem& item)
{
    const auto field = this->_stackTopCurSubFieldAndGoToNextSubField();

    if (item.cls().len() == 32_bits) {
        field.asSinglePrecisionReal().value(item.val());
    } else {
        BT_ASSERT_DBG(item.cls().len() == 64_bits);
        field.asDoublePrecisionReal().value(item.val());
    }
}

void MsgIter::_handleItem(const VarLenSIntFieldItem& item)
{
    this->_handleSIntFieldItem(item);
}

void MsgIter::_handleItem(const VarLenUIntFieldItem& item)
{
    this->_handleUIntFieldItem(item);
}

void MsgIter::_handleStrFieldBeginItem(const FieldItem& item)
{
    this->_stackTopCurSubField().asString().value("");
    _mHaveNullChar = false;
    _mUtf16NullCpFinder = NullCpFinder<2> {};
    _mUtf32NullCpFinder = NullCpFinder<4> {};
    _mStrBuf.clear();
    _mCurStrFieldEncoding = item.cls().asStr().encoding();
}

void MsgIter::_handleStrFieldEndItem()
{
    switch (_mCurStrFieldEncoding) {
    case StrEncoding::Utf16Be:
    case StrEncoding::Utf16Le:
    case StrEncoding::Utf32Be:
    case StrEncoding::Utf32Le:
    {
        /* Convert to UTF-8 */
        const auto utf8Str = bt2c::call([this] {
            bt2c::ConstBytes inBytes {_mStrBuf.begin(), _mStrBuf.end()};

            switch (_mCurStrFieldEncoding) {
            case StrEncoding::Utf16Be:
                return _mUnicodeConv.utf8FromUtf16Be(inBytes);
            case StrEncoding::Utf16Le:
                return _mUnicodeConv.utf8FromUtf16Le(inBytes);
            case StrEncoding::Utf32Be:
                return _mUnicodeConv.utf8FromUtf32Be(inBytes);
            case StrEncoding::Utf32Le:
                return _mUnicodeConv.utf8FromUtf32Le(inBytes);
            default:
                bt_common_abort();
            }
        });
        const auto endIt =
            !utf8Str.empty() && utf8Str.back() == 0 ? utf8Str.end() - 1 : utf8Str.end();

        /* Append */
        this->_stackTopCurSubField().asString().append(
            reinterpret_cast<const char *>(utf8Str.data()), endIt - utf8Str.begin());
    }

    default:
        break;
    }

    this->_stackTopGoToNextSubField();
}

void MsgIter::_handleItem(const NullTerminatedStrFieldBeginItem& item)
{
    this->_handleStrFieldBeginItem(item);
}

void MsgIter::_handleItem(const NullTerminatedStrFieldEndItem&)
{
    this->_handleStrFieldEndItem();
}

void MsgIter::_handleBlobRawDataItem(const RawDataItem& item)
{
    std::memcpy(&this->_stackTopCurSubField().asBlob().data()[_mCurBlobFieldDataOffset],
                item.data().begin(), item.data().size());
    _mCurBlobFieldDataOffset += item.data().size();
}

void MsgIter::_handleStrRawDataItem(const RawDataItem& item)
{
    if (_mHaveNullChar) {
        /* No more text data */
        return;
    }

    if (_mCurStrFieldEncoding == StrEncoding::Utf8) {
        /* Try to find the first U+0000 codepoint */
        const auto endIt = std::find(item.data().begin(), item.data().end(), 0);
        _mHaveNullChar = endIt != item.data().end();

        /* Append to current string field */
        this->_stackTopCurSubField().asString().append(
            reinterpret_cast<const char *>(item.data().data()), endIt - item.data().begin());
    } else {
        /* Try to find the first U+0000 codepoint */
        auto endIt = item.data().end();
        const auto afterNullCpIt = bt2c::call([this, &item] {
            if (_mCurStrFieldEncoding == StrEncoding::Utf16Be ||
                _mCurStrFieldEncoding == StrEncoding::Utf16Le) {
                return _mUtf16NullCpFinder.findNullCp(item.data());
            } else {
                BT_ASSERT_DBG(_mCurStrFieldEncoding == StrEncoding::Utf32Be ||
                              _mCurStrFieldEncoding == StrEncoding::Utf32Le);
                return _mUtf32NullCpFinder.findNullCp(item.data());
            }
        });

        if (afterNullCpIt) {
            /* Found U+0000 */
            endIt = *afterNullCpIt;
            _mHaveNullChar = true;
        }

        /* Append to current string buffer */
        _mStrBuf.insert(_mStrBuf.end(), item.data().begin(), endIt);
    }
}

void MsgIter::_handleItem(const RawDataItem& item)
{
    if (this->_stackTopCurSubField().isString()) {
        this->_handleStrRawDataItem(item);
    } else {
        BT_ASSERT_DBG(this->_stackTopCurSubField().isBlob());
        this->_handleBlobRawDataItem(item);
    }
}

void MsgIter::_handleItem(const StructFieldBeginItem&)
{
    if (_mStack.empty()) {
        /* This is the root field of the current scope */
        BT_ASSERT_DBG(_mCurScopeField);
        this->_stackPush(*_mCurScopeField);
    } else {
        /* Use sub-field */
        this->_stackPush(this->_stackTopCurSubFieldAndGoToNextSubField().asStructure());
    }
}

void MsgIter::_handleItem(const StructFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_handleItem(const StaticLenArrayFieldBeginItem&)
{
    this->_stackPush(this->_stackTopCurSubFieldAndGoToNextSubField().asArray());
}

void MsgIter::_handleItem(const DynLenArrayFieldBeginItem& item)
{
    auto arrayField = this->_stackTopCurSubFieldAndGoToNextSubField().asDynamicArray();

    arrayField.length(item.len());
    this->_stackPush(arrayField);
}

void MsgIter::_handleItem(const ArrayFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_handleItem(const StaticLenBlobFieldBeginItem&)
{
    _mCurBlobFieldDataOffset = 0;
}

void MsgIter::_handleItem(const DynLenBlobFieldBeginItem& item)
{
    this->_stackTopCurSubField().asDynamicBlob().length(item.len().bytes());
    _mCurBlobFieldDataOffset = 0;
}

void MsgIter::_handleItem(const BlobFieldEndItem&)
{
    this->_stackTopGoToNextSubField();
}

void MsgIter::_handleItem(const NonNullTerminatedStrFieldBeginItem& item)
{
    this->_handleStrFieldBeginItem(item);
}

void MsgIter::_handleItem(const NonNullTerminatedStrFieldEndItem&)
{
    this->_handleStrFieldEndItem();
}

void MsgIter::_handleItem(const VariantFieldBeginItem& item)
{
    auto field = this->_stackTopCurSubFieldAndGoToNextSubField().asVariant();

    field.selectOption(item.selectedOptIndex());
    this->_stackPush(field);
}

void MsgIter::_handleItem(const VariantFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_handleItem(const OptionalFieldBeginItem& item)
{
    auto field = this->_stackTopCurSubFieldAndGoToNextSubField().asOption();

    field.hasField(item.isEnabled());
    this->_stackPush(field);
}

void MsgIter::_handleItem(const OptionalFieldEndItem&)
{
    this->_stackPop();
}

void MsgIter::_addMsgToQueue(bt2::ConstMessage::Shared msg)
{
    BT_ASSERT_DBG(_mMsgQueue.len < _mMsgQueue.array.size());
    _mMsgQueue.array[_mMsgQueue.len] = std::move(msg);
    ++_mMsgQueue.len;
}

bt2::ConstMessage::Shared MsgIter::_releaseNextMsg()
{
    if (_mMsgQueue.len == 0) {
        return bt2::ConstMessage::Shared {};
    }

    auto msg = std::move(_mMsgQueue.array.front());

    _mMsgQueue.array[0] = std::move(_mMsgQueue.array[1]);
    _mMsgQueue.array[1] = std::move(_mMsgQueue.array[2]);
    --_mMsgQueue.len;
    return msg;
}

} /* namespace src */
} /* namespace ctf */
