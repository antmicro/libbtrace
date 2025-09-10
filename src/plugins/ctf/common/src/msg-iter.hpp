/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022-2024 EfficiOS, Inc
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_MSG_ITER_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_MSG_ITER_HPP

#include <stack>

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "cpp-common/bt2/message.hpp"
#include "cpp-common/bt2/self-message-iterator.hpp"
#include "cpp-common/bt2/trace-ir.hpp"
#include "cpp-common/bt2c/unicode-conv.hpp"

#include "item-seq/item-seq-iter.hpp"
#include "item-seq/item-visitor.hpp"
#include "item-seq/logging-item-visitor.hpp"
#include "metadata/ctf-ir.hpp"
#include "null-cp-finder.hpp"

namespace ctf {
namespace src {

/*
 * Various quirks that a CTF message iterator can work around.
 */
struct MsgIterQuirks final
{
    /* Packet end timestamps set to zero */
    bool pktEndDefClkValZero = false;

    /*
     * Timestamp of last event record of a packet is greater than the
     * beginning timestamp of the next packet.
     */
    bool eventRecordDefClkValGtNextPktBeginDefClkVal = false;

    /*
     * Timestamp of the first event record of a packet is less than the
     * beginning timestamp of its packet.
     */
    bool eventRecordDefClkValLtPktBeginDefClkVal = false;
};

/*
 * CTF message iterator.
 *
 * Such an iterator essentially converts the items of an underlying item
 * sequence iterator to corresponding libbabeltrace2 messages.
 *
 * Therefore, as a user, you provide:
 *
 * • A medium, which provides data stream data to the iterator.
 *
 * • A CTF IR trace class, which describes how to decode said data.
 *
 * • A libbabeltrace2 self message iterator and stream, which the
 *   iterator needs to create libbabeltrace2 messages.
 *
 * A CTF message iterator may automatically fix some common quirks
 * (see `MsgIterQuirks`).
 */
class MsgIter final
{
public:
    /*
     * Builds a CTF message iterator, using `traceCls` and `medium` to
     * decode a data stream identified by `stream`, and `selfMsgIter`
     * and `stream` to create libbabeltrace2 messages.
     *
     * `quirks` indicates which quirks to fix.
     *
     * It's guaranteed that this constructor doesn't throw
     * `bt2c::TryAgain` or a medium error.
     */
    explicit MsgIter(bt2::SelfMessageIterator selfMsgIter, const ctf::src::TraceCls& traceCls,
                     bt2s::optional<bt2c::Uuid> expectedMetadataStreamUuid, bt2::Stream stream,
                     Medium::UP medium, const MsgIterQuirks& quirks,
                     const bt2c::Logger& parentLogger);

    /* Disable copy/move operations */
    MsgIter(const MsgIter&) = delete;
    MsgIter& operator=(const MsgIter&) = delete;

    /*
     * Advances the iterator to the next message, returning:
     *
     * A libbabeltrace2 message:
     *     Said next message.
     *
     * `bt2s::nullopt`:
     *     The iterator is ended.
     *
     * May throw whatever Medium::buf() may throw as well
     * as `bt2c::Error`.
     */
    bt2::ConstMessage::Shared next();

private:
    /* An optional `unsigned long long` value */
    using _OptUll = bt2s::optional<unsigned long long>;

    /* Single frame of a message iterator stack */
    class _StackFrame
    {
    public:
        explicit _StackFrame(const bt2::StructureField field) noexcept :
            _mFieldType {_FieldType::Struct}, _mField {field}
        {
        }

        explicit _StackFrame(const bt2::VariantField field) noexcept :
            _mFieldType {_FieldType::Variant}, _mField(field)
        {
        }

        explicit _StackFrame(const bt2::OptionField field) noexcept :
            _mFieldType {_FieldType::Option}, _mField(field)
        {
        }

        explicit _StackFrame(const bt2::ArrayField field) noexcept :
            _mFieldType(_FieldType::Array), _mField(field)
        {
        }

        bt2::StructureField structureField() const noexcept
        {
            BT_ASSERT_DBG(_mFieldType == _FieldType::Struct);
            return _mField.structure;
        }

        bt2::VariantField variantField() const noexcept
        {
            BT_ASSERT_DBG(_mFieldType == _FieldType::Variant);
            return _mField.variant;
        }

        bt2::OptionField optionField() const noexcept
        {
            BT_ASSERT_DBG(_mFieldType == _FieldType::Option);
            return _mField.option;
        }

        bt2::ArrayField arrayField() const noexcept
        {
            BT_ASSERT_DBG(_mFieldType == _FieldType::Array);
            return _mField.array;
        }

        unsigned long long subFieldIndex() const noexcept
        {
            return _mSubFieldIndex;
        }

        void goToNextSubField() noexcept
        {
            /*
             * We unconditionally increment `_mSubFieldIndex`, even if
             * the current field is a variant/option field, because
             * curSubField() doesn't care about `_mSubFieldIndex` for
             * those cases anyway.
             *
             * In practice, `_mSubFieldIndex` will reach one with a
             * variant/option field, but curSubField() will never be
             * called with `_mSubFieldIndex` being something else
             * than zero.
             */
            ++_mSubFieldIndex;
        }

        bt2::Field curSubField() noexcept
        {
            switch (_mFieldType) {
            case _FieldType::Struct:
                BT_ASSERT_DBG(_mSubFieldIndex < _mField.structure.cls().length());
                return _mField.structure[_mSubFieldIndex];

            case _FieldType::Variant:
                BT_ASSERT_DBG(_mSubFieldIndex == 0);
                return _mField.variant.selectedOptionField();

            case _FieldType::Option:
                BT_ASSERT_DBG(_mSubFieldIndex == 0);
                BT_ASSERT_DBG(_mField.option.hasField());
                return *_mField.option.field();

            case _FieldType::Array:
                BT_ASSERT_DBG(_mSubFieldIndex < _mField.array.length());
                return _mField.array[_mSubFieldIndex];

            default:
                bt_common_abort();
            }
        }

        bt2::Field curSubFieldAndGoToNextSubField() noexcept
        {
            const auto field = this->curSubField();

            this->goToNextSubField();
            return field;
        }

    private:
        /* Selector of `_mField` below */
        enum class _FieldType
        {
            /* Selects `structure` */
            Struct = 1,

            /* Selects `variant` */
            Variant,

            /* Selects `option` */
            Option,

            /* Selects `array` */
            Array,
        } _mFieldType;

        /* Field of this frame, selected by `_mFieldType` above */
        union _Field
        {
            explicit _Field(const bt2::StructureField field) noexcept
            {
                new (&structure) bt2::StructureField {field};
            }

            explicit _Field(const bt2::VariantField field) noexcept
            {
                new (&variant) bt2::VariantField {field};
            }

            explicit _Field(const bt2::OptionField field) noexcept
            {
                new (&option) bt2::OptionField {field};
            }

            explicit _Field(const bt2::ArrayField field) noexcept
            {
                new (&array) bt2::ArrayField {field};
            }

            static_assert(std::is_trivially_destructible<bt2::StructureField>::value,
                          "`bt2::StructureField` is trivially destructible.");
            static_assert(std::is_trivially_destructible<bt2::VariantField>::value,
                          "`bt2::VariantField` is trivially destructible.");
            static_assert(std::is_trivially_destructible<bt2::OptionField>::value,
                          "`bt2::OptionField` is trivially destructible.");
            static_assert(std::is_trivially_destructible<bt2::ArrayField>::value,
                          "`bt2::ArrayField` is trivially destructible.");

            bt2::StructureField structure;
            bt2::VariantField variant;
            bt2::OptionField option;
            bt2::ArrayField array;
        } _mField;

        /*
         * Index of, depending on `_mFieldType` above:
         *
         * `_FieldType::Struct`:
         *     The current member of `_mField.structure`.
         *
         * `_FieldType::Array`:
         *     The current element field of `_mField.array`.
         *
         * `_FieldType::Variant`:
         * `_FieldType::Option`:
         *     Not applicable.
         */
        unsigned long long _mSubFieldIndex = 0;
    };

    /*
     * Returns whether or not to ignore the field of `item`.
     */
    static bool _ignoreFieldItem(const FieldItem& item) noexcept
    {
        return !item.cls().libCls();
    }

    /*
     * Handles the item `item`, changing the state accordingly, possibly
     * adding one or more messages to `_mMsgs`.
     */
    void _handleItem(const Item& item);

    /* Specific item handlers below */
    void _handleItem(const ArrayFieldEndItem& item);
    void _handleItem(const BlobFieldEndItem& item);
    void _handleItem(const DataStreamInfoItem& item);
    void _handleItem(const DynLenArrayFieldBeginItem& item);
    void _handleItem(const DynLenBlobFieldBeginItem& item);
    void _handleItem(const EventRecordEndItem& item);
    void _handleItem(const EventRecordInfoItem& item);
    void _handleItem(const FixedLenBitArrayFieldItem& item);
    void _handleItem(const FixedLenBoolFieldItem& item);
    void _handleItem(const FixedLenFloatFieldItem& item);
    void _handleItem(const FixedLenSIntFieldItem& item);
    void _handleItem(const FixedLenUIntFieldItem& item);
    void _handleItem(const MetadataStreamUuidItem& item);
    void _handleItem(const NonNullTerminatedStrFieldBeginItem& item);
    void _handleItem(const NonNullTerminatedStrFieldEndItem& item);
    void _handleItem(const NullTerminatedStrFieldBeginItem& item);
    void _handleItem(const NullTerminatedStrFieldEndItem& item);
    void _handleItem(const OptionalFieldBeginItem& item);
    void _handleItem(const OptionalFieldEndItem& item);
    void _handleItem(const PktBeginItem& item);
    void _handleItem(const PktContentEndItem& item);
    void _handleItem(const PktEndItem& item);
    void _handleItem(const PktInfoItem& item);
    void _handleItem(const PktMagicNumberItem& item);
    void _handleBlobRawDataItem(const RawDataItem& item);
    void _handleStrRawDataItem(const RawDataItem& item);
    void _handleItem(const RawDataItem& item);
    void _handleItem(const ScopeBeginItem& item);
    void _handleItem(const ScopeEndItem& item);
    void _handleItem(const StaticLenArrayFieldBeginItem& item);
    void _handleItem(const StaticLenBlobFieldBeginItem& item);
    void _handleItem(const StructFieldBeginItem& item);
    void _handleItem(const StructFieldEndItem& item);
    void _handleItem(const VariantFieldBeginItem& item);
    void _handleItem(const VariantFieldEndItem& item);
    void _handleItem(const VarLenSIntFieldItem& item);
    void _handleItem(const VarLenUIntFieldItem& item);
    void _handleStrFieldBeginItem(const FieldItem& item);
    void _handleStrFieldEndItem();

    template <typename ItemT>
    void _handleUIntFieldItem(const ItemT& item)
    {
        if (_ignoreFieldItem(item)) {
            return;
        }

        const auto field = this->_stackTopCurSubFieldAndGoToNextSubField();

        field.asUnsignedInteger().value(item.val());
    }

    template <typename ItemT>
    void _handleSIntFieldItem(const ItemT& item)
    {
        if (_ignoreFieldItem(item)) {
            return;
        }

        const auto field = this->_stackTopCurSubFieldAndGoToNextSubField();

        field.asSignedInteger().value(item.val());
    }

    /*
     * Calls goToNextSubField() for the top stack frame.
     */
    void _stackTopGoToNextSubField()
    {
        BT_ASSERT_DBG(!_mStack.empty());
        _mStack.top().goToNextSubField();
    }

    /*
     * Returns curSubField() for the top stack frame.
     */
    bt2::Field _stackTopCurSubField()
    {
        BT_ASSERT_DBG(!_mStack.empty());
        return _mStack.top().curSubField();
    }

    /*
     * Returns curSubFieldAndGoToNextSubField() for the top stack frame.
     */
    bt2::Field _stackTopCurSubFieldAndGoToNextSubField()
    {
        BT_ASSERT_DBG(!_mStack.empty());
        return _mStack.top().curSubFieldAndGoToNextSubField();
    }

    /*
     * Pushes a stack frame managing `field` on the stack.
     */
    template <typename FieldT>
    void _stackPush(FieldT&& field)
    {
        _mStack.emplace(std::forward<FieldT>(field));
    }

    /*
     * Removes the top stack frame.
     */
    void _stackPop()
    {
        BT_ASSERT_DBG(!_mStack.empty());
        _mStack.pop();
    }

    /*
     * Sets the current packet to `pkt`.
     */
    void _curPkt(bt2::Packet::Shared pkt)
    {
        BT_ASSERT_DBG(!_mCurPkt);
        _mCurPkt = std::move(pkt);
    }

    /*
     * Resets the current packet.
     */
    void _resetCurPkt()
    {
        BT_ASSERT_DBG(_mCurPkt);
        _mCurPkt.reset();
    }

    /*
     * Creates and returns an initial discarded events message, not
     * setting any specific count.
     */
    bt2::Message::Shared _createInitDiscEventsMsg(const _OptUll& prevPktEndDefClkVal);

    /*
     * Creates and returns an initial discarded packets message, not
     * setting any specific count.
     */
    bt2::Message::Shared _createInitDiscPktsMsg(const _OptUll& prevPktEndDefClkVal);

    /*
     * Creates a packet end message and, if needed, updates the current
     * timestamp.
     */
    bt2::Message::Shared _createPktEndMsgAndUpdateCurDefClkVal();

    /*
     * Creates an event message using the class `cls` and having
     * `defClkVal` as its timestamp.
     */
    bt2::Message::Shared _createEventMsg(bt2::EventClass cls, const _OptUll& defClkVal);

    /*
     * Emits a packet beginning message having `defClkVal`, if set, as
     * its default clock snapshot.
     */
    void _emitPktBeginMsg(const _OptUll& defClkVal);

    /*
     * Emits a delayed packet beginning message, considering the other
     * timestamp `otherDefClkVal`.
     */
    void _emitDelayedPktBeginMsg(const _OptUll& otherDefClkVal);

    /*
     * Adds the message `msg` to the message queue.
     */
    void _addMsgToQueue(bt2::ConstMessage::Shared msg);

    /*
     * Returns one of:
     *
     * A shared libbabeltrace2 message:
     *     The next available message from the message queue, removing
     *     it from the queue.
     *
     * `bt2s::nullopt`:
     *     The message queue is empty.
     */
    bt2::ConstMessage::Shared _releaseNextMsg();

    /* Logger */
    bt2c::Logger _mLogger;

    /* libbabeltrace2 self message iterator to create messages (weak) */
    bt2::SelfMessageIterator _mSelfMsgIter;

    /* Corresponding libbabeltrace2 stream */
    bt2::Stream _mStream;

    /* Expected metadata stream UUID, if any */
    bt2s::optional<bt2c::Uuid> _mExpectedMetadataStreamUuid;

    /* Quirks to fix */
    MsgIterQuirks _mQuirks;

    /* Underlying item sequence iterator to decode the data stream */
    ItemSeqIter _mItemSeqIter;

    /* Whether or not the iterator is ended */
    bool _mIsDone = false;

    /*
     * Queue of already created messages.
     *
     * We're using a queue instead of keeping a single message because
     * because one item (from `_mItemSeqIter`) may correspond to more
     * than one libbabeltrace2 message. One item can generate at most
     * three messages (see `_handleItem(const PktInfoItem&)`), therefore
     * it's a queue of up to three messages.
     *
     * The head of the queue (the next message to return) is always at
     * index 0 within `array`. `len` is the number of messages in
     * the queue.
     */
    struct
    {
        std::array<bt2::ConstMessage::Shared, 3> array;
        std::size_t len;
    } _mMsgQueue;

    /* Stack */
    std::stack<_StackFrame> _mStack;

    /* Root field of current scope */
    bt2::OptionalBorrowedObject<bt2::StructureField> _mCurScopeField;

    /*
     * Whether or not to skip items until reaching the end of the
     * current scope.
     */
    bool _mSkipItemsUntilScopeEndItem = false;

    /*
     * If set: a message that we're building, that's not yet ready to be
     * returned.
     */
    bt2::Message::Shared _mCurMsg;

    /*
     * If set: the current packet.
     *
     * Set while handling a `PktBeginItem` and reset while handling a
     * `PktEndItem`.
     */
    bt2::Packet::Shared _mCurPkt;

    /* Current packet sequence number, if any */
    _OptUll _mCurPktSeqNum;

    /* Current default clock value, if any */
    _OptUll _mCurDefClkVal;

    /* Current discarded event record counter snapshot, if any */
    _OptUll _mCurDiscErCounterSnap;

    /*
     * Values of the beginning and end timestamps of the current packet.
     *
     * Set while handling a `PktInfoItem` and reset while handling a
     * `PktEndItem`.
     */
    _OptUll _mPktBeginDefClkVal;
    _OptUll _mPktEndDefClkVal;

    /*
     * Whether or not a stream beginning message was provided to the
     * user.
     */
    bool _mEmittedStreamBeginMsg = false;

    /*
     * Whether or not to delay the emission of a packet beginning
     * message.
     */
    bool _mDelayPktBeginMsgEmission = false;

    /*
     * Whether or not, while processing `RawDataItem` items, we got a
     * null character.
     */
    bool _mHaveNullChar = false;

    /* Null codepoint finders for UTF-16 and UTF-32 */
    NullCpFinder<2> _mUtf16NullCpFinder;
    NullCpFinder<4> _mUtf32NullCpFinder;

    /* Unicode converter to decode UTF-16 and UTF-32 strings */
    bt2c::UnicodeConv _mUnicodeConv;

    /* Buffer holding the string to convert to UTF-8 */
    std::vector<std::uint8_t> _mStrBuf;

    /*
     * Current BLOB field data offset while processing BLOB field
     * section items.
     */
    std::size_t _mCurBlobFieldDataOffset = 0;

    /*
     * Current string field encoding, if any.
     */
    StrEncoding _mCurStrFieldEncoding = StrEncoding::Utf8;

    /* Helper to log items */
    LoggingItemVisitor _mLoggingVisitor;

    bool _mShouldWork;

    unsigned long long _mCurStreamClassId;
};

} /* namespace src */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_MSG_ITER_HPP */
