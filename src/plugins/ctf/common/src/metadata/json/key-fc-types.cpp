/*
 * Copyright (c) 2023-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "common/assert.h"
#include "common/common.h"
#include "cpp-common/bt2c/contains.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2c/text-loc-str.hpp"

#include "../../../metadata/json-strings.hpp"
#include "key-fc-types.hpp"
#include "utils.hpp"

namespace ctf {
namespace src {
namespace {

/*
 * Helper of keyFcTypes().
 */
class KeyFcTypesFinder final : public ConstFcVisitor
{
private:
    /* Current scope field classes */
    struct _Ctx final
    {
        const Fc *pktHeaderFc;
        const Fc *pktCtxFc;
        const Fc *eventRecordHeaderFc;
        const Fc *commonEventRecordCtxFc;
        const Fc *specEventRecordCtxFc;
        const Fc *eventRecordPayloadFc;
    };

    /* Set of const field classes */
    using _ConstFcSet = std::unordered_set<const Fc *>;

public:
    explicit KeyFcTypesFinder(const Scope scope, const Fc * const pktHeaderFc,
                              const Fc * const pktCtxFc, const Fc * const eventRecordHeaderFc,
                              const Fc * const commonEventRecordCtxFc,
                              const Fc * const specEventRecordCtxFc,
                              const Fc * const eventRecordPayloadFc,
                              const bt2c::Logger& parentLogger) :
        _mLogger {parentLogger, "PLUGIN/CTF/CTF-2-FC-DEP-TYPES"}, _mScope {scope},
        _mCtx {pktHeaderFc,          pktCtxFc,
               eventRecordHeaderFc,  commonEventRecordCtxFc,
               specEventRecordCtxFc, eventRecordPayloadFc}
    {
    }

    /*
     * Moves the resulting field class dependency type map to
     * the caller.
     */
    KeyFcTypes takeKeyFcTypes() noexcept
    {
        return std::move(_mKeyFcTypes);
    }

private:
    void visit(const StaticLenArrayFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const DynLenArrayFc& fc) override
    {
        this->_addDynLenKeyFcType(fc);
        this->_visit(fc);
    }

    void visit(const DynLenStrFc& fc) override
    {
        this->_addDynLenKeyFcType(fc);
    }

    void visit(const DynLenBlobFc& fc) override
    {
        this->_addDynLenKeyFcType(fc);
    }

    void visit(const StructFc& fc) override
    {
        for (auto& memberCls : fc) {
            try {
                memberCls.fc().accept(*this);
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                    memberCls.fc().loc(), "Invalid structure field member class.");
            }
        }
    }

    void visit(const OptionalWithBoolSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const OptionalWithUIntSelFc& fc) override
    {
        this->_visit(fc);
    }

    void visit(const OptionalWithSIntSelFc&) override
    {
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void visit(const VariantWithUIntSelFc& fc) override
    {
        this->_addOptionalOrVariantKeyFcType(fc);

        for (auto optIt = fc.begin(); optIt != fc.end(); ++optIt) {
            try {
                this->_withinCompoundFc(fc, optIt - fc.begin(), [this, &optIt] {
                    optIt->fc().accept(*this);
                });
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(optIt->fc().loc(),
                                                             "Invalid variant field class option.");
            }
        }
    }

    void visit(const VariantWithSIntSelFc&) override
    {
        /* Doesn't exist at this point */
        bt_common_abort();
    }

    void _visit(const ArrayFc& fc)
    {
        try {
            this->_withinCompoundFc(fc, [this, &fc] {
                fc.elemFc().accept(*this);
            });
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid element field class of array field class.");
        }
    }

    void _visit(const OptionalFc& fc)
    {
        const auto keyFcType = this->_addOptionalOrVariantKeyFcType(fc);

        if (fc.isOptionalWithBoolSel() && keyFcType != KeyFcType::Bool) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, fc.loc(),
                "Expecting a class of optional fields with a boolean selector field "
                "because the `{}` property is absent.",
                jsonstr::selFieldRanges);
        }

        try {
            this->_withinCompoundFc(fc, [this, &fc] {
                fc.fc().accept(*this);
            });
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                fc.loc(), "Invalid field class of optional field class.");
        }
    }

    /*
     * Adds the key field class type of the dynamic-length field class
     * `fc` to `_mKeyFcTypes`.
     */
    template <typename FcT>
    void _addDynLenKeyFcType(FcT& fc)
    {
        this->_validateDynLenKeyFcType(this->_addKeyFcs(fc, fc.lenFieldLoc()), fc.lenFieldLoc());
    }

    /*
     * Adds the key field class type of the optional or variant field
     * class `fc` to `_mKeyFcTypes` and returns said type.
     */
    template <typename FcT>
    KeyFcType _addOptionalOrVariantKeyFcType(FcT& fc)
    {
        return this->_keyFcType(**this->_addKeyFcs(fc, fc.selFieldLoc()).begin());
    }

    /*
     * Adds the key field class type of `fc` to `_mKeyFcTypes` and
     * returns the dependencies of `fc`.
     */
    template <typename FcT>
    _ConstFcSet _addKeyFcs(FcT& fc, const FieldLoc& fieldLoc)
    {
        auto keyFcs = this->_findKeyFcs(fc, fieldLoc);

        _mKeyFcTypes.emplace(std::make_pair(&fc, this->_keyFcType(**keyFcs.begin())));
        return keyFcs;
    }

    /*
     * Adds to `keyFcs` the key field classes of `dependentFc`, using
     * the field location `fieldLoc`, from `baseFc` and the field
     * location item iterator `fieldLocIt`.
     *
     * Returns `true` if `dependentFc` isn't reached yet (safe to
     * continue to find key field classes).
     */
    bool _findKeyFcs(const Fc& baseFc, const Fc& dependentFc, const FieldLoc& fieldLoc,
                     const FieldLoc::Items::const_iterator fieldLocIt, _ConstFcSet& keyFcs) const
    {
        if (baseFc.isFixedLenBool() || baseFc.isInt()) {
            if (fieldLocIt != fieldLoc.end()) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, baseFc.loc(),
                    "Cannot reach anything beyond a scalar field class for {}.",
                    absFieldLocStr(fieldLoc, fieldLocIt + 1));
            }

            keyFcs.insert(&baseFc);
            return true;
        } else if (baseFc.isStruct()) {
            if (fieldLocIt == fieldLoc.end()) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, baseFc.loc(),
                    "Field location must not locate a structure field class.");
            }

            /* Find the member class named `**fieldLocIt` */
            for (auto& memberCls : baseFc.asStruct()) {
                if (&memberCls.fc() == &dependentFc) {
                    /* Reached the dependent field class */
                    return false;
                }

                if (memberCls.name() != **fieldLocIt) {
                    continue;
                }

                return this->_findKeyFcs(memberCls.fc(), dependentFc, fieldLoc, fieldLocIt + 1,
                                         keyFcs);
            }

            /* Member class not found */
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, baseFc.loc(),
                "At field location {}: no structure field member class named `{}`.",
                absFieldLocStr(fieldLoc, fieldLocIt), **fieldLocIt);
        } else if (baseFc.isArray()) {
            if (!bt2c::contains(_mCompoundFcIndexes, &baseFc)) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, baseFc.loc(),
                    "At field location {}: unreachable array field element.",
                    absFieldLocStr(fieldLoc, fieldLocIt));
            }

            auto& elemFc = baseFc.asArray().elemFc();

            if (&elemFc == &dependentFc) {
                /* Reached the dependent field class */
                return false;
            }

            return this->_findKeyFcs(elemFc, dependentFc, fieldLoc, fieldLocIt, keyFcs);
        } else if (baseFc.isOptional()) {
            if (!bt2c::contains(_mCompoundFcIndexes, &baseFc)) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, baseFc.loc(), "At field location {}: unreachable optional field.",
                    absFieldLocStr(fieldLoc, fieldLocIt));
            }

            auto& optionalFc = baseFc.asOptional().fc();

            if (&optionalFc == &dependentFc) {
                /* Reached the dependent field class */
                return false;
            }

            return this->_findKeyFcs(optionalFc, dependentFc, fieldLoc, fieldLocIt, keyFcs);
        } else if (baseFc.isVariant()) {
            auto& opts = baseFc.asVariantWithUIntSel().opts();
            const auto curOptIndexIt = _mCompoundFcIndexes.find(&baseFc);

            if (curOptIndexIt == _mCompoundFcIndexes.end()) {
                /*
                 * Not currently visiting this variant field class:
                 * consider all options.
                 */
                for (auto& opt : opts) {
                    if (&opt.fc() == &dependentFc) {
                        /* Reached the dependent field class */
                        return false;
                    }

                    if (!this->_findKeyFcs(opt.fc(), dependentFc, fieldLoc, fieldLocIt, keyFcs)) {
                        /* Reached the dependent field class */
                        return false;
                    }
                }
            } else {
                /*
                 * Currently visiting this variant field class: consider
                 * only the currently visited option.
                 */
                auto& optFc = opts[curOptIndexIt->second].fc();

                if (&optFc == &dependentFc) {
                    /* Reached the dependent field class */
                    return false;
                }

                return this->_findKeyFcs(optFc, dependentFc, fieldLoc, fieldLocIt, keyFcs);
            }

            return true;
        } else {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, baseFc.loc(), "At field location {}: unexpected type of field class.",
                absFieldLocStr(fieldLoc, fieldLocIt));
        }
    }

    /*
     * Returns the dependency type from the type of `fc`.
     */
    static KeyFcType _keyFcType(const Fc& fc) noexcept
    {
        if (fc.isFixedLenBool()) {
            return KeyFcType::Bool;
        } else if (fc.isUInt()) {
            return KeyFcType::UInt;
        } else {
            BT_ASSERT(fc.isSInt());
            return KeyFcType::SInt;
        }
    };

    /*
     * Returns the field class (within `_mCtx`) of the scope
     * of `fieldLoc`.
     */
    const Fc& _scopeFc(const FieldLoc& fieldLoc) const
    {
        /* Validate the scope first */
        if (static_cast<int>(*fieldLoc.origin()) > static_cast<int>(_mScope)) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                bt2c::Error, fieldLoc.loc(),
                "A field within a {} field cannot depend on another field "
                "within a {} field (unreachable).",
                scopeStr(_mScope), scopeStr(*fieldLoc.origin()));
        }

        /* Retrieve scope field class from `_mCtx` */
        const auto scopeFc = bt2c::call([this, &fieldLoc] {
            switch (*fieldLoc.origin()) {
            case Scope::PktHeader:
                return _mCtx.pktHeaderFc;
            case Scope::PktCtx:
                return _mCtx.pktCtxFc;
            case Scope::EventRecordHeader:
                return _mCtx.eventRecordHeaderFc;
            case Scope::CommonEventRecordCtx:
                return _mCtx.commonEventRecordCtxFc;
            case Scope::SpecEventRecordCtx:
                return _mCtx.specEventRecordCtxFc;
            case Scope::EventRecordPayload:
                return _mCtx.eventRecordPayloadFc;
            default:
                bt_common_abort();
            }
        });

        if (!scopeFc) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(bt2c::Error, fieldLoc.loc(),
                                                       "Missing required {} field class.",
                                                       scopeStr(*fieldLoc.origin()));
        }

        return *scopeFc;
    }

    /*
     * Finds the key field classes of `dependentFc` using the field
     * location `fieldLoc`.
     *
     * This method only considers boolean and integer field classes as
     * key field classes, throwing `bt2c::Error` when it finds
     * anything else.
     *
     * This method doesn't add to the returned set field classes which
     * occur after `dependentFc` .
     *
     * This method also throws if:
     *
     * • `fieldLoc` is invalid anyhow.
     *
     * • `fieldLoc` locates field classes having different key field
     *   class types.
     *
     * • `fieldLoc` doesn't locate any field class.
     */
    _ConstFcSet _findKeyFcs(const Fc& dependentFc, const FieldLoc& fieldLoc) const
    {
        try {
            /* Find key field classes and return them */
            _ConstFcSet keyFcs;

            this->_findKeyFcs(this->_scopeFc(fieldLoc), dependentFc, fieldLoc, fieldLoc.begin(),
                              keyFcs);

            /* Validate that `keyFcs` contains at least one item */
            if (keyFcs.empty()) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, fieldLoc.loc(), "Field location doesn't locate anything.");
            }

            /*
             * Validate that all the items of `keyFcs` have the
             * same type.
             */
            {
                const auto expectedType = this->_keyFcType(**keyFcs.begin());

                for (const auto fc : keyFcs) {
                    if (this->_keyFcType(*fc) != expectedType) {
                        BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                            bt2c::Error, fieldLoc.loc(),
                            "Field location locates field classes having different types "
                            "([{}] and [{}]).",
                            bt2c::textLocStr((*keyFcs.begin())->loc(), _mLogger.textLocStrFmt()),
                            bt2c::textLocStr(fc->loc(), _mLogger.textLocStrFmt()));
                    }
                }
            }

            /* Return the set */
            return keyFcs;
        } catch (const bt2c::Error&) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(fieldLoc.loc(),
                                                         "Invalid field location {}.",
                                                         absFieldLocStr(fieldLoc, fieldLoc.end()));
        }
    }

    /*
     * Validates the key field class type `keyFcType` for some
     * dynamic-length field class.
     */
    void _validateDynLenKeyFcType(const _ConstFcSet& keyFcs, const FieldLoc& fieldLoc) const
    {
        BT_ASSERT(!keyFcs.empty());

        if (this->_keyFcType(**keyFcs.begin()) != KeyFcType::UInt) {
            try {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW(
                    bt2c::Error, (*keyFcs.begin())->loc(),
                    "Expecting an unsigned integer field class.");
            } catch (const bt2c::Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW(
                    fieldLoc.loc(), "Invalid field location {}.",
                    absFieldLocStr(fieldLoc, fieldLoc.end()));
            }
        }
    }

    /*
     * In this order:
     *
     * 1. Marks the underlying field class at the index `index` of the
     *    compound field class `fc` as being currently visited.
     *
     * 2. Calls `func()`.
     *
     * 3. Cancels 1.
     */
    template <typename FuncT>
    void _withinCompoundFc(const Fc& fc, const std::size_t index, FuncT&& func)
    {
        BT_ASSERT(!bt2c::contains(_mCompoundFcIndexes, &fc));
        _mCompoundFcIndexes.emplace(std::make_pair(&fc, index));
        func();
        _mCompoundFcIndexes.erase(&fc);
    }

    /*
     * In this order:
     *
     * 1. Marks the compound field class `fc` as being
     *    currently visited.
     *
     * 2. Calls `func()`.
     *
     * 3. Cancels 1.
     */
    template <typename FuncT>
    void _withinCompoundFc(const Fc& fc, FuncT&& func)
    {
        this->_withinCompoundFc(fc, 0, std::forward<FuncT>(func));
    }

    bt2c::Logger _mLogger;
    Scope _mScope;
    _Ctx _mCtx;

    /* Result */
    KeyFcTypes _mKeyFcTypes;

    /*
     * Map of compound field classes to the index of the currently
     * visited immediate underlying field class, that is:
     *
     * For a variant field class F:
     *     Index of the option of F containing the field class currently
     *     being visited.
     *
     * For an array field class F:
     * For an optional field class F:
     *     0: if F is part of the map, then its element/optional field
     *     class is currently being visited.
     *
     * This is used to provide a visiting context to _findKeyFcs() so as
     * to follow the correct variant field class option as well as to
     * validate key field classes.
     *
     * For example:
     *
     *     Root: Structure FC                                       [0]
     *       `len`: Fixed-length unsigned integer FC                [1]
     *       `meow`: Dynamic-length array FC                        [2]
     *         Element FC: Structure FC                             [3]
     *           `tag`: Fixed-length signed integer FC              [4]
     *           `val`: Variant FC                                  [5]
     *             `boss`: Null-terminated string FC                [6]
     *             `zoom`: Structure FC                             [7]
     *               `len`: Variable-length unsigned integer FC     [8]
     *               `data`: Dynamic-length BLOB FC                 [9]
     *             `line6`: Structure FC                            [10]
     *               `len`: Fixed-length unsigned integer FC        [11]
     *
     * If _findKeyFcs() is currently visiting [9] to find its
     * dependencies, then the map would contain:
     *
     *     [2] → 0     (visiting current element of `/meow`)
     *     [5] → 1     (visiting second option (`zoom`) of `/meow/val`)
     *
     * This means that, if the length field location of [9] is
     * `/meow/val/len`, then we must only consider the `zoom` option,
     * not the `line6` one, even though both contain a member class
     * named `len`.
     */
    std::unordered_map<const Fc *, std::size_t> _mCompoundFcIndexes;
};

} /* namespace */

KeyFcTypes keyFcTypes(const Fc& scopeFc, const Scope scope, const Fc * const pktHeaderFc,
                      const Fc * const pktCtxFc, const Fc * const eventRecordHeaderFc,
                      const Fc * const commonEventRecordCtxFc,
                      const Fc * const specEventRecordCtxFc, const Fc * const eventRecordPayloadFc,
                      const bt2c::Logger& parentLogger)
{
    KeyFcTypesFinder finder {scope,
                             pktHeaderFc,
                             pktCtxFc,
                             eventRecordHeaderFc,
                             commonEventRecordCtxFc,
                             specEventRecordCtxFc,
                             eventRecordPayloadFc,
                             parentLogger};

    scopeFc.accept(finder);
    return finder.takeKeyFcTypes();
}

} /* namespace src */
} /* namespace ctf */
