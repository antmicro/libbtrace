/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2022-2024 Philippe Proulx <pproulx@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_METADATA_CTF_IR_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_METADATA_CTF_IR_HPP

#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "cpp-common/bt2/clock-class.hpp"
#include "cpp-common/bt2/field-class.hpp"
#include "cpp-common/bt2/trace-ir.hpp"
#include "cpp-common/bt2c/data-len.hpp"
#include "cpp-common/bt2s/make-unique.hpp"
#include "cpp-common/bt2s/optional.hpp"
#include "cpp-common/vendor/wise-enum/wise_enum.h"

#include "int-range-set.hpp"

namespace ctf {
namespace ir {

/*
 * This is the common CTF IR API, that is, the intermediate
 * representation of CTF metadata objects for the whole `ctf` plugin.
 *
 * CLASS HIERARCHY
 * ━━━━━━━━━━━━━━━
 * The class hierarchy (omitting template parameters) is as such:
 *
 *     TraceCls
 *     DataStreamCls
 *     EventRecordCls
 *     ClkCls
 *     FieldLoc
 *     StructFieldMemberCls
 *     VariantFcOpt
 *     Fc
 *       FixedLenBitArrayFc
 *         FixedLenBitMapFc
 *         FixedLenBoolFc
 *         FixedLenFloatFc
 *         FixedLenIntFc
 *           FixedLenUIntFc
 *           FixedLenSIntFc
 *       VarLengthIntFc
 *         VarLengthUIntFc
 *         VarLengthSIntFc
 *       StrFc
 *         NullTerminatedStrFc
 *         NonNullTerminatedStrFc
 *           StaticLenStrFc
 *           DynLenStrFc
 *       BlobFc
 *         StaticLenBlobFc
 *         DynLenBlobFc
 *       ArrayFc
 *         StaticLenArrayFc
 *         DynLenArrayFc
 *       StructFc
 *       OptionalFc
 *         OptionalWithBoolSelFc
 *         OptionalWithIntSelFc
 *           OptionalWithUIntSelFc
 *           OptionalWithSIntSelFc
 *       VariantFc
 *         VariantWithUIntSelFc
 *         VariantWithSIntSelFc
 *
 * The `FcVisitor` and `ConstFcVisitor` base classes are available to
 * visit field classes through the virtual Fc::accept() methods.
 *
 * Each class template has the `UserMixinsT` template parameter.
 *
 * USER MIXINS
 * ━━━━━━━━━━━
 * `UserMixinsT` is expected to be a user mixin container, a type which
 * defines the following nested types (user mixins):
 *
 * • `ClkCls`
 * • `DataStreamCls`
 * • `DynLenArrayFc`
 * • `DynLenBlobFc`
 * • `DynLenStrFc`
 * • `EventRecordCls`
 * • `Fc`
 * • `FieldLoc`
 * • `FixedLenBitArrayFc`
 * • `FixedLenBitMapFc`
 * • `FixedLenBoolFc`
 * • `FixedLenIntFc`
 * • `FixedLenUIntFc`
 * • `OptionalFc`
 * • `OptionalWithBoolSelFc`
 * • `OptionalWithSIntSelFc`
 * • `OptionalWithUIntSelFc`
 * • `StaticLenArrayFc`
 * • `StaticLenBlobFc`
 * • `StaticLenStrFc`
 * • `StructFc`
 * • `StructFieldMemberCls`
 * • `TraceCls`
 * • `VariantFcOpt`
 * • `VariantWithSIntSelFc`
 * • `VariantWithUIntSelFc`
 * • `VarLenIntFc`
 * • `VarLenUIntFc`
 *
 * Most class templates inherit a given user mixin. For example,
 * `FixedLenBoolFc` inherits `UserMixinsT::FixedLenBoolFc`. This makes
 * it possible for the user to inject data and methods into the class
 * while keeping the hierarchy and common features.
 *
 * A class template which inherits a user mixin M has a constructor
 * which accepts an instance of M by value to initialize this part of
 * the object.
 *
 * If a class template C which inherits a user mixin also inherits
 * another class template inheriting another user mixin, then the
 * constructor of C accepts both mixins. For example,
 * FixedLenUIntFc::FixedLenUIntFc() accepts three mixins: field class,
 * fixed-length bit array field class, and fixed-length integer
 * field class.
 *
 * A mixin must be copy-constructible to make the Fc::clone()
 * method work.
 *
 * The API offers `DefUserMixins` which defines empty user mixins to act
 * as a base user mixin container structure.
 *
 * USAGE
 * ━━━━━
 * This is how you would use this API:
 *
 * • Define your own user mixin container structure which inherits
 *   `DefUserMixins`, defining the user mixins you need to add data and
 *   methods to specific common classes.
 *
 * • Define aliases for each `ctf::ir` type you need, using your user
 *   mixin container structure as the `UserMixinsT` template parameter
 *   when needed.
 *
 * • Create convenient object creation functions to construct specific
 *   CTF IR objects from parameters, hiding the internal user
 *   mixin details.
 */

template <typename UserMixinsT>
class FixedLenBitArrayFc;

template <typename UserMixinsT>
class FixedLenBitMapFc;

template <typename UserMixinsT>
class FixedLenBoolFc;

template <typename UserMixinsT>
class FixedLenFloatFc;

template <typename UserMixinsT>
class FixedLenIntFc;

template <typename UserMixinsT>
class FixedLenUIntFc;

template <typename UserMixinsT>
class FixedLenSIntFc;

template <typename UserMixinsT>
class VarLenIntFc;

template <typename UserMixinsT>
class VarLenSIntFc;

template <typename UserMixinsT>
class VarLenUIntFc;

template <typename UserMixinsT>
class StrFc;

template <typename UserMixinsT>
class NullTerminatedStrFc;

template <typename UserMixinsT>
class NonNullTerminatedStrFc;

template <typename UserMixinsT>
class StaticLenStrFc;

template <typename UserMixinsT>
class DynLenStrFc;

template <typename UserMixinsT>
class BlobFc;

template <typename UserMixinsT>
class StaticLenBlobFc;

template <typename UserMixinsT>
class DynLenBlobFc;

template <typename UserMixinsT>
class ArrayFc;

template <typename UserMixinsT>
class StaticLenArrayFc;

template <typename UserMixinsT>
class DynLenArrayFc;

template <typename UserMixinsT>
class StructFc;

template <typename UserMixinsT>
class OptionalFc;

template <typename UserMixinsT>
class OptionalWithBoolSelFc;

template <typename UserMixinsT>
class OptionalWithUIntSelFc;

template <typename UserMixinsT>
class OptionalWithSIntSelFc;

template <typename UserMixinsT>
class VariantWithUIntSelFc;

template <typename UserMixinsT>
class VariantWithSIntSelFc;

/*
 * Visitor of `Fc<UserMixinsT>`.
 *
 * See `ConstFcVisitor` which visits `const Fc<UserMixinsT>`.
 */
template <typename UserMixinsT>
class FcVisitor
{
protected:
    explicit FcVisitor() = default;

public:
    virtual ~FcVisitor() = default;

    virtual void visit(FixedLenBitArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenBitMapFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenBoolFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenFloatFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(FixedLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(VarLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(VarLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(NullTerminatedStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(StaticLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(DynLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(StaticLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(DynLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(StaticLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(DynLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(StructFc<UserMixinsT>&)
    {
    }

    virtual void visit(OptionalWithBoolSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(OptionalWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(OptionalWithSIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(VariantWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(VariantWithSIntSelFc<UserMixinsT>&)
    {
    }
};

/*
 * Visitor of `const Fc<UserMixinsT>`.
 *
 * See `FcVisitor` which visits `Fc<UserMixinsT>`.
 */
template <typename UserMixinsT>
class ConstFcVisitor
{
protected:
    explicit ConstFcVisitor() = default;

public:
    virtual ~ConstFcVisitor() = default;

    virtual void visit(const FixedLenBitArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenBitMapFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenBoolFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenFloatFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const FixedLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VarLenSIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VarLenUIntFc<UserMixinsT>&)
    {
    }

    virtual void visit(const NullTerminatedStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StaticLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(const DynLenStrFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StaticLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(const DynLenBlobFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StaticLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(const DynLenArrayFc<UserMixinsT>&)
    {
    }

    virtual void visit(const StructFc<UserMixinsT>&)
    {
    }

    virtual void visit(const OptionalWithBoolSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const OptionalWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const OptionalWithSIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VariantWithUIntSelFc<UserMixinsT>&)
    {
    }

    virtual void visit(const VariantWithSIntSelFc<UserMixinsT>&)
    {
    }
};

namespace internal {

/* clang-format off */

/*
 * To make the Fc<UserMixinsT>::isXyz() methods more efficient, `FcType`
 * enumerators (below) are bitwise compositions of `FcTypeTraits` values
 * (traits/features). The isXyz() methods only check if specific bits of
 * the field class type are set.
 */
struct FcTypeTraits final
{
    enum {
        FixedOrStaticLen    = 1 << 0,
        VarOrDynLen         = 1 << 1,
        BitArray            = 1 << 2,
        BitMap              = 1 << 3,
        Bool                = 1 << 4,
        Int                 = 1 << 5,
        UInt                = (1 << 6) | Int,
        SInt                = (1 << 7) | Int,
        Float               = 1 << 8,
        Str                 = 1 << 9,
        NullTerminated      = 1 << 10,
        NonNullTerminated   = 1 << 11,
        Blob                = 1 << 12,
        Array               = 1 << 13,
        Struct              = 1 << 14,
        BoolSel             = 1 << 15,
        IntSel              = 1 << 16,
        UIntSel             = (1 << 17) | IntSel,
        SIntSel             = (1 << 18) | IntSel,
        Optional            = 1 << 19,
        Variant             = 1 << 20,
    };
};

/* clang-format on */

} /* namespace internal */

/* clang-format off */

/*
 * Field class type.
 */
WISE_ENUM_CLASS(FcType,
    (FixedLenBitArray,      internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::BitArray),

    (FixedLenBitMap,        internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::BitArray |
                            internal::FcTypeTraits::BitMap),

    (FixedLenBool,          internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::BitArray |
                            internal::FcTypeTraits::Bool),

    (FixedLenUInt,          internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::BitArray |
                            internal::FcTypeTraits::UInt),

    (FixedLenSInt,          internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::BitArray |
                            internal::FcTypeTraits::SInt),

    (FixedLenFloat,         internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::BitArray |
                            internal::FcTypeTraits::Float),

    (VarLenUInt,            internal::FcTypeTraits::VarOrDynLen |
                            internal::FcTypeTraits::UInt),

    (VarLenSInt,            internal::FcTypeTraits::VarOrDynLen |
                            internal::FcTypeTraits::SInt),

    (NullTerminatedStr,     internal::FcTypeTraits::NullTerminated |
                            internal::FcTypeTraits::Str),

    (StaticLenStr,          internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::NonNullTerminated |
                            internal::FcTypeTraits::Str),

    (DynLenStr,             internal::FcTypeTraits::VarOrDynLen |
                            internal::FcTypeTraits::NonNullTerminated |
                            internal::FcTypeTraits::Str),

    (StaticLenBlob,         internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::Blob),

    (DynLenBlob,            internal::FcTypeTraits::VarOrDynLen |
                            internal::FcTypeTraits::Blob),

    (StaticLenArray,        internal::FcTypeTraits::FixedOrStaticLen |
                            internal::FcTypeTraits::Array),

    (DynLenArray,           internal::FcTypeTraits::VarOrDynLen |
                            internal::FcTypeTraits::Array),

    (Struct,                internal::FcTypeTraits::Struct),

    (OptionalWithBoolSel,   internal::FcTypeTraits::Optional |
                            internal::FcTypeTraits::BoolSel),

    (OptionalWithUIntSel,   internal::FcTypeTraits::Optional |
                            internal::FcTypeTraits::UIntSel),

    (OptionalWithSIntSel,   internal::FcTypeTraits::Optional |
                            internal::FcTypeTraits::SIntSel),

    (VariantWithUIntSel,    internal::FcTypeTraits::Variant |
                            internal::FcTypeTraits::UIntSel),

    (VariantWithSIntSel,    internal::FcTypeTraits::Variant |
                            internal::FcTypeTraits::SIntSel)
)

/* clang-format on */

/*
 * Optional attributes.
 */
using OptAttrs = bt2::ConstMapValue::Shared;

namespace internal {

/*
 * Internal mixin for classes with an optional equivalent libbabeltrace2
 * class.
 */
template <typename ClsT>
class WithLibCls
{
public:
    /*
     * Equivalent libbabeltrace2 class (borrowed).
     */
    const bt2::OptionalBorrowedObject<ClsT> libCls() const noexcept
    {
        return _mLibCls;
    }

    /*
     * Equivalent libbabeltrace2 class (borrowed).
     */
    bt2::OptionalBorrowedObject<ClsT> libCls() noexcept
    {
        return _mLibCls;
    }

    /*
     * Sets the equivalent libbabeltrace2 class to `libCls` (borrowed).
     */
    void libCls(const ClsT libCls) noexcept
    {
        _mLibCls = libCls;
    }

private:
    /* Equivalent libbabeltrace2 class (borrowed) */
    bt2::OptionalBorrowedObject<ClsT> _mLibCls;
};

/*
 * Internal mixin for classes with attributes.
 */
class WithAttrsMixin
{
protected:
    explicit WithAttrsMixin(OptAttrs attrs) : _mAttrs {std::move(attrs)}
    {
    }

public:
    /*
     * Attributes of this object.
     */
    const OptAttrs& attrs() const noexcept
    {
        return _mAttrs;
    }

protected:
    /*
     * Moves the attributes to the caller.
     */
    OptAttrs _takeAttrs() noexcept
    {
        return std::move(_mAttrs);
    }

private:
    /* Attributes of this object */
    OptAttrs _mAttrs;
};

} /* namespace internal */

/*
 * Field class base.
 *
 * Specific properties:
 *
 * • Alignment of instances.
 * • Attributes.
 */
template <typename UserMixinsT>
class Fc :
    public internal::WithAttrsMixin,
    public internal::WithLibCls<bt2::FieldClass>,
    public UserMixinsT::Fc
{
public:
    using Type = FcType;
    using UP = std::unique_ptr<Fc>;

protected:
    explicit Fc(const FcType type, typename UserMixinsT::Fc mixin, const unsigned int align,
                OptAttrs&& attrs) :
        internal::WithAttrsMixin {std::move(attrs)}, UserMixinsT::Fc {std::move(mixin)},
        _mType {type}, _mAlign {align}
    {
    }

public:
    /* Disable copy/move operations to make this API simpler */
    Fc(const Fc&) = delete;
    Fc(Fc&&) = delete;
    Fc& operator=(const Fc&) = delete;
    Fc& operator=(Fc&&) = delete;

    virtual ~Fc() = default;

    Type type() const noexcept
    {
        return _mType;
    }

    /*
     * Alignment (bits) of instances of this field class.
     */
    unsigned int align() const noexcept
    {
        return _mAlign;
    }

    /*
     * Moves the attributes of this field class to the caller.
     */
    OptAttrs takeAttrs() noexcept
    {
        return this->_takeAttrs();
    }

    /*
     * Clones this field class and returns the clone.
     */
    virtual UP clone() const = 0;

    /*
     * Accepts a visitor to visit this field class.
     */
    virtual void accept(FcVisitor<UserMixinsT>&) = 0;

    /*
     * Accepts a visitor to visit this constant field class.
     */
    virtual void accept(ConstFcVisitor<UserMixinsT>&) const = 0;

    /* Casting methods below */
    FixedLenBitArrayFc<UserMixinsT>& asFixedLenBitArray() noexcept;
    const FixedLenBitArrayFc<UserMixinsT>& asFixedLenBitArray() const noexcept;
    FixedLenBitMapFc<UserMixinsT>& asFixedLenBitMap() noexcept;
    const FixedLenBitMapFc<UserMixinsT>& asFixedLenBitMap() const noexcept;
    FixedLenBoolFc<UserMixinsT>& asFixedLenBool() noexcept;
    const FixedLenBoolFc<UserMixinsT>& asFixedLenBool() const noexcept;
    FixedLenFloatFc<UserMixinsT>& asFixedLenFloat() noexcept;
    const FixedLenFloatFc<UserMixinsT>& asFixedLenFloat() const noexcept;
    FixedLenIntFc<UserMixinsT>& asFixedLenInt() noexcept;
    const FixedLenIntFc<UserMixinsT>& asFixedLenInt() const noexcept;
    FixedLenSIntFc<UserMixinsT>& asFixedLenSInt() noexcept;
    const FixedLenSIntFc<UserMixinsT>& asFixedLenSInt() const noexcept;
    FixedLenUIntFc<UserMixinsT>& asFixedLenUInt() noexcept;
    const FixedLenUIntFc<UserMixinsT>& asFixedLenUInt() const noexcept;
    VarLenIntFc<UserMixinsT>& asVarLenInt() noexcept;
    const VarLenIntFc<UserMixinsT>& asVarLenInt() const noexcept;
    VarLenUIntFc<UserMixinsT>& asVarLenUInt() noexcept;
    const VarLenUIntFc<UserMixinsT>& asVarLenUInt() const noexcept;
    VarLenSIntFc<UserMixinsT>& asVarLenSInt() noexcept;
    const VarLenSIntFc<UserMixinsT>& asVarLenSInt() const noexcept;
    StrFc<UserMixinsT>& asStr() noexcept;
    const StrFc<UserMixinsT>& asStr() const noexcept;
    NullTerminatedStrFc<UserMixinsT>& asNullTerminatedStr() noexcept;
    const NullTerminatedStrFc<UserMixinsT>& asNullTerminatedStr() const noexcept;
    NonNullTerminatedStrFc<UserMixinsT>& asNonNullTerminatedStr() noexcept;
    const NonNullTerminatedStrFc<UserMixinsT>& asNonNullTerminatedStr() const noexcept;
    StaticLenStrFc<UserMixinsT>& asStaticLenStr() noexcept;
    const StaticLenStrFc<UserMixinsT>& asStaticLenStr() const noexcept;
    DynLenStrFc<UserMixinsT>& asDynLenStr() noexcept;
    const DynLenStrFc<UserMixinsT>& asDynLenStr() const noexcept;
    BlobFc<UserMixinsT>& asBlob() noexcept;
    const BlobFc<UserMixinsT>& asBlob() const noexcept;
    StaticLenBlobFc<UserMixinsT>& asStaticLenBlob() noexcept;
    const StaticLenBlobFc<UserMixinsT>& asStaticLenBlob() const noexcept;
    DynLenBlobFc<UserMixinsT>& asDynLenBlob() noexcept;
    const DynLenBlobFc<UserMixinsT>& asDynLenBlob() const noexcept;
    ArrayFc<UserMixinsT>& asArray() noexcept;
    const ArrayFc<UserMixinsT>& asArray() const noexcept;
    StaticLenArrayFc<UserMixinsT>& asStaticLenArray() noexcept;
    const StaticLenArrayFc<UserMixinsT>& asStaticLenArray() const noexcept;
    DynLenArrayFc<UserMixinsT>& asDynLenArray() noexcept;
    const DynLenArrayFc<UserMixinsT>& asDynLenArray() const noexcept;
    StructFc<UserMixinsT>& asStruct() noexcept;
    const StructFc<UserMixinsT>& asStruct() const noexcept;
    OptionalFc<UserMixinsT>& asOptional() noexcept;
    const OptionalFc<UserMixinsT>& asOptional() const noexcept;
    OptionalWithBoolSelFc<UserMixinsT>& asOptionalWithBoolSel() noexcept;
    const OptionalWithBoolSelFc<UserMixinsT>& asOptionalWithBoolSel() const noexcept;
    OptionalWithUIntSelFc<UserMixinsT>& asOptionalWithUIntSel() noexcept;
    const OptionalWithUIntSelFc<UserMixinsT>& asOptionalWithUIntSel() const noexcept;
    OptionalWithSIntSelFc<UserMixinsT>& asOptionalWithSIntSel() noexcept;
    const OptionalWithSIntSelFc<UserMixinsT>& asOptionalWithSIntSel() const noexcept;
    VariantWithUIntSelFc<UserMixinsT>& asVariantWithUIntSel() noexcept;
    const VariantWithUIntSelFc<UserMixinsT>& asVariantWithUIntSel() const noexcept;
    VariantWithSIntSelFc<UserMixinsT>& asVariantWithSIntSel() noexcept;
    const VariantWithSIntSelFc<UserMixinsT>& asVariantWithSIntSel() const noexcept;

    bool isFixedLenBitArray() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::FixedOrStaticLen |
                                   internal::FcTypeTraits::BitArray);
    }

    bool isFixedLenBitMap() const noexcept
    {
        return _mType == Type::FixedLenBitMap;
    }

    bool isFixedLenBool() const noexcept
    {
        return _mType == Type::FixedLenBool;
    }

    bool isFixedLenFloat() const noexcept
    {
        return _mType == Type::FixedLenFloat;
    }

    bool isInt() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::Int);
    }

    bool isUInt() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::UInt);
    }

    bool isSInt() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::SInt);
    }

    bool isFixedLenInt() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::FixedOrStaticLen |
                                   internal::FcTypeTraits::Int);
    }

    bool isFixedLenUInt() const noexcept
    {
        return _mType == Type::FixedLenUInt;
    }

    bool isFixedLenSInt() const noexcept
    {
        return _mType == Type::FixedLenSInt;
    }

    bool isVarLenInt() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::VarOrDynLen |
                                   internal::FcTypeTraits::Int);
    }

    bool isVarLenUInt() const noexcept
    {
        return _mType == Type::VarLenUInt;
    }

    bool isVarLenSInt() const noexcept
    {
        return _mType == Type::VarLenSInt;
    }

    bool isStr() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::Str);
    }

    bool isNullTerminatedStr() const noexcept
    {
        return _mType == Type::NullTerminatedStr;
    }

    bool isNonNullTerminatedStr() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::NonNullTerminated);
    }

    bool isStaticLenStr() const noexcept
    {
        return _mType == Type::StaticLenStr;
    }

    bool isDynLenStr() const noexcept
    {
        return _mType == Type::DynLenStr;
    }

    bool isBlob() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::Blob);
    }

    bool isStaticLenBlob() const noexcept
    {
        return _mType == Type::StaticLenBlob;
    }

    bool isDynLenBlob() const noexcept
    {
        return _mType == Type::DynLenBlob;
    }

    bool isArray() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::Array);
    }

    bool isStaticLenArray() const noexcept
    {
        return _mType == Type::StaticLenArray;
    }

    bool isDynLenArray() const noexcept
    {
        return _mType == Type::DynLenArray;
    }

    bool isStruct() const noexcept
    {
        return _mType == Type::Struct;
    }

    bool isOptional() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::Optional);
    }

    bool isOptionalWithBoolSel() const noexcept
    {
        return _mType == Type::OptionalWithBoolSel;
    }

    bool isOptionalWithIntSel() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::Optional |
                                   internal::FcTypeTraits::IntSel);
    }

    bool isOptionalWithUIntSel() const noexcept
    {
        return _mType == Type::OptionalWithUIntSel;
    }

    bool isOptionalWithSIntSel() const noexcept
    {
        return _mType == Type::OptionalWithSIntSel;
    }

    bool isVariant() const noexcept
    {
        return this->_hasTypeTrait(internal::FcTypeTraits::Variant);
    }

    bool isVariantWithUIntSel() const noexcept
    {
        return _mType == Type::VariantWithUIntSel;
    }

    bool isVariantWithSIntSel() const noexcept
    {
        return _mType == Type::VariantWithSIntSel;
    }

private:
    /*
     * Returns whether or not this field class has the type trait
     * `typeTrait` (one or more bitwise-OR combined `FcTypeTraits`
     * enumerators).
     */
    bool _hasTypeTrait(const int typeTrait) const noexcept
    {
        return (static_cast<int>(_mType) & typeTrait) == typeTrait;
    }

    /* Type of this field class */
    Type _mType;

    /* Alignment (bits) of instances of this field class */
    unsigned int _mAlign;
};

/* clang-format off */

/*
 * Byte order.
 */
WISE_ENUM_CLASS(ByteOrder,
    /* Big-endian */
    Big,

    /* Little-endian */
    Little
)

/*
 * Bit order.
 */
WISE_ENUM_CLASS(BitOrder,
    /* First to last */
    FirstToLast,

    /* Last to first */
    LastToFirst
)

/* clang-format on */

/*
 * Fixed-length bit array field class.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Length of instances.
 * • Byte order of instances.
 * • Bit order of instances.
 */
template <typename UserMixinsT>
class FixedLenBitArrayFc : public Fc<UserMixinsT>, public UserMixinsT::FixedLenBitArrayFc
{
protected:
    explicit FixedLenBitArrayFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                                typename UserMixinsT::FixedLenBitArrayFc mixin,
                                const unsigned int align, const bt2c::DataLen len,
                                const ByteOrder byteOrder, const bt2s::optional<BitOrder>& bitOrder,
                                OptAttrs&& attrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), align, std::move(attrs)},
        UserMixinsT::FixedLenBitArrayFc(std::move(mixin)), _mLen {len}, _mByteOrder {byteOrder},
        _mBitOrder {bitOrder ? *bitOrder :
                               (byteOrder == ByteOrder::Big ? BitOrder::LastToFirst :
                                                              BitOrder::FirstToLast)}
    {
        using namespace bt2c::literals::datalen;

        BT_ASSERT(len > 0_bits && len <= 64_bits);
        BT_ASSERT(align > 0);
    }

public:
    explicit FixedLenBitArrayFc(typename UserMixinsT::Fc fcMixin,
                                typename UserMixinsT::FixedLenBitArrayFc mixin,
                                const unsigned int align, const bt2c::DataLen len,
                                const ByteOrder byteOrder,
                                const bt2s::optional<BitOrder>& bitOrder = bt2s::nullopt,
                                OptAttrs attrs = OptAttrs {}) :
        FixedLenBitArrayFc {FcType::FixedLenBitArray,
                            std::move(fcMixin),
                            std::move(mixin),
                            align,
                            len,
                            byteOrder,
                            bitOrder,
                            std::move(attrs)}
    {
    }

    /*
     * Length of instances of this field class.
     */
    bt2c::DataLen len() const noexcept
    {
        return _mLen;
    }

    /*
     * Byte order of instances of this field class.
     */
    ByteOrder byteOrder() const noexcept
    {
        return _mByteOrder;
    }

    /*
     * Bit order of instances of this field class.
     */
    BitOrder bitOrder() const noexcept
    {
        return _mBitOrder;
    }

    /*
     * Returns whether or not the bits of instances of a fixed-length
     * bit array field class having the byte order `byteOrder` and the
     * bit order `bitOrder` (deduced from `byteOrder` if
     * `bt2s::nullopt`) are reversed, that is, in an unnatural way.
     */
    static bool isRev(const ByteOrder byteOrder, const bt2s::optional<BitOrder>& bitOrder) noexcept
    {
        if (!bitOrder) {
            return false;
        }

        return (byteOrder == ByteOrder::Big && *bitOrder == BitOrder::FirstToLast) ||
               (byteOrder == ByteOrder::Little && *bitOrder == BitOrder::LastToFirst);
    }

    /*
     * Like isRev() above, but using the properties of this field class.
     */
    bool isRev() const noexcept
    {
        return FixedLenBitArrayFc::isRev(_mByteOrder, _mBitOrder);
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenBitArrayFc>(*this, *this, this->align(), _mLen,
                                                     _mByteOrder, _mBitOrder, this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    /* Length of instances of this field class */
    bt2c::DataLen _mLen;

    /* Byte order of instances of this field class */
    ByteOrder _mByteOrder;

    /* Bit order of instances of this field class */
    BitOrder _mBitOrder;
};

/*
 * Fixed-length bit map field class.
 *
 * Specific property over `FixedLenBitArrayFc<UserMixinsT>`:
 *
 * • Flags of instances.
 */
template <typename UserMixinsT>
class FixedLenBitMapFc final :
    public FixedLenBitArrayFc<UserMixinsT>,
    public UserMixinsT::FixedLenBitMapFc
{
public:
    using Flags = std::unordered_map<std::string, UIntRangeSet>;

    explicit FixedLenBitMapFc(typename UserMixinsT::Fc fcMixin,
                              typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                              typename UserMixinsT::FixedLenBitMapFc mixin,
                              const unsigned int align, const bt2c::DataLen len,
                              const ByteOrder byteOrder, Flags flags,
                              const bt2s::optional<BitOrder>& bitOrder = bt2s::nullopt,
                              OptAttrs attrs = OptAttrs {}) :
        FixedLenBitArrayFc<UserMixinsT> {FcType::FixedLenBitMap,
                                         std::move(fcMixin),
                                         std::move(fixedLenBitArrayFcMixin),
                                         align,
                                         len,
                                         byteOrder,
                                         bitOrder,
                                         std::move(attrs)},
        UserMixinsT::FixedLenBitMapFc(std::move(mixin)), _mFlags {std::move(flags)}
    {
        BT_ASSERT(!_mFlags.empty());
    }

    /*
     * Flags of this fixed-length bit map field class.
     */
    const Flags& flags() const noexcept
    {
        return _mFlags;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenBitMapFc>(*this, *this, *this, this->align(), this->len(),
                                                   this->byteOrder(), _mFlags, this->bitOrder(),
                                                   this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    Flags _mFlags;
};

/*
 * Fixed-length boolean field class.
 */
template <typename UserMixinsT>
class FixedLenBoolFc final :
    public FixedLenBitArrayFc<UserMixinsT>,
    public UserMixinsT::FixedLenBoolFc
{
public:
    explicit FixedLenBoolFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenBoolFc mixin, const unsigned int align,
                            const bt2c::DataLen len, const ByteOrder byteOrder,
                            const bt2s::optional<BitOrder>& bitOrder = bt2s::nullopt,
                            OptAttrs attrs = OptAttrs {}) :
        FixedLenBitArrayFc<UserMixinsT> {FcType::FixedLenBool,
                                         std::move(fcMixin),
                                         std::move(fixedLenBitArrayFcMixin),
                                         align,
                                         len,
                                         byteOrder,
                                         bitOrder,
                                         std::move(attrs)},
        UserMixinsT::FixedLenBoolFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenBoolFc>(*this, *this, *this, this->align(), this->len(),
                                                 this->byteOrder(), this->bitOrder(),
                                                 this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Fixed-length floating-point number field class.
 */
template <typename UserMixinsT>
class FixedLenFloatFc final : public FixedLenBitArrayFc<UserMixinsT>
{
public:
    explicit FixedLenFloatFc(typename UserMixinsT::Fc fcMixin,
                             typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                             const unsigned int align, const bt2c::DataLen len,
                             const ByteOrder byteOrder,
                             const bt2s::optional<BitOrder>& bitOrder = bt2s::nullopt,
                             OptAttrs attrs = OptAttrs {}) :
        FixedLenBitArrayFc<UserMixinsT> {FcType::FixedLenFloat,
                                         std::move(fcMixin),
                                         std::move(fixedLenBitArrayFcMixin),
                                         align,
                                         len,
                                         byteOrder,
                                         bitOrder,
                                         std::move(attrs)}
    {
        using namespace bt2c::literals::datalen;

        BT_ASSERT(len == 32_bits || len == 64_bits);
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenFloatFc>(*this, *this, this->align(), this->len(),
                                                  this->byteOrder(), this->bitOrder(),
                                                  this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/* clang-format off */

/*
 * Display base.
 */
WISE_ENUM_CLASS(DispBase,
    /* Binary */
    (Bin, 2),

    /* Octal */
    (Oct, 8),

    /* Decimal */
    (Dec, 10),

    /* Hexadecimal */
    (Hex, 16)
)

/* clang-format on */

namespace internal {

/*
 * Internal mixin for integer field classes with a preferred display
 * base.
 */
class WithPrefDispBaseMixin
{
protected:
    explicit WithPrefDispBaseMixin(const DispBase prefDispBase) : _mPrefDispBase {prefDispBase}
    {
    }

public:
    /*
     * Preferred display base of instances of this field class.
     */
    DispBase prefDispBase() const noexcept
    {
        return _mPrefDispBase;
    }

private:
    /* Preferred display base of instances of this field class */
    DispBase _mPrefDispBase;
};

/*
 * Internal mixin for integer field classes with mappings.
 */
template <typename MappingRangeSetT>
class WithMappingsMixin
{
public:
    using Mappings = std::unordered_map<std::string, MappingRangeSetT>;
    using Val = typename MappingRangeSetT::Val;

protected:
    explicit WithMappingsMixin(Mappings&& mappings) : _mMappings {std::move(mappings)}
    {
    }

public:
    /*
     * Mappings of instances of this integer field class.
     */
    const Mappings& mappings() const noexcept
    {
        return _mMappings;
    }

private:
    /* Mappings of instances of this integer field class */
    Mappings _mMappings;
};

} /* namespace internal */

/*
 * Fixed-length integer field class base.
 *
 * Specific property over `FixedLenBitArrayFc<UserMixinsT>`:
 *
 * • Preferred display base of instances.
 */
template <typename UserMixinsT>
class FixedLenIntFc :
    public FixedLenBitArrayFc<UserMixinsT>,
    public internal::WithPrefDispBaseMixin,
    public UserMixinsT::FixedLenIntFc
{
protected:
    explicit FixedLenIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                           typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                           typename UserMixinsT::FixedLenIntFc mixin, const unsigned int align,
                           const bt2c::DataLen len, const ByteOrder byteOrder,
                           const bt2s::optional<BitOrder>& bitOrder, const DispBase prefDispBase,
                           OptAttrs&& attrs) :
        FixedLenBitArrayFc<UserMixinsT> {
            type,     std::move(fcMixin), std::move(fixedLenBitArrayFcMixin), align, len, byteOrder,
            bitOrder, std::move(attrs)},
        internal::WithPrefDispBaseMixin {prefDispBase},
        UserMixinsT::FixedLenIntFc {std::move(mixin)}
    {
    }
};

/* clang-format off */

/*
 * Unsigned integer field role.
 */
WISE_ENUM_CLASS(UIntFieldRole,
    /* Packet magic number */
    (PktMagicNumber,                1 << 1),

    /* Data stream class ID */
    (DataStreamClsId,               1 << 2),

    /* Data stream ID */
    (DataStreamId,                  1 << 3),

    /* Total length of packet */
    (PktTotalLen,                   1 << 4),

    /* Content length of packet */
    (PktContentLen,                 1 << 5),

    /* Default clock timestamp */
    (DefClkTs,                      1 << 6),

    /* Default clock timestamp at end of packet */
    (PktEndDefClkTs,                1 << 7),

    /* Discarded event record counter snapshot */
    (DiscEventRecordCounterSnap,    1 << 8),

    /* Packet sequence number */
    (PktSeqNum,                     1 << 9),

    /* Event record class ID */
    (EventRecordClsId,              1 << 10)
)

/* clang-format on */

/*
 * Set of unsigned integer field roles.
 */
using UIntFieldRoles = std::set<UIntFieldRole>;

namespace internal {

/*
 * Internal mixin for unsigned integer field class classes.
 */
class UIntFcMixin
{
protected:
    explicit UIntFcMixin(UIntFieldRoles roles) : _mRoles {std::move(roles)}
    {
    }

public:
    /*
     * Roles of instances of this unsigned integer field class.
     */
    const UIntFieldRoles& roles() const noexcept
    {
        return _mRoles;
    }

    /*
     * Returns whether or not the instances of this field class have the
     * role `role`.
     */
    bool hasRole(const UIntFieldRole role) const noexcept
    {
        return _mRoles.count(role) == 1;
    }

private:
    /* Roles of instances of this unsigned integer field class */
    UIntFieldRoles _mRoles;
};

} /* namespace internal */

/*
 * Fixed-length unsigned integer field class.
 *
 * Specific properties over `FixedLenIntFc<UserMixinsT>`:
 *
 * • Mappings.
 * • Roles of instances.
 */
template <typename UserMixinsT>
class FixedLenUIntFc final :
    public FixedLenIntFc<UserMixinsT>,
    public internal::WithMappingsMixin<UIntRangeSet>,
    public internal::UIntFcMixin,
    public UserMixinsT::FixedLenUIntFc
{
public:
    using typename internal::WithMappingsMixin<UIntRangeSet>::Mappings;

    explicit FixedLenUIntFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                            typename UserMixinsT::FixedLenUIntFc mixin, const unsigned int align,
                            const bt2c::DataLen len, const ByteOrder byteOrder,
                            const bt2s::optional<BitOrder>& bitOrder = bt2s::nullopt,
                            const DispBase prefDispBase = DispBase::Dec, Mappings mappings = {},
                            UIntFieldRoles roles = {}, OptAttrs attrs = OptAttrs {}) :
        FixedLenIntFc<UserMixinsT> {FcType::FixedLenUInt,
                                    std::move(fcMixin),
                                    std::move(fixedLenBitArrayFcMixin),
                                    std::move(fixedLenIntFcMixin),
                                    align,
                                    len,
                                    byteOrder,
                                    bitOrder,
                                    prefDispBase,
                                    std::move(attrs)},
        internal::WithMappingsMixin<UIntRangeSet> {std::move(mappings)},
        internal::UIntFcMixin {std::move(roles)}, UserMixinsT::FixedLenUIntFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenUIntFc>(
            *this, *this, *this, *this, this->align(), this->len(), this->byteOrder(),
            this->bitOrder(), this->prefDispBase(), this->mappings(), this->roles(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Fixed-length signed integer field class.
 *
 * Specific property over `FixedLenIntFc<UserMixinsT>`:
 *
 * • Mappings.
 */
template <typename UserMixinsT>
class FixedLenSIntFc final :
    public FixedLenIntFc<UserMixinsT>,
    public internal::WithMappingsMixin<SIntRangeSet>
{
public:
    using typename internal::WithMappingsMixin<SIntRangeSet>::Mappings;

    explicit FixedLenSIntFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::FixedLenBitArrayFc fixedLenBitArrayFcMixin,
                            typename UserMixinsT::FixedLenIntFc fixedLenIntFcMixin,
                            const unsigned int align, const bt2c::DataLen len,
                            const ByteOrder byteOrder,
                            const bt2s::optional<BitOrder>& bitOrder = bt2s::nullopt,
                            const DispBase prefDispBase = DispBase::Dec, Mappings mappings = {},
                            OptAttrs attrs = OptAttrs {}) :
        FixedLenIntFc<UserMixinsT> {FcType::FixedLenSInt,
                                    std::move(fcMixin),
                                    std::move(fixedLenBitArrayFcMixin),
                                    std::move(fixedLenIntFcMixin),
                                    align,
                                    len,
                                    byteOrder,
                                    bitOrder,
                                    prefDispBase,
                                    std::move(attrs)},
        internal::WithMappingsMixin<SIntRangeSet> {std::move(mappings)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<FixedLenSIntFc>(
            *this, *this, *this, this->align(), this->len(), this->byteOrder(), this->bitOrder(),
            this->prefDispBase(), this->mappings(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variable-length integer field class base.
 */
template <typename UserMixinsT>
class VarLenIntFc :
    public Fc<UserMixinsT>,
    public internal::WithPrefDispBaseMixin,
    public UserMixinsT::VarLenIntFc
{
protected:
    explicit VarLenIntFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                         typename UserMixinsT::VarLenIntFc mixin, const DispBase prefDispBase,
                         OptAttrs&& attrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 8, std::move(attrs)},
        internal::WithPrefDispBaseMixin {prefDispBase}, UserMixinsT::VarLenIntFc {std::move(mixin)}
    {
    }
};

/*
 * Variable-length unsigned integer field class.
 *
 * Specific properties over `VarLenIntFc<UserMixinsT>`:
 *
 * • Mappings.
 * • Roles of instances.
 */
template <typename UserMixinsT>
class VarLenUIntFc final :
    public VarLenIntFc<UserMixinsT>,
    public internal::WithMappingsMixin<UIntRangeSet>,
    public internal::UIntFcMixin,
    public UserMixinsT::VarLenUIntFc
{
public:
    using typename internal::WithMappingsMixin<UIntRangeSet>::Mappings;

    explicit VarLenUIntFc(typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::VarLenIntFc varLenIntFcMixin,
                          typename UserMixinsT::VarLenUIntFc mixin, const DispBase prefDispBase,
                          Mappings mappings = {}, UIntFieldRoles roles = {},
                          OptAttrs attrs = OptAttrs {}) :
        VarLenIntFc<UserMixinsT> {FcType::VarLenUInt, std::move(fcMixin),
                                  std::move(varLenIntFcMixin), prefDispBase, std::move(attrs)},
        internal::WithMappingsMixin<UIntRangeSet> {std::move(mappings)},
        internal::UIntFcMixin {std::move(roles)}, UserMixinsT::VarLenUIntFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VarLenUIntFc>(*this, *this, *this, this->prefDispBase(),
                                               this->mappings(), this->roles(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variable-length signed integer field class.
 *
 * Specific property over `VarLenIntFc<UserMixinsT>`:
 *
 * • Mappings.
 */
template <typename UserMixinsT>
class VarLenSIntFc final :
    public VarLenIntFc<UserMixinsT>,
    public internal::WithMappingsMixin<SIntRangeSet>
{
public:
    using typename internal::WithMappingsMixin<SIntRangeSet>::Mappings;

    explicit VarLenSIntFc(typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::VarLenIntFc varLenIntFcMixin,
                          const DispBase prefDispBase, Mappings mappings = {},
                          OptAttrs attrs = OptAttrs {}) :
        VarLenIntFc<UserMixinsT> {FcType::VarLenSInt, std::move(fcMixin),
                                  std::move(varLenIntFcMixin), prefDispBase, std::move(attrs)},
        internal::WithMappingsMixin<SIntRangeSet> {std::move(mappings)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VarLenSIntFc>(*this, *this, this->prefDispBase(), this->mappings(),
                                               this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/* clang-format off */

/*
 * String encoding.
 */
WISE_ENUM_CLASS(StrEncoding,
    /* UTF-8 */
    Utf8,

    /* UTF-16BE */
    Utf16Be,

    /* UTF-16LE */
    Utf16Le,

    /* UTF-32BE */
    Utf32Be,

    /* UTF-32LE */
    Utf32Le
)

/* clang-format on */

/*
 * String field class base.
 *
 * Specific property over `Fc<UserMixinsT>`:
 *
 * • Encoding of instances.
 */
template <typename UserMixinsT>
class StrFc : public Fc<UserMixinsT>
{
protected:
    explicit StrFc(const FcType type, typename UserMixinsT::Fc fcMixin, const StrEncoding encoding,
                   OptAttrs&& attrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 8, std::move(attrs)}, _mEncoding {encoding}
    {
    }

public:
    /*
     * Encoding of instances of this string field class.
     */
    StrEncoding encoding() const noexcept
    {
        return _mEncoding;
    }

private:
    /* Encoding of instances of this string field class */
    StrEncoding _mEncoding;
};

/*
 * Null-terminated string field class.
 */
template <typename UserMixinsT>
class NullTerminatedStrFc final : public StrFc<UserMixinsT>
{
public:
    explicit NullTerminatedStrFc(typename UserMixinsT::Fc fcMixin,
                                 const StrEncoding encoding = StrEncoding::Utf8,
                                 OptAttrs attrs = OptAttrs {}) :
        StrFc<UserMixinsT> {FcType::NullTerminatedStr, std::move(fcMixin), encoding,
                            std::move(attrs)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<NullTerminatedStrFc>(*this, this->encoding(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/* clang-format off */

/*
 * Scope.
 */
WISE_ENUM_CLASS(Scope,
    /* Packet header */
    PktHeader,

    /* Packet context */
    PktCtx,

    /* Event record header */
    EventRecordHeader,

    /* Common event record context */
    CommonEventRecordCtx,

    /* Specific event record context */
    SpecEventRecordCtx,

    /* Event record payload */
    EventRecordPayload
)

/* clang-format on */

/*
 * Field location.
 *
 * A field location may be:
 *
 * Absolute:
 *     Has an origin and no `bt2s::nullopt` items.
 *
 * Relative:
 *     Has no origin and may contain `bt2s::nullopt` items.
 *
 *     A `bt2s::nullopt` item means "go to parent structure field"
 *     (CTF 2 strategy).
 */
template <typename UserMixinsT>
class FieldLoc final : public UserMixinsT::FieldLoc
{
public:
    using Items = std::vector<bt2s::optional<std::string>>;

    explicit FieldLoc(typename UserMixinsT::FieldLoc mixin, bt2s::optional<Scope> origin,
                      Items items) :
        UserMixinsT::FieldLoc {std::move(mixin)}, _mOrigin {std::move(origin)},
        _mItems {std::move(items)}
    {
    }

    /*
     * Origin of this field location, or `bt2s::nullopt` if it's a
     * relative field location.
     */
    const bt2s::optional<Scope>& origin() const noexcept
    {
        return _mOrigin;
    }

    /*
     * Path item of this field location.
     */
    const Items& items() const noexcept
    {
        return _mItems;
    }

    Items::const_reference operator[](const Items::size_type index) const noexcept
    {
        return _mItems[index];
    }

    Items::size_type size() const noexcept
    {
        return _mItems.size();
    }

    Items::const_iterator begin() const noexcept
    {
        return _mItems.begin();
    }

    Items::const_iterator end() const noexcept
    {
        return _mItems.end();
    }

private:
    /* Origin of this field location */
    bt2s::optional<Scope> _mOrigin;

    /* Path items of this field location */
    Items _mItems;
};

namespace internal {

/*
 * Internal mixin for static-length field class classes.
 */
class StaticLenFcMixin
{
protected:
    explicit StaticLenFcMixin(const std::size_t len) : _mLen {len}
    {
    }

public:
    /*
     * Length (bytes or elements) of instances of this field class.
     */
    std::size_t len() const noexcept
    {
        return _mLen;
    }

private:
    /* Length of instances of this field class */
    std::size_t _mLen;
};

/*
 * Internal mixin for dynamic-length field class classes.
 */
template <typename UserMixinsT>
class DynLenFcMixin
{
protected:
    explicit DynLenFcMixin(FieldLoc<UserMixinsT> lenFieldLoc) :
        _mLenFieldLoc {std::move(lenFieldLoc)}
    {
    }

public:
    /*
     * Length field location of instances of this field class.
     */
    const FieldLoc<UserMixinsT>& lenFieldLoc() const noexcept
    {
        return _mLenFieldLoc;
    }

    /*
     * Sets the length field location of instances of this field class
     * to `loc`.
     */
    void lenFieldLoc(FieldLoc<UserMixinsT> loc) noexcept
    {
        _mLenFieldLoc = std::move(loc);
    }

private:
    /* Length field location of instances of this field class */
    FieldLoc<UserMixinsT> _mLenFieldLoc;
};

} /* namespace internal */

/*
 * Non-null-terminated string field class base.
 */
template <typename UserMixinsT>
class NonNullTerminatedStrFc : public StrFc<UserMixinsT>
{
protected:
    explicit NonNullTerminatedStrFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                                    const StrEncoding strEncoding, OptAttrs&& attrs) :
        StrFc<UserMixinsT> {type, std::move(fcMixin), strEncoding, std::move(attrs)}
    {
    }
};

/*
 * Static-length string field class.
 *
 * Specific property over `NonNullTerminatedStrFc<UserMixinsT>`:
 *
 * • Length (number of bytes) of instances.
 */
template <typename UserMixinsT>
class StaticLenStrFc final :
    public NonNullTerminatedStrFc<UserMixinsT>,
    public internal::StaticLenFcMixin,
    public UserMixinsT::StaticLenStrFc
{
public:
    explicit StaticLenStrFc(typename UserMixinsT::Fc fcMixin,
                            typename UserMixinsT::StaticLenStrFc mixin, const std::size_t len,
                            const StrEncoding encoding = StrEncoding::Utf8,
                            OptAttrs attrs = OptAttrs {}) :
        NonNullTerminatedStrFc<UserMixinsT> {FcType::StaticLenStr, std::move(fcMixin), encoding,
                                             std::move(attrs)},
        internal::StaticLenFcMixin {len}, UserMixinsT::StaticLenStrFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StaticLenStrFc>(*this, *this, this->len(), this->encoding(),
                                                 this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Dynamic-length string field class.
 *
 * Specific property over `NonNullTerminatedStrFc<UserMixinsT>`:
 *
 * • Length field location of instances.
 */
template <typename UserMixinsT>
class DynLenStrFc final :
    public NonNullTerminatedStrFc<UserMixinsT>,
    public internal::DynLenFcMixin<UserMixinsT>,
    public UserMixinsT::DynLenStrFc
{
public:
    explicit DynLenStrFc(typename UserMixinsT::Fc fcMixin, typename UserMixinsT::DynLenStrFc mixin,
                         FieldLoc<UserMixinsT> lenFieldLoc,
                         const StrEncoding encoding = StrEncoding::Utf8,
                         OptAttrs attrs = OptAttrs {}) :
        NonNullTerminatedStrFc<UserMixinsT> {FcType::DynLenStr, std::move(fcMixin), encoding,
                                             std::move(attrs)},
        internal::DynLenFcMixin<UserMixinsT> {std::move(lenFieldLoc)},
        UserMixinsT::DynLenStrFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<DynLenStrFc>(*this, *this, this->lenFieldLoc(), this->encoding(),
                                              this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

extern const char * const defaultBlobMediaType;

/*
 * BLOB field class base.
 *
 * Specific property over `Fc<UserMixinsT>`:
 *
 * • Media type of instances.
 */
template <typename UserMixinsT>
class BlobFc : public Fc<UserMixinsT>
{
protected:
    explicit BlobFc(const FcType type, typename UserMixinsT::Fc fcMixin, std::string&& mediaType,
                    OptAttrs&& attrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 8, std::move(attrs)},
        _mMediaType {std::move(mediaType)}
    {
    }

public:
    /*
     * Media type of instances of this field class.
     */
    const std::string& mediaType() const noexcept
    {
        return _mMediaType;
    }

private:
    /* Media type of instances of this field class */
    std::string _mMediaType;
};

/*
 * Static-length BLOB field class.
 *
 * Specific properties over `BlobFc<UserMixinsT>`:
 *
 * • Length (number of bytes) of instances.
 *
 * • Whether or not instances have the "metadata stream UUID" role.
 */
template <typename UserMixinsT>
class StaticLenBlobFc final :
    public BlobFc<UserMixinsT>,
    public internal::StaticLenFcMixin,
    public UserMixinsT::StaticLenBlobFc
{
public:
    explicit StaticLenBlobFc(typename UserMixinsT::Fc fcMixin,
                             typename UserMixinsT::StaticLenBlobFc mixin, const std::size_t len,
                             std::string mediaType = defaultBlobMediaType,
                             const bool hasMetadataStreamUuidRole = false,
                             OptAttrs attrs = OptAttrs {}) :
        BlobFc<UserMixinsT> {FcType::StaticLenBlob, std::move(fcMixin), std::move(mediaType),
                             std::move(attrs)},
        internal::StaticLenFcMixin {len}, UserMixinsT::StaticLenBlobFc(std::move(mixin)),
        _mHasMetadataStreamUuidRole {hasMetadataStreamUuidRole}
    {
    }

    bool hasMetadataStreamUuidRole() const noexcept
    {
        return _mHasMetadataStreamUuidRole;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StaticLenBlobFc>(*this, *this, this->len(), this->mediaType(),
                                                  _mHasMetadataStreamUuidRole, this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    bool _mHasMetadataStreamUuidRole;
};

/*
 * Dynamic-length BLOB field class.
 *
 * Specific property over `BlobFc<UserMixinsT>`:
 *
 * • Length field location of instances.
 */
template <typename UserMixinsT>
class DynLenBlobFc final :
    public BlobFc<UserMixinsT>,
    public internal::DynLenFcMixin<UserMixinsT>,
    public UserMixinsT::DynLenBlobFc
{
public:
    explicit DynLenBlobFc(typename UserMixinsT::Fc fcMixin,
                          typename UserMixinsT::DynLenBlobFc mixin,
                          FieldLoc<UserMixinsT> lenFieldLoc,
                          std::string mediaType = defaultBlobMediaType,
                          OptAttrs attrs = OptAttrs {}) :
        BlobFc<UserMixinsT> {FcType::DynLenBlob, std::move(fcMixin), std::move(mediaType),
                             std::move(attrs)},
        internal::DynLenFcMixin<UserMixinsT> {std::move(lenFieldLoc)},
        UserMixinsT::DynLenBlobFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<DynLenBlobFc>(*this, *this, this->lenFieldLoc(), this->mediaType(),
                                               this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Array field class base.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Class of element fields.
 * • Minimum alignment of instances.
 */
template <typename UserMixinsT>
class ArrayFc : public Fc<UserMixinsT>
{
protected:
    explicit ArrayFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                     typename Fc<UserMixinsT>::UP&& elemFc, const unsigned int minAlign,
                     OptAttrs&& attrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), ArrayFc::_effectiveAlign(*elemFc, minAlign),
                         std::move(attrs)},
        _mElemFc {std::move(elemFc)}, _mMinAlign {minAlign}
    {
        BT_ASSERT(_mElemFc);
    }

public:
    /*
     * Class of the element fields of instances of this field class.
     */
    const Fc<UserMixinsT>& elemFc() const noexcept
    {
        return *_mElemFc;
    }

    /*
     * Class of the element fields of instances of this field class.
     */
    Fc<UserMixinsT>& elemFc() noexcept
    {
        return *_mElemFc;
    }

    /*
     * Sets the class of the element fields of instances of this field
     * class.
     */
    void elemFc(typename Fc<UserMixinsT>::UP elemFc) noexcept
    {
        _mElemFc = std::move(elemFc);
    }

    /*
     * Moves the class of the element fields of instances of this field
     * class to the caller.
     */
    typename Fc<UserMixinsT>::UP takeElemFc() noexcept
    {
        return std::move(_mElemFc);
    }

    /*
     * Minimum alignment (bits) of instances of this field class.
     */
    unsigned int minAlign() const noexcept
    {
        return _mMinAlign;
    }

private:
    /*
     * Returns the effective alignment of an array field of which:
     *
     * • The minimum alignment is `minAlign` bits.
     * • The elements are instances of `elemFc`.
     */
    static unsigned int _effectiveAlign(const Fc<UserMixinsT>& elemFc,
                                        const unsigned int minAlign) noexcept
    {
        return std::max(elemFc.align(), minAlign);
    }

    /* Class of the element fields of instances of this field class */
    typename Fc<UserMixinsT>::UP _mElemFc;

    /* Minimum alignment (bits) of instances of this field class */
    unsigned int _mMinAlign;
};

/*
 * Static-length array field class.
 *
 * Specific property over `ArrayFc<UserMixinsT>`:
 *
 * • Length (number of elements) of instances.
 */
template <typename UserMixinsT>
class StaticLenArrayFc final :
    public ArrayFc<UserMixinsT>,
    public internal::StaticLenFcMixin,
    public UserMixinsT::StaticLenArrayFc
{
public:
    explicit StaticLenArrayFc(typename UserMixinsT::Fc fcMixin,
                              typename UserMixinsT::StaticLenArrayFc mixin, const std::size_t len,
                              typename Fc<UserMixinsT>::UP elemFc, const unsigned int minAlign = 1,
                              OptAttrs attrs = OptAttrs {}) :
        ArrayFc<UserMixinsT> {FcType::StaticLenArray, std::move(fcMixin), std::move(elemFc),
                              minAlign, std::move(attrs)},
        internal::StaticLenFcMixin {len}, UserMixinsT::StaticLenArrayFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StaticLenArrayFc>(
            *this, *this, this->len(), this->elemFc().clone(), this->minAlign(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Dynamic-length array field class.
 *
 * Specific property over `ArrayFc<UserMixinsT>`:
 *
 * • Length field location of instances.
 */
template <typename UserMixinsT>
class DynLenArrayFc final :
    public ArrayFc<UserMixinsT>,
    public internal::DynLenFcMixin<UserMixinsT>,
    public UserMixinsT::DynLenArrayFc
{
public:
    explicit DynLenArrayFc(typename UserMixinsT::Fc fcMixin,
                           typename UserMixinsT::DynLenArrayFc mixin,
                           FieldLoc<UserMixinsT> lenFieldLoc, typename Fc<UserMixinsT>::UP elemFc,
                           const unsigned int minAlign = 1, OptAttrs attrs = OptAttrs {}) :
        ArrayFc<UserMixinsT> {FcType::DynLenArray, std::move(fcMixin), std::move(elemFc), minAlign,
                              std::move(attrs)},
        internal::DynLenFcMixin<UserMixinsT> {std::move(lenFieldLoc)},
        UserMixinsT::DynLenArrayFc {std::move(mixin)}
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<DynLenArrayFc>(*this, *this, this->lenFieldLoc(),
                                                this->elemFc().clone(), this->minAlign(),
                                                this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Structure field member class.
 */
template <typename UserMixinsT>
class StructFieldMemberCls final :
    public internal::WithAttrsMixin,
    public UserMixinsT::StructFieldMemberCls
{
public:
    explicit StructFieldMemberCls(typename UserMixinsT::StructFieldMemberCls mixin,
                                  std::string name, typename Fc<UserMixinsT>::UP fc,
                                  OptAttrs attrs = OptAttrs {}) :
        internal::WithAttrsMixin {std::move(attrs)},
        UserMixinsT::StructFieldMemberCls(std::move(mixin)), _mName {std::move(name)},
        _mFc {std::move(fc)}
    {
        BT_ASSERT(_mFc);
    }

    /*
     * Builds a member class from `other`, cloning its field class.
     */
    StructFieldMemberCls(const StructFieldMemberCls& other) :
        internal::WithAttrsMixin {other.attrs()}, UserMixinsT::StructFieldMemberCls(other),
        _mName {other.name()}, _mFc {other.fc().clone()}
    {
    }

    /*
     * Name of this member class.
     */
    const std::string& name() const noexcept
    {
        return _mName;
    }

    /*
     * Field class of this member class.
     */
    const Fc<UserMixinsT>& fc() const noexcept
    {
        return *_mFc;
    }

    /*
     * Field class of this member class.
     */
    Fc<UserMixinsT>& fc() noexcept
    {
        return *_mFc;
    }

    /*
     * Moves the field class of this member class to the caller.
     */
    typename Fc<UserMixinsT>::UP takeFc() noexcept
    {
        return std::move(_mFc);
    }

    /*
     * Sets the field class of this member class.
     */
    void fc(typename Fc<UserMixinsT>::UP fc) noexcept
    {
        _mFc = std::move(fc);
    }

private:
    std::string _mName;
    typename Fc<UserMixinsT>::UP _mFc;
};

/*
 * Structure field class.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Minimum alignment of instances.
 * • Classes of members of instances.
 */
template <typename UserMixinsT>
class StructFc final : public Fc<UserMixinsT>, public UserMixinsT::StructFc
{
public:
    using MemberClasses = std::vector<StructFieldMemberCls<UserMixinsT>>;

    explicit StructFc(typename UserMixinsT::Fc fcMixin, typename UserMixinsT::StructFc mixin,
                      MemberClasses memberClasses = {}, const unsigned int minAlign = 1,
                      OptAttrs attrs = OptAttrs {}) :
        Fc<UserMixinsT> {FcType::Struct, std::move(fcMixin),
                         StructFc::_effectiveAlign(memberClasses, minAlign), std::move(attrs)},
        UserMixinsT::StructFc(std::move(mixin)), _mMemberClasses {std::move(memberClasses)},
        _mMinAlign {minAlign}
    {
    }

    /*
     * Classes of members of instances of this field class.
     */
    const MemberClasses& memberClasses() const noexcept
    {
        return _mMemberClasses;
    }

    typename MemberClasses::const_reference
    operator[](const typename MemberClasses::size_type index) const noexcept
    {
        return _mMemberClasses[index];
    }

    typename MemberClasses::reference
    operator[](const typename MemberClasses::size_type index) noexcept
    {
        return _mMemberClasses[index];
    }

    const typename MemberClasses::value_type *operator[](const std::string& name) const noexcept
    {
        return this->_memberClsByName<const typename MemberClasses::value_type>(*this, name);
    }

    typename MemberClasses::value_type *operator[](const std::string& name) noexcept
    {
        return this->_memberClsByName<typename MemberClasses::value_type>(*this, name);
    }

    typename MemberClasses::size_type size() const noexcept
    {
        return _mMemberClasses.size();
    }

    bool isEmpty() const noexcept
    {
        return _mMemberClasses.empty();
    }

    typename MemberClasses::const_iterator begin() const noexcept
    {
        return _mMemberClasses.begin();
    }

    typename MemberClasses::iterator begin() noexcept
    {
        return _mMemberClasses.begin();
    }

    typename MemberClasses::const_iterator end() const noexcept
    {
        return _mMemberClasses.end();
    }

    typename MemberClasses::iterator end() noexcept
    {
        return _mMemberClasses.end();
    }

    typename MemberClasses::const_reverse_iterator rbegin() const noexcept
    {
        return _mMemberClasses.rbegin();
    }

    typename MemberClasses::reverse_iterator rbegin() noexcept
    {
        return _mMemberClasses.rbegin();
    }

    typename MemberClasses::const_reverse_iterator rend() const noexcept
    {
        return _mMemberClasses.rend();
    }

    typename MemberClasses::reverse_iterator rend() noexcept
    {
        return _mMemberClasses.rend();
    }

    /*
     * Minimum alignment (bits) of instances of this field class.
     */
    unsigned int minAlign() const noexcept
    {
        return _mMinAlign;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<StructFc>(*this, *this, _mMemberClasses, _mMinAlign,
                                           this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }

private:
    /*
     * Returns the effective alignment of a structure field of which:
     *
     * • The minimum alignment is `minAlign` bits.
     * • The members are instances of `memberClasses`.
     */
    static unsigned int _effectiveAlign(const MemberClasses& memberClasses,
                                        const unsigned int minAlign) noexcept
    {
        auto align = minAlign;

        for (auto& memberCls : memberClasses) {
            align = std::max(align, memberCls.fc().align());
        }

        return align;
    }

    template <typename ValT, typename StructFcT>
    static ValT *_memberClsByName(StructFcT& structFc, const std::string& name) noexcept
    {
        for (auto& memberCls : structFc._mMemberClasses) {
            if (memberCls.name() == name) {
                return &memberCls;
            }
        }

        return nullptr;
    }

    /* Classes of members of instances of this field class */
    MemberClasses _mMemberClasses;

    /* Minimum alignment (bits) of instances of this field class */
    unsigned int _mMinAlign;
};

/*
 * Optional field class base.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Selector field location of instances.
 * • Optional field of instances.
 */
template <typename UserMixinsT>
class OptionalFc : public Fc<UserMixinsT>, public UserMixinsT::OptionalFc
{
protected:
    explicit OptionalFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                        typename UserMixinsT::OptionalFc mixin, typename Fc<UserMixinsT>::UP&& fc,
                        FieldLoc<UserMixinsT>&& selFieldLoc, OptAttrs&& attrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 1, std::move(attrs)},
        UserMixinsT::OptionalFc {std::move(mixin)}, _mSelFieldLoc {std::move(selFieldLoc)},
        _mFc {std::move(fc)}
    {
    }

public:
    /*
     * Selector field location of instances of this field class.
     */
    const FieldLoc<UserMixinsT>& selFieldLoc() const noexcept
    {
        return _mSelFieldLoc;
    }

    /*
     * Sets the selector field location of instances of this field class
     * to `loc`.
     */
    void selFieldLoc(FieldLoc<UserMixinsT> loc) noexcept
    {
        _mSelFieldLoc = std::move(loc);
    }

    /*
     * Moves the selector field location of instances of this field
     * class to the caller.
     */
    FieldLoc<UserMixinsT> takeSelFieldLoc() noexcept
    {
        return std::move(_mSelFieldLoc);
    }

    /*
     * Class of the optional field of instances of this field class.
     */
    const Fc<UserMixinsT>& fc() const noexcept
    {
        return *_mFc;
    }

    /*
     * Class of the optional field of instances of this field class.
     */
    Fc<UserMixinsT>& fc() noexcept
    {
        return *_mFc;
    }

    /*
     * Sets the class of the optional field of instances of this field
     * class.
     */
    void fc(typename Fc<UserMixinsT>::UP fc) noexcept
    {
        _mFc = std::move(fc);
    }

    /*
     * Moves the class of the optional field of instances of this field
     * class to the caller.
     */
    typename Fc<UserMixinsT>::UP takeFc() noexcept
    {
        return std::move(_mFc);
    }

private:
    /* Selector field location of instances of this field class */
    FieldLoc<UserMixinsT> _mSelFieldLoc;

    /* Class of the optional field of instances of this field class */
    typename Fc<UserMixinsT>::UP _mFc;
};

/*
 * Class of optional fields with a boolean selector.
 */
template <typename UserMixinsT>
class OptionalWithBoolSelFc final :
    public OptionalFc<UserMixinsT>,
    public UserMixinsT::OptionalWithBoolSelFc
{
public:
    /* Selector value type */
    using SelVal = bool;

    explicit OptionalWithBoolSelFc(typename UserMixinsT::Fc fcMixin,
                                   typename UserMixinsT::OptionalFc optionalFcMixin,
                                   typename UserMixinsT::OptionalWithBoolSelFc mixin,
                                   typename Fc<UserMixinsT>::UP fc,
                                   FieldLoc<UserMixinsT> selFieldLoc,
                                   OptAttrs attrs = OptAttrs {}) :
        OptionalFc<UserMixinsT> {FcType::OptionalWithBoolSel, std::move(fcMixin),
                                 std::move(optionalFcMixin),  std::move(fc),
                                 std::move(selFieldLoc),      std::move(attrs)},
        UserMixinsT::OptionalWithBoolSelFc(std::move(mixin))
    {
    }

    /*
     * Returns whether or not an instance of this field class is enabled
     * by the selector value `selVal`.
     */
    bool isEnabledBySelVal(const bool selVal) const noexcept
    {
        return selVal;
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<OptionalWithBoolSelFc>(*this, *this, *this, this->fc().clone(),
                                                        this->selFieldLoc(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Base class of optional fields with an integer selector.
 *
 * `IntRangeSetT` is the integer selector range set type.
 *
 * Specific property over `OptionalFc<UserMixinsT>`:
 *
 * • Selector field ranges which enable an instance.
 */
template <typename UserMixinsT, typename IntRangeSetT>
class OptionalWithIntSelFc :
    public OptionalFc<UserMixinsT>,
    public UserMixinsT::OptionalWithIntSelFc
{
public:
    /* Integer selector range set type */
    using SelFieldRanges = IntRangeSetT;

    /* Selector value type */
    using SelVal = typename IntRangeSetT::Val;

protected:
    explicit OptionalWithIntSelFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                                  typename UserMixinsT::OptionalFc optionalFcMixin,
                                  typename UserMixinsT::OptionalWithIntSelFc mixin,
                                  typename Fc<UserMixinsT>::UP&& fc,
                                  FieldLoc<UserMixinsT>&& selFieldLoc,
                                  IntRangeSetT&& selFieldRanges, OptAttrs&& attrs) :
        OptionalFc<UserMixinsT> {type,          std::move(fcMixin),     std::move(optionalFcMixin),
                                 std::move(fc), std::move(selFieldLoc), std::move(attrs)},
        UserMixinsT::OptionalWithIntSelFc(std::move(mixin)),
        _mSelFieldRanges {std::move(selFieldRanges)}
    {
    }

public:
    /*
     * Integer selector field ranges which enable an instance of this
     * field class.
     */
    const IntRangeSetT& selFieldRanges() const noexcept
    {
        return _mSelFieldRanges;
    }

    /*
     * Returns whether or not an instance of this field class is
     * enabled by the selector value `selVal`.
     */
    bool isEnabledBySelVal(const SelVal selVal) const noexcept
    {
        return _mSelFieldRanges.contains(selVal);
    }

private:
    /* Integer selector field ranges */
    IntRangeSetT _mSelFieldRanges;
};

/*
 * Class of optional fields with an unsigned integer selector.
 */
template <typename UserMixinsT>
class OptionalWithUIntSelFc final :
    public OptionalWithIntSelFc<UserMixinsT, UIntRangeSet>,
    public UserMixinsT::OptionalWithUIntSelFc
{
public:
    explicit OptionalWithUIntSelFc(
        typename UserMixinsT::Fc fcMixin, typename UserMixinsT::OptionalFc optionalFcMixin,
        typename UserMixinsT::OptionalWithIntSelFc optionalWithIntSelFcMixin,
        typename UserMixinsT::OptionalWithUIntSelFc mixin, typename Fc<UserMixinsT>::UP fc,
        FieldLoc<UserMixinsT> selFieldLoc, UIntRangeSet selFieldRanges,
        OptAttrs attrs = OptAttrs {}) :
        OptionalWithIntSelFc<UserMixinsT, UIntRangeSet> {FcType::OptionalWithUIntSel,
                                                         std::move(fcMixin),
                                                         std::move(optionalFcMixin),
                                                         std::move(optionalWithIntSelFcMixin),
                                                         std::move(fc),
                                                         std::move(selFieldLoc),
                                                         std::move(selFieldRanges),
                                                         std::move(attrs)},
        UserMixinsT::OptionalWithUIntSelFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<OptionalWithUIntSelFc>(*this, *this, *this, *this,
                                                        this->fc().clone(), this->selFieldLoc(),
                                                        this->selFieldRanges(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Class of optional fields with a signed integer selector.
 */
template <typename UserMixinsT>
class OptionalWithSIntSelFc final :
    public OptionalWithIntSelFc<UserMixinsT, SIntRangeSet>,
    public UserMixinsT::OptionalWithSIntSelFc
{
public:
    explicit OptionalWithSIntSelFc(
        typename UserMixinsT::Fc fcMixin, typename UserMixinsT::OptionalFc optionalFcMixin,
        typename UserMixinsT::OptionalWithIntSelFc optionalWithIntSelFcMixin,
        typename UserMixinsT::OptionalWithSIntSelFc mixin, typename Fc<UserMixinsT>::UP fc,
        FieldLoc<UserMixinsT> selFieldLoc, SIntRangeSet selFieldRanges,
        OptAttrs attrs = OptAttrs {}) :
        OptionalWithIntSelFc<UserMixinsT, SIntRangeSet> {FcType::OptionalWithSIntSel,
                                                         std::move(fcMixin),
                                                         std::move(optionalFcMixin),
                                                         std::move(optionalWithIntSelFcMixin),
                                                         std::move(fc),
                                                         std::move(selFieldLoc),
                                                         std::move(selFieldRanges),
                                                         std::move(attrs)},
        UserMixinsT::OptionalWithSIntSelFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<OptionalWithSIntSelFc>(*this, *this, *this, *this,
                                                        this->fc().clone(), this->selFieldLoc(),
                                                        this->selFieldRanges(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Variant field class option.
 *
 * `IntRangeSetT` is the integer selector range set type.
 */
template <typename UserMixinsT, typename IntRangeSetT>
class VariantFcOpt final : public internal::WithAttrsMixin, public UserMixinsT::VariantFcOpt
{
public:
    /* Integer selector range set type */
    using SelFieldRanges = IntRangeSetT;

    /* Selector value type */
    using SelVal = typename IntRangeSetT::Val;

    explicit VariantFcOpt(typename UserMixinsT::VariantFcOpt mixin, typename Fc<UserMixinsT>::UP fc,
                          IntRangeSetT selFieldRanges, bt2s::optional<std::string> name,
                          OptAttrs attrs = OptAttrs {}) :
        internal::WithAttrsMixin {std::move(attrs)}, UserMixinsT::VariantFcOpt(std::move(mixin)),
        _mName {std::move(name)}, _mFc {std::move(fc)}, _mSelFieldRanges {std::move(selFieldRanges)}
    {
        BT_ASSERT(_mFc);
    }

    /*
     * Builds a variant field class option from `other`, cloning its
     * field class.
     */
    VariantFcOpt(const VariantFcOpt& other) :
        internal::WithAttrsMixin {other.attrs()}, UserMixinsT::VariantFcOpt(other),
        _mName {other.name()}, _mFc {other.fc().clone()}, _mSelFieldRanges {other.selFieldRanges()}
    {
    }

    /*
     * Name of this variant field class option.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * Moves the name of this variant field class option to the caller.
     */
    typename bt2s::optional<std::string> takeName() noexcept
    {
        return std::move(_mName);
    }

    /*
     * Field class of this variant field class option.
     */
    const Fc<UserMixinsT>& fc() const noexcept
    {
        return *_mFc;
    }

    /*
     * Name of this variant field class option.
     */
    Fc<UserMixinsT>& fc() noexcept
    {
        return *_mFc;
    }

    /*
     * Moves the field class of this variant field class option to the
     * caller.
     */
    typename Fc<UserMixinsT>::UP takeFc() noexcept
    {
        return std::move(_mFc);
    }

    /*
     * Sets the field class of this variant field class option.
     */
    void fc(typename Fc<UserMixinsT>::UP fc) noexcept
    {
        _mFc = std::move(fc);
    }

    /*
     * Integer selector field ranges which select this variant field
     * class option.
     */
    const IntRangeSetT& selFieldRanges() const noexcept
    {
        return _mSelFieldRanges;
    }

    /*
     * Moves the attributes of this variant field class option to
     * the caller.
     */
    OptAttrs takeAttrs() noexcept
    {
        return this->_takeAttrs();
    }

private:
    bt2s::optional<std::string> _mName;
    typename Fc<UserMixinsT>::UP _mFc;
    IntRangeSetT _mSelFieldRanges;
};

/*
 * Variant field class base.
 *
 * `IntRangeSetT` is the integer selector range set type.
 *
 * Specific properties over `Fc<UserMixinsT>`:
 *
 * • Selector field location of instances.
 * • Options.
 */
template <typename UserMixinsT, typename IntRangeSetT>
class VariantFc : public Fc<UserMixinsT>, public UserMixinsT::VariantFc
{
public:
    /* Option type */
    using Opt = VariantFcOpt<UserMixinsT, IntRangeSetT>;

    /* Type of options */
    using Opts = std::vector<Opt>;

    /* Integer selector range set type */
    using SelFieldRanges = typename Opt::SelFieldRanges;

    /* Selector value type */
    using SelVal = typename Opt::SelVal;

protected:
    explicit VariantFc(const FcType type, typename UserMixinsT::Fc fcMixin,
                       typename UserMixinsT::VariantFc mixin, Opts&& opts,
                       FieldLoc<UserMixinsT>&& selFieldLoc, OptAttrs&& attrs) :
        Fc<UserMixinsT> {type, std::move(fcMixin), 1, std::move(attrs)},
        UserMixinsT::VariantFc {std::move(mixin)}, _mOpts {std::move(opts)},
        _mSelFieldLoc {std::move(selFieldLoc)}
    {
    }

public:
    /*
     * Selector field location of instances of this field class.
     */
    const FieldLoc<UserMixinsT>& selFieldLoc() const noexcept
    {
        return _mSelFieldLoc;
    }

    /*
     * Sets the selector field location of instances of this field class
     * to `loc`.
     */
    void selFieldLoc(FieldLoc<UserMixinsT> loc) noexcept
    {
        _mSelFieldLoc = std::move(loc);
    }

    /*
     * Moves the selector field location of instances of this field
     * class to the caller.
     */
    FieldLoc<UserMixinsT> takeSelFieldLoc() noexcept
    {
        return std::move(_mSelFieldLoc);
    }

    /*
     * Options of this field class.
     */
    const Opts& opts() const noexcept
    {
        return _mOpts;
    }

    /*
     * Options of this field class.
     */
    Opts& opts() noexcept
    {
        return _mOpts;
    }

    typename Opts::const_reference operator[](const typename Opts::size_type index) const noexcept
    {
        return _mOpts[index];
    }

    typename Opts::reference operator[](const typename Opts::size_type index) noexcept
    {
        return _mOpts[index];
    }

    const typename Opts::value_type *operator[](const std::string& name) const noexcept
    {
        return this->_optByName<const typename Opts::value_type>(*this, name);
    }

    typename Opts::value_type *operator[](const std::string& name) noexcept
    {
        return this->_optByName<typename Opts::value_type>(*this, name);
    }

    typename Opts::size_type size() const noexcept
    {
        return _mOpts.size();
    }

    typename Opts::const_iterator begin() const noexcept
    {
        return _mOpts.begin();
    }

    typename Opts::iterator begin() noexcept
    {
        return _mOpts.begin();
    }

    typename Opts::const_iterator end() const noexcept
    {
        return _mOpts.end();
    }

    typename Opts::iterator end() noexcept
    {
        return _mOpts.end();
    }

    /*
     * Returns the option of this field class which the selector value
     * `selVal` selects, or `nullptr` if none.
     */
    typename Opts::const_iterator findOptBySelVal(const SelVal selVal) const noexcept
    {
        return std::find_if(_mOpts.begin(), _mOpts.end(), [selVal](const Opt& opt) {
            return opt.selFieldRanges().contains(selVal);
        });
    }

private:
    template <typename ValT, typename VarFcT>
    static ValT *_optByName(VarFcT& varFc, const std::string& name) noexcept
    {
        for (auto& opt : varFc._mOpts) {
            if (opt.name() && *opt.name() == name) {
                return &opt;
            }
        }

        return nullptr;
    }

    /* Options of this field class */
    Opts _mOpts;

    /* Selector field location of instances of this field class */
    FieldLoc<UserMixinsT> _mSelFieldLoc;
};

/*
 * Class of variant fields with an unsigned integer selector.
 */
template <typename UserMixinsT>
class VariantWithUIntSelFc final :
    public VariantFc<UserMixinsT, UIntRangeSet>,
    public UserMixinsT::VariantWithUIntSelFc
{
public:
    explicit VariantWithUIntSelFc(typename UserMixinsT::Fc fcMixin,
                                  typename UserMixinsT::VariantFc variantFcMixin,
                                  typename UserMixinsT::VariantWithUIntSelFc mixin,
                                  typename VariantFc<UserMixinsT, UIntRangeSet>::Opts opts,
                                  FieldLoc<UserMixinsT> selFieldLoc, OptAttrs attrs = OptAttrs {}) :
        VariantFc<UserMixinsT, UIntRangeSet> {FcType::VariantWithUIntSel, std::move(fcMixin),
                                              std::move(variantFcMixin),  std::move(opts),
                                              std::move(selFieldLoc),     std::move(attrs)},
        UserMixinsT::VariantWithUIntSelFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VariantWithUIntSelFc>(*this, *this, *this, this->opts(),
                                                       this->selFieldLoc(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

/*
 * Class of variant fields with a signed integer selector.
 */
template <typename UserMixinsT>
class VariantWithSIntSelFc final :
    public VariantFc<UserMixinsT, SIntRangeSet>,
    public UserMixinsT::VariantWithSIntSelFc
{
public:
    explicit VariantWithSIntSelFc(typename UserMixinsT::Fc fcMixin,
                                  typename UserMixinsT::VariantFc variantFcMixin,
                                  typename UserMixinsT::VariantWithSIntSelFc mixin,
                                  typename VariantFc<UserMixinsT, SIntRangeSet>::Opts opts,
                                  FieldLoc<UserMixinsT> selFieldLoc, OptAttrs attrs = OptAttrs {}) :
        VariantFc<UserMixinsT, SIntRangeSet> {FcType::VariantWithSIntSel, std::move(fcMixin),
                                              std::move(variantFcMixin),  std::move(opts),
                                              std::move(selFieldLoc),     std::move(attrs)},
        UserMixinsT::VariantWithSIntSelFc(std::move(mixin))
    {
    }

    typename Fc<UserMixinsT>::UP clone() const override
    {
        return bt2s::make_unique<VariantWithSIntSelFc>(*this, *this, *this, this->opts(),
                                                       this->selFieldLoc(), this->attrs());
    }

    void accept(FcVisitor<UserMixinsT>& visitor) override
    {
        visitor.visit(*this);
    }

    void accept(ConstFcVisitor<UserMixinsT>& visitor) const override
    {
        visitor.visit(*this);
    }
};

template <typename UserMixinsT>
FixedLenBitArrayFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBitArray() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBitArray());
    return static_cast<FixedLenBitArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenBitArrayFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBitArray() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBitArray());
    return static_cast<const FixedLenBitArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenBitMapFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBitMap() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBitMap());
    return static_cast<FixedLenBitMapFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenBitMapFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBitMap() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBitMap());
    return static_cast<const FixedLenBitMapFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenBoolFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBool() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBool());
    return static_cast<FixedLenBoolFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenBoolFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenBool() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenBool());
    return static_cast<const FixedLenBoolFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenFloatFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenFloat() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenFloat());
    return static_cast<FixedLenFloatFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenFloatFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenFloat() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenFloat());
    return static_cast<const FixedLenFloatFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenInt() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenInt());
    return static_cast<FixedLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenInt() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenInt());
    return static_cast<const FixedLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenSInt() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenSInt());
    return static_cast<FixedLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenSInt() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenSInt());
    return static_cast<const FixedLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
FixedLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenUInt() noexcept
{
    BT_ASSERT_DBG(this->isFixedLenUInt());
    return static_cast<FixedLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const FixedLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asFixedLenUInt() const noexcept
{
    BT_ASSERT_DBG(this->isFixedLenUInt());
    return static_cast<const FixedLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenInt() noexcept
{
    BT_ASSERT_DBG(this->isVarLenInt());
    return static_cast<VarLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenInt() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenInt());
    return static_cast<const VarLenIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenSInt() noexcept
{
    BT_ASSERT_DBG(this->isVarLenSInt());
    return static_cast<VarLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenSIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenSInt() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenSInt());
    return static_cast<const VarLenSIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VarLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenUInt() noexcept
{
    BT_ASSERT_DBG(this->isVarLenUInt());
    return static_cast<VarLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VarLenUIntFc<UserMixinsT>& Fc<UserMixinsT>::asVarLenUInt() const noexcept
{
    BT_ASSERT_DBG(this->isVarLenUInt());
    return static_cast<const VarLenUIntFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
NullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNullTerminatedStr() noexcept
{
    BT_ASSERT_DBG(this->isNullTerminatedStr());
    return static_cast<NullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const NullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNullTerminatedStr() const noexcept
{
    BT_ASSERT_DBG(this->isNullTerminatedStr());
    return static_cast<const NullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
NonNullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNonNullTerminatedStr() noexcept
{
    BT_ASSERT_DBG(this->isNonNullTerminatedStr());
    return static_cast<NonNullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const NonNullTerminatedStrFc<UserMixinsT>& Fc<UserMixinsT>::asNonNullTerminatedStr() const noexcept
{
    BT_ASSERT_DBG(this->isNonNullTerminatedStr());
    return static_cast<const NonNullTerminatedStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StrFc<UserMixinsT>& Fc<UserMixinsT>::asStr() noexcept
{
    BT_ASSERT_DBG(this->isStr());
    return static_cast<StrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StrFc<UserMixinsT>& Fc<UserMixinsT>::asStr() const noexcept
{
    BT_ASSERT_DBG(this->isStr());
    return static_cast<const StrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StaticLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenStr() noexcept
{
    BT_ASSERT_DBG(this->isStaticLenStr());
    return static_cast<StaticLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StaticLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenStr() const noexcept
{
    BT_ASSERT_DBG(this->isStaticLenStr());
    return static_cast<const StaticLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
DynLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenStr() noexcept
{
    BT_ASSERT_DBG(this->isDynLenStr());
    return static_cast<DynLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const DynLenStrFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenStr() const noexcept
{
    BT_ASSERT_DBG(this->isDynLenStr());
    return static_cast<const DynLenStrFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
BlobFc<UserMixinsT>& Fc<UserMixinsT>::asBlob() noexcept
{
    BT_ASSERT_DBG(this->isBlob());
    return static_cast<BlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const BlobFc<UserMixinsT>& Fc<UserMixinsT>::asBlob() const noexcept
{
    BT_ASSERT_DBG(this->isBlob());
    return static_cast<const BlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StaticLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenBlob() noexcept
{
    BT_ASSERT_DBG(this->isStaticLenBlob());
    return static_cast<StaticLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StaticLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenBlob() const noexcept
{
    BT_ASSERT_DBG(this->isStaticLenBlob());
    return static_cast<const StaticLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
DynLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenBlob() noexcept
{
    BT_ASSERT_DBG(this->isDynLenBlob());
    return static_cast<DynLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const DynLenBlobFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenBlob() const noexcept
{
    BT_ASSERT_DBG(this->isDynLenBlob());
    return static_cast<const DynLenBlobFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
ArrayFc<UserMixinsT>& Fc<UserMixinsT>::asArray() noexcept
{
    BT_ASSERT_DBG(this->isArray());
    return static_cast<ArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const ArrayFc<UserMixinsT>& Fc<UserMixinsT>::asArray() const noexcept
{
    BT_ASSERT_DBG(this->isArray());
    return static_cast<const ArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StaticLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenArray() noexcept
{
    BT_ASSERT_DBG(this->isStaticLenArray());
    return static_cast<StaticLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StaticLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asStaticLenArray() const noexcept
{
    BT_ASSERT_DBG(this->isStaticLenArray());
    return static_cast<const StaticLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
DynLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenArray() noexcept
{
    BT_ASSERT_DBG(this->isDynLenArray());
    return static_cast<DynLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const DynLenArrayFc<UserMixinsT>& Fc<UserMixinsT>::asDynLenArray() const noexcept
{
    BT_ASSERT_DBG(this->isDynLenArray());
    return static_cast<const DynLenArrayFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
StructFc<UserMixinsT>& Fc<UserMixinsT>::asStruct() noexcept
{
    BT_ASSERT_DBG(this->isStruct());
    return static_cast<StructFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const StructFc<UserMixinsT>& Fc<UserMixinsT>::asStruct() const noexcept
{
    BT_ASSERT_DBG(this->isStruct());
    return static_cast<const StructFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalFc<UserMixinsT>& Fc<UserMixinsT>::asOptional() noexcept
{
    BT_ASSERT_DBG(this->isOptional());
    return static_cast<OptionalFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalFc<UserMixinsT>& Fc<UserMixinsT>::asOptional() const noexcept
{
    BT_ASSERT_DBG(this->isOptional());
    return static_cast<const OptionalFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalWithBoolSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithBoolSel() noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithBoolSel());
    return static_cast<OptionalWithBoolSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalWithBoolSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithBoolSel() const noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithBoolSel());
    return static_cast<const OptionalWithBoolSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithUIntSel() noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithUIntSel());
    return static_cast<OptionalWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithUIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithUIntSel());
    return static_cast<const OptionalWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
OptionalWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithSIntSel() noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithSIntSel());
    return static_cast<OptionalWithSIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const OptionalWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asOptionalWithSIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isOptionalWithSIntSel());
    return static_cast<const OptionalWithSIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VariantWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithUIntSel() noexcept
{
    BT_ASSERT_DBG(this->isVariantWithUIntSel());
    return static_cast<VariantWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VariantWithUIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithUIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isVariantWithUIntSel());
    return static_cast<const VariantWithUIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
VariantWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithSIntSel() noexcept
{
    BT_ASSERT_DBG(this->isVariantWithSIntSel());
    return static_cast<VariantWithSIntSelFc<UserMixinsT>&>(*this);
}

template <typename UserMixinsT>
const VariantWithSIntSelFc<UserMixinsT>& Fc<UserMixinsT>::asVariantWithSIntSel() const noexcept
{
    BT_ASSERT_DBG(this->isVariantWithSIntSel());
    return static_cast<const VariantWithSIntSelFc<UserMixinsT>&>(*this);
}

/*
 * Clock offset (seconds and cycles).
 */
class ClkOffset final
{
public:
    explicit ClkOffset(const long long seconds = 0, const unsigned long long cycles = 0) noexcept :
        _mSeconds {seconds}, _mCycles {cycles}
    {
    }

    /*
     * Seconds part of this clock offset offset.
     */
    long long seconds() const noexcept
    {
        return _mSeconds;
    }

    /*
     * Cycles part of this clock offset offset.
     */
    unsigned long long cycles() const noexcept
    {
        return _mCycles;
    }

private:
    /* Seconds part of this clock offset offset */
    long long _mSeconds;

    /* Cycles part of this clock offset offset */
    unsigned long long _mCycles;
};

/*
 * Clock origin (namespace, name, and unique ID).
 */
class ClkOrigin final
{
public:
    /*
     * Builds a clock origin having the (optional) namespace `ns`, the
     * name `name`, and the unique ID `uid`.
     */
    explicit ClkOrigin(bt2s::optional<std::string> ns, std::string name, std::string uid) :
        _mNs {std::move(ns)}, _mName {std::move(name)}, _mUid {std::move(uid)}
    {
    }

    /*
     * Builds a Unix epoch clock origin.
     */
    explicit ClkOrigin() : ClkOrigin {_unixEpochNs, _unixEpochName, _unixEpochUid}
    {
    }

    /*
     * Namespace.
     */
    const bt2s::optional<std::string>& ns() const noexcept
    {
        return _mNs;
    }

    /*
     * Name.
     */
    const std::string& name() const noexcept
    {
        return _mName;
    }

    /*
     * Unique ID.
     */
    const std::string& uid() const noexcept
    {
        return _mUid;
    }

    /*
     * Returns whether or not this clock origin is the Unix epoch.
     */
    bool isUnixEpoch() const noexcept
    {
        return _mNs == _unixEpochNs && _mName == _unixEpochName && _mUid == _unixEpochUid;
    }

private:
    /* Internal Unix epoch origin namespace, name, and unique ID */
    static const char * const _unixEpochNs;
    static const char * const _unixEpochName;
    static const char * const _unixEpochUid;

    /* Namespace */
    bt2s::optional<std::string> _mNs;

    /* Name */
    std::string _mName;

    /* Unique ID */
    std::string _mUid;
};

/*
 * Clock class.
 */
template <typename UserMixinsT>
class ClkCls final :
    public internal::WithAttrsMixin,
    public internal::WithLibCls<bt2::ClockClass>,
    public UserMixinsT::ClkCls
{
public:
    /* Shared pointer to a clock class */
    using SP = std::shared_ptr<ClkCls>;

    explicit ClkCls(typename UserMixinsT::ClkCls mixin, std::string id,
                    const unsigned long long freq, bt2s::optional<std::string> ns = bt2s::nullopt,
                    bt2s::optional<std::string> name = bt2s::nullopt,
                    bt2s::optional<std::string> uid = bt2s::nullopt,
                    const ClkOffset& offsetFromOrigin = ClkOffset {},
                    bt2s::optional<ClkOrigin> origin = ClkOrigin {},
                    bt2s::optional<std::string> descr = bt2s::nullopt,
                    bt2s::optional<unsigned long long> precision = bt2s::nullopt,
                    bt2s::optional<unsigned long long> accuracy = bt2s::nullopt,
                    OptAttrs attrs = OptAttrs {}) :
        internal::WithAttrsMixin {std::move(attrs)}, UserMixinsT::ClkCls {std::move(mixin)},
        _mId {std::move(id)}, _mNs {std::move(ns)}, _mName {std::move(name)},
        _mUid {std::move(uid)}, _mFreq {freq}, _mOffsetFromOrigin {offsetFromOrigin},
        _mOrigin {std::move(origin)}, _mDescr {std::move(descr)},
        _mPrecision {std::move(precision)}, _mAccuracy {std::move(accuracy)}
    {
        BT_ASSERT(_mFreq > 0);
        BT_ASSERT(_mOffsetFromOrigin.cycles() < _mFreq);
    }

    /*
     * Unique ID of this clock class within its trace class.
     */
    const std::string& id() const noexcept
    {
        return _mId;
    }

    /*
     * Namespace of instances of this clock class.
     */
    const bt2s::optional<std::string>& ns() const noexcept
    {
        return _mNs;
    }

    /*
     * Name of instances of this clock class.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * UID of instances of this clock class.
     */
    const bt2s::optional<std::string>& uid() const noexcept
    {
        return _mUid;
    }

    /*
     * Frequency (Hz) of instances of this clock class.
     */
    unsigned long long freq() const noexcept
    {
        return _mFreq;
    }

    /*
     * Offset from origin of instances of this clock class.
     */
    const ClkOffset& offsetFromOrigin() const noexcept
    {
        return _mOffsetFromOrigin;
    }

    /*
      * Sets the offset from origin of instances of this clock class.
      */
    void offsetFromOrigin(const ClkOffset& offsetFromOrigin) noexcept
    {
        _mOffsetFromOrigin = offsetFromOrigin;
    }

    /*
     * Origin of instances of this clock class.
     */
    const bt2s::optional<ClkOrigin>& origin() const noexcept
    {
        return _mOrigin;
    }

    /*
     * Sets the origin of instances of this clock class.
     */
    void origin(bt2s::optional<ClkOrigin> origin) noexcept
    {
        _mOrigin = std::move(origin);
    }

    /*
     * Description of instances of this clock class.
     */
    const bt2s::optional<std::string>& descr() const noexcept
    {
        return _mDescr;
    }

    /*
     * Precision (cycles) of instances of this clock class.
     */
    const bt2s::optional<unsigned long long>& precision() const noexcept
    {
        return _mPrecision;
    }

    /*
     * Accuracy (cycles) of instances of this clock class.
     */
    const bt2s::optional<unsigned long long>& accuracy() const noexcept
    {
        return _mAccuracy;
    }

private:
    /* Unique ID of this clock class within its trace class */
    std::string _mId;

    /* Namespace of instances of this clock class */
    bt2s::optional<std::string> _mNs;

    /* Name of instances of this clock class */
    bt2s::optional<std::string> _mName;

    /* UID of instances of this clock class */
    bt2s::optional<std::string> _mUid;

    /* Frequency (Hz) of instances of this clock class */
    unsigned long long _mFreq;

    /* Offset from origin of instances of this clock class */
    ClkOffset _mOffsetFromOrigin;

    /* Origin of instances of this clock class */
    bt2s::optional<ClkOrigin> _mOrigin;

    /* Description of instances of this clock class */
    bt2s::optional<std::string> _mDescr;

    /* Precision (cycles) of instances of this clock class */
    bt2s::optional<unsigned long long> _mPrecision;

    /* Accuracy (cycles) of instances of this clock class */
    bt2s::optional<unsigned long long> _mAccuracy;
};

/*
 * Event record class.
 */
template <typename UserMixinsT>
class EventRecordCls final :
    public internal::WithAttrsMixin,
    public internal::WithLibCls<bt2::EventClass>,
    public UserMixinsT::EventRecordCls
{
public:
    /* Unique pointer to an event record class */
    using UP = std::unique_ptr<EventRecordCls>;

    explicit EventRecordCls(typename UserMixinsT::EventRecordCls mixin, const unsigned long long id,
                            bt2s::optional<std::string> ns = bt2s::nullopt,
                            bt2s::optional<std::string> name = bt2s::nullopt,
                            bt2s::optional<std::string> uid = bt2s::nullopt,
                            typename StructFc<UserMixinsT>::UP specCtxFc = nullptr,
                            typename StructFc<UserMixinsT>::UP payloadFc = nullptr,
                            OptAttrs attrs = OptAttrs {}) :
        internal::WithAttrsMixin {std::move(attrs)}, UserMixinsT::EventRecordCls(std::move(mixin)),
        _mId {id}, _mNs {std::move(ns)}, _mName {std::move(name)}, _mUid {std::move(uid)},
        _mSpecCtxFc {std::move(specCtxFc)}, _mPayloadFc {std::move(payloadFc)}
    {
    }

    /*
     * ID of this event record class.
     */
    unsigned long long id() const noexcept
    {
        return _mId;
    }

    /*
     * Namespace of instances of this event record class.
     */
    const bt2s::optional<std::string>& ns() const noexcept
    {
        return _mNs;
    }

    /*
     * Name of instances of this event record class.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * UID of instances of this event record class.
     */
    const bt2s::optional<std::string>& uid() const noexcept
    {
        return _mUid;
    }

    /*
     * Class of the specific context field of instances of this event
     * record class.
     */
    const StructFc<UserMixinsT> *specCtxFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mSpecCtxFc.get());
    }

    /*
     * Class of the specific context field of instances of this event
     * record class.
     */
    StructFc<UserMixinsT> *specCtxFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mSpecCtxFc.get());
    }

    /*
     * Class of the payload field of instances of this event record
     * class.
     */
    const StructFc<UserMixinsT> *payloadFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPayloadFc.get());
    }

    /*
     * Class of the payload field of instances of this event record
     * class.
     */
    StructFc<UserMixinsT> *payloadFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPayloadFc.get());
    }

private:
    /* ID of this event record class */
    unsigned long long _mId;

    /* Namespace of instances of this event record class */
    bt2s::optional<std::string> _mNs;

    /* Name of instances of this event record class */
    bt2s::optional<std::string> _mName;

    /* UID of instances of this event record class */
    bt2s::optional<std::string> _mUid;

    /*
     * Class of the specific context field of instances of this event
     * record class.
     */
    typename StructFc<UserMixinsT>::UP _mSpecCtxFc;

    /*
     * Class of the payload field of instances of this event record
     * class.
     */
    typename StructFc<UserMixinsT>::UP _mPayloadFc;
};

namespace internal {

/*
 * Less-than functor working on numeric IDs of unique pointers to
 * `ObjT`.
 */
template <typename ObjT>
struct ObjUpIdLt final
{
    bool operator()(const typename ObjT::UP& objA, const typename ObjT::UP& objB) const noexcept
    {
        return objA->id() < objB->id();
    }
};

} /* namespace internal */

/*
 * Data stream class.
 */
template <typename UserMixinsT>
class DataStreamCls final :
    public internal::WithAttrsMixin,
    public internal::WithLibCls<bt2::StreamClass>,
    public UserMixinsT::DataStreamCls
{
public:
    /* Unique pointer to a data stream class */
    using UP = std::unique_ptr<DataStreamCls>;

    /* Event record class set */
    using EventRecordClsSet = std::set<typename EventRecordCls<UserMixinsT>::UP,
                                       internal::ObjUpIdLt<EventRecordCls<UserMixinsT>>>;

    explicit DataStreamCls(typename UserMixinsT::DataStreamCls mixin, const unsigned long long id,
                           bt2s::optional<std::string> ns = bt2s::nullopt,
                           bt2s::optional<std::string> name = bt2s::nullopt,
                           bt2s::optional<std::string> uid = bt2s::nullopt,
                           typename StructFc<UserMixinsT>::UP pktCtxFc = nullptr,
                           typename StructFc<UserMixinsT>::UP eventRecordHeaderFc = nullptr,
                           typename StructFc<UserMixinsT>::UP commonEventRecordCtxFc = nullptr,
                           typename ClkCls<UserMixinsT>::SP defClkCls = nullptr,
                           OptAttrs attrs = OptAttrs {}) :
        internal::WithAttrsMixin {std::move(attrs)}, UserMixinsT::DataStreamCls(std::move(mixin)),
        _mId {id}, _mNs {std::move(ns)}, _mName {std::move(name)}, _mUid {std::move(uid)},
        _mPktCtxFc {std::move(pktCtxFc)}, _mEventRecordHeaderFc {std::move(eventRecordHeaderFc)},
        _mCommonEventRecordCtxFc {std::move(commonEventRecordCtxFc)},
        _mDefClkCls {std::move(defClkCls)}
    {
    }

    /*
     * ID of this data stream class.
     */
    unsigned long long id() const noexcept
    {
        return _mId;
    }

    /*
     * Namespace of instances of this data stream class.
     */
    const bt2s::optional<std::string>& ns() const noexcept
    {
        return _mNs;
    }

    /*
     * Name of instances of this data stream class.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * UID of instances of this data stream class.
     */
    const bt2s::optional<std::string>& uid() const noexcept
    {
        return _mUid;
    }

    /*
     * Class of the packet context field of instances of this data
     * stream class.
     */
    const StructFc<UserMixinsT> *pktCtxFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktCtxFc.get());
    }

    /*
     * Class of the context field of packets which are part of instances
     * of this data stream class.
     */
    StructFc<UserMixinsT> *pktCtxFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktCtxFc.get());
    }

    /*
     * Class of the context field of packets which are part of instances
     * of this data stream class.
     */
    const StructFc<UserMixinsT> *eventRecordHeaderFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mEventRecordHeaderFc.get());
    }

    /*
     * Class of the header field of event records which are part of
     * instances of this data stream class.
     */
    StructFc<UserMixinsT> *eventRecordHeaderFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mEventRecordHeaderFc.get());
    }

    /*
     * Class of the header field of event records which are part of
     * instances of this data stream class.
     */
    const StructFc<UserMixinsT> *commonEventRecordCtxFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mCommonEventRecordCtxFc.get());
    }

    /*
     * Class of the common context field of event records which are part
     * of instances of this data stream class.
     */
    StructFc<UserMixinsT> *commonEventRecordCtxFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mCommonEventRecordCtxFc.get());
    }

    /*
     * Class of the common context field of event records which are part
     * of instances of this data stream class.
     */
    const ClkCls<UserMixinsT> *defClkCls() const noexcept
    {
        return _mDefClkCls.get();
    }

    /*
     * Class of the default clock of instances of this data stream
     * class.
     */
    ClkCls<UserMixinsT> *defClkCls() noexcept
    {
        return _mDefClkCls.get();
    }

    /*
     * Event record classes of this data stream class.
     */
    const EventRecordClsSet& eventRecordClasses() const noexcept
    {
        return _mEventRecordClasses;
    }

    /*
     * Adds the event record class `eventRecordCls` to the set of event
     * record classes of this data stream class.
     */
    void addEventRecordCls(typename EventRecordCls<UserMixinsT>::UP eventRecordCls)
    {
        BT_ASSERT_DBG(eventRecordCls);
        _mEventRecordClsIdMap[eventRecordCls->id()] = eventRecordCls.get();
        _mEventRecordClasses.emplace(std::move(eventRecordCls));
    }

    const EventRecordCls<UserMixinsT> *operator[](const unsigned long long id) const noexcept
    {
        return this->_eventRecordClsById<const EventRecordCls<UserMixinsT>>(*this, id);
    }

    EventRecordCls<UserMixinsT> *operator[](const unsigned long long id) noexcept
    {
        return this->_eventRecordClsById<EventRecordCls<UserMixinsT>>(*this, id);
    }

    typename EventRecordClsSet::size_type size() const noexcept
    {
        return _mEventRecordClasses.size();
    }

    typename EventRecordClsSet::const_iterator begin() const noexcept
    {
        return _mEventRecordClasses.begin();
    }

    typename EventRecordClsSet::iterator begin() noexcept
    {
        return _mEventRecordClasses.begin();
    }

    typename EventRecordClsSet::const_iterator end() const noexcept
    {
        return _mEventRecordClasses.end();
    }

    typename EventRecordClsSet::iterator end() noexcept
    {
        return _mEventRecordClasses.end();
    }

private:
    using _EventRecordClsByIdMap =
        std::unordered_map<unsigned long long, EventRecordCls<UserMixinsT> *>;

    template <typename ValT, typename DataStreamClsT>
    static ValT *_eventRecordClsById(DataStreamClsT& dataStreamCls,
                                     const unsigned long long id) noexcept
    {
        const auto it = dataStreamCls._mEventRecordClsIdMap.find(id);

        if (it == dataStreamCls._mEventRecordClsIdMap.end()) {
            return nullptr;
        }

        return it->second;
    }

    /* ID of this data stream class */
    unsigned long long _mId;

    /* Event record classes of this data stream class */
    EventRecordClsSet _mEventRecordClasses;

    /* Map of event record class ID to event record class */
    _EventRecordClsByIdMap _mEventRecordClsIdMap;

    /* Namespace of instances of this data stream class */
    bt2s::optional<std::string> _mNs;

    /* Name of instances of this data stream class */
    bt2s::optional<std::string> _mName;

    /* UID of instances of this data stream class */
    bt2s::optional<std::string> _mUid;

    /*
     * Class of the context field of packets which are part of instances
     * of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mPktCtxFc;

    /*
     * Class of the header field of event records which are part of
     * instances of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mEventRecordHeaderFc;

    /*
     * Class of the common context field of event records which are part
     * of instances of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mCommonEventRecordCtxFc;

    /*
     * Class of the default clock of instances of this data stream
     * class.
     */
    typename ClkCls<UserMixinsT>::SP _mDefClkCls;
};

/*
 * Trace class.
 */
template <typename UserMixinsT>
class TraceCls final :
    public internal::WithAttrsMixin,
    public internal::WithLibCls<bt2::TraceClass>,
    public UserMixinsT::TraceCls
{
public:
    /* Data stream class set */
    using DataStreamClsSet = std::set<typename DataStreamCls<UserMixinsT>::UP,
                                      internal::ObjUpIdLt<DataStreamCls<UserMixinsT>>>;

    explicit TraceCls(typename UserMixinsT::TraceCls mixin,
                      bt2s::optional<std::string> ns = bt2s::nullopt,
                      bt2s::optional<std::string> name = bt2s::nullopt,
                      bt2s::optional<std::string> uid = bt2s::nullopt,
                      bt2::ConstMapValue::Shared env = bt2::ConstMapValue::Shared {},
                      typename Fc<UserMixinsT>::UP pktHeaderFc = nullptr,
                      OptAttrs attrs = OptAttrs {}) :
        internal::WithAttrsMixin {std::move(attrs)}, UserMixinsT::TraceCls {std::move(mixin)},
        _mNs {std::move(ns)}, _mName {std::move(name)}, _mUid {std::move(uid)},
        _mEnv {std::move(env)}, _mPktHeaderFc {std::move(pktHeaderFc)}
    {
        BT_ASSERT(!_mPktHeaderFc || _mPktHeaderFc->isStruct());
    }

    /*
     * Namespace of instances of this trace class.
     */
    const bt2s::optional<std::string>& ns() const noexcept
    {
        return _mNs;
    }

    /*
     * Name of instances of this trace class.
     */
    const bt2s::optional<std::string>& name() const noexcept
    {
        return _mName;
    }

    /*
     * UID of instances of this trace class.
     */
    const bt2s::optional<std::string>& uid() const noexcept
    {
        return _mUid;
    }

    /*
     * Environment of instances of this trace class.
     */
    const bt2::ConstMapValue::Shared& env() const noexcept
    {
        return _mEnv;
    }

    /*
     * Class of the header field of packets which are part of instances
     * of this data stream class.
     */
    const StructFc<UserMixinsT> *pktHeaderFc() const noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktHeaderFc.get());
    }

    /*
     * Class of the header field of packets which are part of instances
     * of this data stream class.
     */
    StructFc<UserMixinsT> *pktHeaderFc() noexcept
    {
        return static_cast<StructFc<UserMixinsT> *>(_mPktHeaderFc.get());
    }

    /*
     * Data stream classes of this trace class.
     */
    const DataStreamClsSet& dataStreamClasses() const noexcept
    {
        return _mDataStreamClasses;
    }

    /*
     * Adds the data stream class `dataStreamCls` to the set of data
     * stream classes of this trace class.
     */
    void addDataStreamCls(typename DataStreamCls<UserMixinsT>::UP dataStreamCls)
    {
        BT_ASSERT_DBG(dataStreamCls);
        _mDataStreamClsIdMap[dataStreamCls->id()] = dataStreamCls.get();
        _mDataStreamClasses.emplace(std::move(dataStreamCls));
    }

    const DataStreamCls<UserMixinsT> *operator[](const unsigned long long id) const noexcept
    {
        return this->_dataStreamClsById<const DataStreamCls<UserMixinsT>>(*this, id);
    }

    DataStreamCls<UserMixinsT> *operator[](const unsigned long long id) noexcept
    {
        return this->_dataStreamClsById<DataStreamCls<UserMixinsT>>(*this, id);
    }

    typename DataStreamClsSet::size_type size() const noexcept
    {
        return _mDataStreamClasses.size();
    }

    typename DataStreamClsSet::const_iterator begin() const noexcept
    {
        return _mDataStreamClasses.begin();
    }

    typename DataStreamClsSet::iterator begin() noexcept
    {
        return _mDataStreamClasses.begin();
    }

    typename DataStreamClsSet::const_iterator end() const noexcept
    {
        return _mDataStreamClasses.end();
    }

    typename DataStreamClsSet::iterator end() noexcept
    {
        return _mDataStreamClasses.end();
    }

private:
    using _DataStreamClsByIdMap =
        std::unordered_map<unsigned long long, DataStreamCls<UserMixinsT> *>;

    template <typename ValT, typename TraceClsT>
    static ValT *_dataStreamClsById(TraceClsT& traceCls, const unsigned long long id) noexcept
    {
        const auto it = traceCls._mDataStreamClsIdMap.find(id);

        if (it == traceCls._mDataStreamClsIdMap.end()) {
            return nullptr;
        }

        return it->second;
    }

    /* Data stream classes of this trace class */
    DataStreamClsSet _mDataStreamClasses;

    /* Map of data stream class ID to data stream class */
    _DataStreamClsByIdMap _mDataStreamClsIdMap;

    /* Namespace of instances of this trace class */
    bt2s::optional<std::string> _mNs;

    /* Name of instances of this trace class */
    bt2s::optional<std::string> _mName;

    /* UID of instances of this trace class */
    bt2s::optional<std::string> _mUid;

    /* Environment of instances of this trace class */
    bt2::ConstMapValue::Shared _mEnv;

    /*
     * Class of the header field of packets which are part of instances
     * of this data stream class.
     */
    typename Fc<UserMixinsT>::UP _mPktHeaderFc;
};

/*
 * Default user mixins.
 */
struct DefUserMixins
{
    struct FieldLoc
    {
    };

    struct Fc
    {
    };

    struct FixedLenBitArrayFc
    {
    };

    struct FixedLenBitMapFc
    {
    };

    struct FixedLenBoolFc
    {
    };

    struct FixedLenIntFc
    {
    };

    struct FixedLenUIntFc
    {
    };

    struct VarLenIntFc
    {
    };

    struct VarLenUIntFc
    {
    };

    struct StaticLenStrFc
    {
    };

    struct DynLenStrFc
    {
    };

    struct StaticLenBlobFc
    {
    };

    struct DynLenBlobFc
    {
    };

    struct StaticLenArrayFc
    {
    };

    struct DynLenArrayFc
    {
    };

    struct StructFieldMemberCls
    {
    };

    struct StructFc
    {
    };

    struct OptionalFc
    {
    };

    struct OptionalWithBoolSelFc
    {
    };

    struct OptionalWithIntSelFc
    {
    };

    struct OptionalWithUIntSelFc
    {
    };

    struct OptionalWithSIntSelFc
    {
    };

    struct VariantFcOpt
    {
    };

    struct VariantFc
    {
    };

    struct VariantWithUIntSelFc
    {
    };

    struct VariantWithSIntSelFc
    {
    };

    struct ClkCls
    {
    };

    struct EventRecordCls
    {
    };

    struct DataStreamCls
    {
    };

    struct TraceCls
    {
    };
};

} /* namespace ir */
} /* namespace ctf */

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_METADATA_CTF_IR_HPP */
