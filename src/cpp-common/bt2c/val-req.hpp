/*
 * Copyright (c) 2022-2024 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_VAL_REQ_HPP
#define BABELTRACE_CPP_COMMON_BT2C_VAL_REQ_HPP

#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>

#include "logging.hpp"

#include "exc.hpp"
#include "text-loc.hpp"

namespace bt2c {

/*
 * This set of class templates makes it possible to get basic
 * requirement classes to validate JSON-like value objects, that is, a
 * system of null, boolean, unsigned/signed integer, real, string,
 * array, and object value objects.
 *
 * All the class templates accept a `ValT` parameter which is the base
 * type of the objects to validate, as well as `ValOpsT`, a structure
 * which defines specific value operations.
 *
 * The requirements of `ValOptsT` are:
 *
 * static ValType valType(const ValT& val):
 *     Returns the type of `val` as a `ValType` value.
 *
 * static const char *typeDetStr(ValType type):
 *     Returns the determiner (lowercase) to use for the value type
 *     `type`.
 *
 *     This is required to generate an error message.
 *
 * static const char *typeStr(ValType type):
 *     Returns the name (lowercase) of the value type `type`.
 *
 *     This is required to generate an error message.
 *
 * static constexpr const char *objValPropName:
 *     Name (lowercase) of an object value object property.
 *
 * static const TextLoc& valLoc(const ValT& val):
 *     Returns the location of the value `val`.
 *
 *     This is required to build a text parse error (`TextParseError`).
 *
 * static const SomeUIntVal& asUInt(const ValT& val):
 *     Returns `val` as an unsigned integer value object.
 *
 * static const SomeStrVal& asStr(const ValT& val):
 *     Returns `val` as a string value object.
 *
 * static const SomeArrayVal& asArray(const ValT& val):
 *     Returns `val` as an array value object.
 *
 * static const SomeObjVal& asObj(const ValT& val):
 *     Returns `val` as an object value object.
 *
 * template <typename ScalarValT> using ScalarValRawValT = ...:
 *     Raw value type of the scalar value object type `ScalarValT`.
 *
 * static unsigned long long scalarValRawVal(const SomeUIntVal& val):
 *     Returns the raw value of the unsigned value object `val`.
 *
 * static long long scalarValRawVal(const SomeSIntVal& val):
 *     Returns the raw value of the signed value object `val`.
 *
 * static double scalarValRawVal(const SomeRealVal& val):
 *     Returns the raw value of the real value object `val`.
 *
 * static const std::string& scalarValRawVal(const SomeStrVal& val):
 *     Returns the raw value of the string value object `val`.
 *
 * static std::size_t arrayValSize(const SomeArrayVal& val):
 *     Returns the size of the array value object `val`.
 *
 * static const ValT& arrayValElem(const SomeArrayVal& val, std::size_t index):
 *     Returns the element of the array value object `val` at the index
 *     `index`.
 *
 * static const ValT *objValVal(const SomeObjVal& val, const std::string& key):
 *     Returns the value of the object value object `val` having the key
 *     `key`, or `nullptr` if there's none.
 *
 * static SomeIterator objValBegin(const SomeObjVal& val):
 *     Returns an iterator at the beginning of the object value object
 *     `val`.
 *
 * static SomeIterator objValEnd(const SomeObjVal& val):
 *     Returns an iterator at the end of the object value object `val`.
 *
 * static const std::string& objValItKey(const SomeIterator& it):
 *     Returns the key of the object value object iterator `it`.
 *
 * static const ValT& objValItVal(const SomeIterator& it):
 *     Returns the value object of the object value object iterator
 *     `it`.
 */

/*
 * Value requirement abstract base class.
 */
template <typename ValT, typename ValOpsT>
class ValReq
{
public:
    /* Shared pointer to constant value requirement */
    using SP = std::shared_ptr<const ValReq>;

protected:
    /*
     * Builds a value requirement.
     */
    explicit ValReq(const Logger& parentLogger) noexcept : _mLogger {parentLogger, "VAL-REQ"}
    {
    }

public:
    /* Deleted copy/move operations to simplify */
    ValReq(const ValReq&) = delete;
    ValReq(ValReq&&) = delete;
    ValReq& operator=(const ValReq&) = delete;
    ValReq& operator=(ValReq&&) = delete;

    virtual ~ValReq() = default;

    /*
     * Validates that `val` satisfies this requirement.
     */
    void validate(const ValT& val) const
    {
        this->_validate(val);
    }

protected:
    static const TextLoc& _loc(const ValT& val) noexcept
    {
        return ValOpsT::valLoc(val);
    }

    const Logger& _logger() const noexcept
    {
        return _mLogger;
    }

private:
    /*
     * Requirement-specific validation.
     */
    virtual void _validate(const ValT&) const
    {
    }

protected:
    Logger _mLogger;
};

/*
 * Value type.
 */
enum class ValType
{
    Null,
    Bool,
    SInt,
    UInt,
    Real,
    Str,
    Array,
    Obj,
};

/*
 * "Value has type" requirement.
 *
 * An instance of this class validates that a value has a given type.
 */
template <typename ValT, typename ValOpsT>
class ValHasTypeReq : public ValReq<ValT, ValOpsT>
{
public:
    /*
     * Builds a "value has type" requirement: _validate() validates that
     * the type of the value is `type`.
     */
    explicit ValHasTypeReq(const ValType type, const Logger& parentLogger) noexcept :
        ValReq<ValT, ValOpsT> {parentLogger}, _mType {type}
    {
    }

    /*
     * Returns a shared pointer to "value has type" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const ValType type, const Logger& parentLogger)
    {
        return std::make_shared<ValHasTypeReq>(type, parentLogger);
    }

protected:
    void _validate(const ValT& val) const override
    {
        if (ValOpsT::valType(val) != _mType) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), Error, this->_loc(val), "Expecting {} {}.",
                ValOpsT::typeDetStr(_mType), ValOpsT::typeStr(_mType));
        }
    }

private:
    /* Required value type */
    ValType _mType;
};

/*
 * Any integer value requirement.
 *
 * An instance of this class validates that a value is an integer value
 * (unsigned or signed).
 */
template <typename ValT, typename ValOpsT>
class AnyIntValReq : public ValReq<ValT, ValOpsT>
{
public:
    explicit AnyIntValReq(const Logger& parentLogger) noexcept :
        ValReq<ValT, ValOpsT> {parentLogger}
    {
    }

    /*
     * Returns a shared pointer to any integer value requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const Logger& parentLogger)
    {
        return std::make_shared<AnyIntValReq>(parentLogger);
    }

protected:
    void _validate(const ValT& val) const override
    {
        if (!val.isUInt() && !val.isSInt()) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(this->_logger(), Error, this->_loc(val),
                                                            "Expecting an integer.");
        }
    }
};

/*
 * Unsigned integer (range) value requirement.
 *
 * An instance of this class validates that a value is an unsigned
 * integer value.
 */
template <typename ValT, typename ValOpsT>
class UIntValReq : public ValHasTypeReq<ValT, ValOpsT>
{
public:
    /*
     * Builds an unsigned integer value: _validate() validates that the
     * integer value is an unsigned integer type.
     */
    explicit UIntValReq(const Logger& parentLogger) noexcept :
        ValHasTypeReq<ValT, ValOpsT> {ValType::UInt, parentLogger}
    {
    }

    /*
     * Returns a shared pointer to unsigned integer value requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const Logger& parentLogger)
    {
        return std::make_shared<UIntValReq>(parentLogger);
    }
};

/*
 * Signed integer value (range) requirement.
 *
 * An instance of this class validates that a value is an integer value
 * (unsigned or signed) and that its raw value is between
 * -9,223,372,036,854,775,808 and 9,223,372,036,854,775,807.
 */
template <typename ValT, typename ValOpsT>
class SIntValReq : public AnyIntValReq<ValT, ValOpsT>
{
public:
    explicit SIntValReq(const Logger& parentLogger) noexcept :
        AnyIntValReq<ValT, ValOpsT> {parentLogger}
    {
    }

    /*
     * Returns a shared pointer to signed value requirement, forwarding
     * the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const Logger& parentLogger)
    {
        return std::make_shared<SIntValReq>(parentLogger);
    }

protected:
    void _validate(const ValT& val) const override
    {
        /* Validate that it's an integer value */
        AnyIntValReq<ValT, ValOpsT>::_validate(val);

        if (ValOpsT::valType(val) == ValType::SInt) {
            /* Always correct */
            return;
        }

        /* Validate the raw value */
        static constexpr auto llMaxAsUll =
            static_cast<unsigned long long>(std::numeric_limits<long long>::max());

        const auto rawVal = ValOpsT::scalarValRawVal(ValOpsT::asUInt(val));

        if (rawVal > llMaxAsUll) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), Error, this->_loc(val),
                "Expecting a signed integer: {} is greater than {}.", rawVal, llMaxAsUll);
        }
    }
};

/*
 * "Integer value in range" requirement template.
 *
 * An instance of this class validates that, given a value V of type
 * `IntValT`:
 *
 * • V has the type enumerator `TypeV`.
 * • The raw value of V is within a given range.
 */
template <typename ValT, typename ValOpsT, typename IntValT, ValType TypeV>
class IntValInRangeReq : public ValHasTypeReq<ValT, ValOpsT>
{
private:
    /* Raw value type */
    using _RawVal = typename ValOpsT::template ScalarValRawValT<IntValT>;

public:
    /*
     * Builds an "integer value in range" requirement: _validate()
     * validates that the raw value of the integer value is:
     *
     * • If `minVal` is set: greater than or equal to `*minVal`.
     * • If `maxVal` is set: less than or equal to `*maxVal`.
     */
    explicit IntValInRangeReq(const bt2s::optional<_RawVal>& minVal,
                              const bt2s::optional<_RawVal>& maxVal,
                              const Logger& parentLogger) noexcept :
        ValHasTypeReq<ValT, ValOpsT> {TypeV, parentLogger},
        _mMinVal {minVal ? *minVal : std::numeric_limits<_RawVal>::min()},
        _mMaxVal {maxVal ? *maxVal : std::numeric_limits<_RawVal>::max()}
    {
    }

    /*
     * Builds an "integer value in range" requirement: _validate()
     * validates that the raw value of the integer value is exactly
     * `exactVal`.
     */
    explicit IntValInRangeReq(const _RawVal exactVal, const Logger& parentLogger) noexcept :
        IntValInRangeReq {exactVal, exactVal, parentLogger}
    {
    }

    /*
     * Returns a shared pointer to "integer value in range" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const bt2s::optional<_RawVal>& minVal,
                                                     const bt2s::optional<_RawVal>& maxVal,
                                                     const Logger& parentLogger)
    {
        return std::make_shared<IntValInRangeReq>(minVal, maxVal, parentLogger);
    }

    /*
     * Returns a shared pointer to "integer value in range" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(const _RawVal exactVal,
                                                     const Logger& parentLogger)
    {
        return std::make_shared<IntValInRangeReq>(exactVal, parentLogger);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& intVal = static_cast<const IntValT&>(val);
        const auto rawVal = ValOpsT::scalarValRawVal(intVal);

        if (rawVal < _mMinVal) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), Error, this->_loc(intVal),
                "Integer {} is too small: expecting at least {}.", rawVal, _mMinVal);
        }

        if (rawVal > _mMaxVal) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), Error, this->_loc(intVal),
                "Integer {} is too large: expecting at most {}.", rawVal, _mMaxVal);
        }
    }

private:
    /* Minimum raw value */
    _RawVal _mMinVal;

    /* Maximum raw value */
    _RawVal _mMaxVal;
};

namespace internal {

template <typename RawValT>
std::string rawValStr(const RawValT& rawVal)
{
    return fmt::to_string(rawVal);
}

template <>
inline std::string rawValStr<std::string>(const std::string& val)
{
    return fmt::format("`{}`", val);
}

template <>
inline std::string rawValStr<bool>(const bool& val)
{
    return val ? "true" : "false";
}

} /* namespace internal */

/*
 * "Scalar value in set" requirement template.
 *
 * An instance of this class validates that, given a value V of type
 * `ScalarValT`:
 *
 * • V has the type enumerator `TypeV`.
 * • The raw value of V is an element of a given set.
 */
template <typename ValT, typename ValOpsT, typename ScalarValT, ValType TypeV>
class ScalarValInSetReq : public ValHasTypeReq<ValT, ValOpsT>
{
private:
    /* Raw value type */
    using _RawVal = typename ValOpsT::template ScalarValRawValT<ScalarValT>;

public:
    /*
     * Raw value set type.
     *
     * Using `std::set` instead of `std::unordered_set` because
     * _setStr() needs the elements in order.
     */
    using Set = std::set<_RawVal>;

    /*
     * Builds a "scalar value in set" requirement: _validate() validates
     * that the raw value of the scalar value is an element of `set`.
     */
    explicit ScalarValInSetReq(Set set, const Logger& parentLogger) :
        ValHasTypeReq<ValT, ValOpsT> {TypeV, parentLogger}, _mSet {std::move(set)}
    {
    }

    /*
     * Builds a "scalar value in set" requirement: _validate() validates
     * that the raw value of the scalar value is exactly `rawVal`.
     */
    explicit ScalarValInSetReq(_RawVal rawVal, const Logger& parentLogger) :
        ScalarValInSetReq {Set {std::move(rawVal)}, parentLogger}
    {
    }

    /*
     * Returns a shared pointer to "scalar value in set" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(Set set, const Logger& parentLogger)
    {
        return std::make_shared<ScalarValInSetReq>(std::move(set), parentLogger);
    }

    /*
     * Returns a shared pointer to "scalar value in set" requirement,
     * forwarding the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(_RawVal rawVal, const Logger& parentLogger)
    {
        return std::make_shared<ScalarValInSetReq>(std::move(rawVal), parentLogger);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& scalarVal = static_cast<const ScalarValT&>(val);
        const auto& rawVal = ValOpsT::scalarValRawVal(scalarVal);

        if (_mSet.find(rawVal) == _mSet.end()) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), Error, this->_loc(val), "Unexpected value {}: expecting {}.",
                internal::rawValStr(rawVal), this->_setStr());
        }
    }

private:
    /*
     * Serializes the raw values of `_mSet` and returns the resulting
     * string.
     */
    std::string _setStr() const
    {
        if (_mSet.size() == 1) {
            /* Special case: direct value */
            return internal::rawValStr(*_mSet.begin());
        } else if (_mSet.size() == 2) {
            /* Special case: "or" word without any comma */
            return fmt::format("{} or {}", internal::rawValStr(*_mSet.begin()),
                               internal::rawValStr(*std::next(_mSet.begin())));
        }

        /* Enumeration with at least one comma */
        std::ostringstream ss;

        {
            const auto lastIt = std::prev(_mSet.end());

            for (auto it = _mSet.begin(); it != lastIt; ++it) {
                ss << internal::rawValStr(*it) << ", ";
            }

            ss << "or " << internal::rawValStr(*lastIt);
        }

        return ss.str();
    }

    /* Set of expected raw values */
    Set _mSet;
};

/*
 * Array value requirement.
 *
 * An instance of this class validates that, given a value V:
 *
 * • V is an array value.
 * • The size of V is within a given range.
 * • All the elements of V satisfy a given value requirement.
 */
template <typename ValT, typename ValOpsT>
class ArrayValReq : public ValHasTypeReq<ValT, ValOpsT>
{
public:
    using SP = typename ValReq<ValT, ValOpsT>::SP;

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • If `minSize` is set: the size of V is greater than or equal to
     *   `*minSize`.
     *
     * • If `maxSize` is set: the size of V is less than or equal to
     *   `*maxSize`.
     *
     * • If `elemValReq` is set: all the elements of V satisfy
     *   `*elemValReq`.
     */
    explicit ArrayValReq(const bt2s::optional<std::size_t>& minSize,
                         const bt2s::optional<std::size_t>& maxSize, SP elemValReq,
                         const Logger& parentLogger) :
        ValHasTypeReq<ValT, ValOpsT> {ValType::Array, parentLogger},
        _mMinSize {minSize ? *minSize : std::numeric_limits<std::size_t>::min()},
        _mMaxSize {maxSize ? *maxSize : std::numeric_limits<std::size_t>::max()},
        _mElemValReq {std::move(elemValReq)}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • If `minSize` is set: the size of V is greater than or equal to
     *   `*minSize`.
     *
     * • If `maxSize` is set: the size of V is less than or equal to
     *   `*maxSize`.
     */
    explicit ArrayValReq(const bt2s::optional<std::size_t>& minSize,
                         const bt2s::optional<std::size_t>& maxSize, const Logger& parentLogger) :
        ArrayValReq {minSize, maxSize, nullptr, parentLogger}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • The size of V is exactly `exactSize`.
     *
     * • If `elemValReq` is set: all the elements of V satisfy
     *   `*elemValReq`.
     */
    explicit ArrayValReq(const std::size_t exactSize, SP elemValReq, const Logger& parentLogger) :
        ArrayValReq {exactSize, exactSize, std::move(elemValReq), parentLogger}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that,
     * for a given array value V:
     *
     * • The size of V is exactly `exactSize`.
     */
    explicit ArrayValReq(const std::size_t exactSize, const Logger& parentLogger) :
        ArrayValReq {exactSize, exactSize, nullptr, parentLogger}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that all
     * the elements of a given array value satisfy `*elemValReq`, if
     * set.
     */
    explicit ArrayValReq(SP elemValReq, const Logger& parentLogger) :
        ArrayValReq {bt2s::nullopt, bt2s::nullopt, std::move(elemValReq), parentLogger}
    {
    }

    /*
     * Builds an array value requirement: _validate() validates that
     * a given value is an array value.
     */
    explicit ArrayValReq(const Logger& parentLogger) :
        ArrayValReq {bt2s::nullopt, bt2s::nullopt, parentLogger}
    {
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const bt2s::optional<std::size_t>& minSize,
                     const bt2s::optional<std::size_t>& maxSize, SP elemValReq,
                     const Logger& parentLogger)
    {
        return std::make_shared<ArrayValReq>(minSize, maxSize, std::move(elemValReq), parentLogger);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const bt2s::optional<std::size_t>& minSize,
                     const bt2s::optional<std::size_t>& maxSize, const Logger& parentLogger)
    {
        return std::make_shared<ArrayValReq>(minSize, maxSize, parentLogger);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const std::size_t exactSize, SP elemValReq, const Logger& parentLogger)
    {
        return std::make_shared<ArrayValReq>(exactSize, std::move(elemValReq), parentLogger);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(const std::size_t exactSize, const Logger& parentLogger)
    {
        return std::make_shared<ArrayValReq>(exactSize, parentLogger);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameters to the constructor.
     */
    static SP shared(SP elemValReq, const Logger& parentLogger)
    {
        return std::make_shared<ArrayValReq>(std::move(elemValReq), parentLogger);
    }

    /*
     * Returns a shared pointer to array value requirement, forwarding
     * the parameter to the constructor.
     */
    static SP shared(const Logger& parentLogger)
    {
        return std::make_shared<ArrayValReq>(parentLogger);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& arrayVal = ValOpsT::asArray(val);
        const auto size = ValOpsT::arrayValSize(arrayVal);

        if (size < _mMinSize) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), Error, this->_loc(val),
                "Size of array ({}) is too small: expecting at least {} elements.", size,
                _mMinSize);
        }

        if (size > _mMaxSize) {
            BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                this->_logger(), Error, this->_loc(val),
                "Size of array ({}) is too large: expecting at most {} elements.", size, _mMaxSize);
        }

        if (_mElemValReq) {
            for (std::size_t i = 0; i < size; ++i) {
                auto& elemVal = ValOpsT::arrayValElem(arrayVal, i);

                try {
                    _mElemValReq->validate(elemVal);
                } catch (const Error&) {
                    BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW_SPEC(
                        this->_logger(), this->_loc(elemVal), "Invalid array element #{}.", i + 1);
                }
            }
        }
    }

private:
    std::size_t _mMinSize;
    std::size_t _mMaxSize;
    SP _mElemValReq;
};

/*
 * Object value property requirement.
 *
 * An instance of this class contains the requirements of a single
 * object value property, that is:
 *
 * • Whether or not it's required.
 * • The requirement of the value of the property.
 */
template <typename ValT, typename ValOpsT>
class ObjValPropReq final
{
public:
    /*
     * Builds an object value property requirement, required if
     * `isRequired` is true: if `valReq` is set, then validate()
     * validates that a value satisfies `*valReq`.
     *
     * Not `explicit` to make the construction of `ObjValReq` lighter.
     */
    ObjValPropReq(typename ValReq<ValT, ValOpsT>::SP valReq = nullptr,
                  const bool isRequired = false) :
        _mIsRequired {isRequired}, _mValReq {std::move(valReq)}
    {
    }

    /*
     * Whether or not the property is required.
     */
    bool isRequired() const noexcept
    {
        return _mIsRequired;
    }

    /*
     * Validates that `val` satisfies this requirement.
     */
    void validate(const ValT& val) const
    {
        if (_mValReq) {
            _mValReq->validate(val);
        }
    }

private:
    /* Whether or not this property is required */
    bool _mIsRequired = false;

    /* Requirement of the value */
    typename ValReq<ValT, ValOpsT>::SP _mValReq;
};

/*
 * Object value requirement.
 *
 * An instance of this class validates that, given a value V:
 *
 * • V is an object value.
 *
 * • The properties of V satisfy a given set of object value property
 *   requirements.
 */
template <typename ValT, typename ValOpsT>
class ObjValReq : public ValHasTypeReq<ValT, ValOpsT>
{
public:
    /* Map of property name to property requirement */
    using PropReqs = std::unordered_map<std::string, ObjValPropReq<ValT, ValOpsT>>;

    /* Single entry (pair) of `PropReqs` */
    using PropReqsEntry = typename PropReqs::value_type;

public:
    /*
     * Builds an object value requirement: _validate() validates that,
     * for a given object value V:
     *
     * • If `allowUnknownProps` is false, then V has no value of which
     *   the key is not an element of the keys of `propReqs`.
     *
     * • For each property requirement PR having the key K in
     *   `propReqs`: if `PR.isRequired()`, then a value having the key K
     *   exists in V.
     *
     * • For each value VV having the key K in V: VV satisfies the value
     *   requirement, if any, of `propReqs[K]`.
     */
    explicit ObjValReq(PropReqs propReqs, const bool allowUnknownProps,
                       const Logger& parentLogger) :
        ValHasTypeReq<ValT, ValOpsT> {ValType::Obj, parentLogger}, _mPropReqs {std::move(propReqs)},
        _mAllowUnknownProps {allowUnknownProps}
    {
    }

    /*
     * Builds an object value requirement: _validate() validates that,
     * for a given object value V:
     *
     * • V has no value of which the key is not an element of the keys
     *   of `propReqs`.
     *
     * • For each property requirement PR having the key K in
     *   `propReqs`: if `PR.isRequired()`, then a value having the key K
     *   exists in V.
     *
     * • For each value VV having the key K in V: VV satisfies the value
     *   requirement, if any, of `propReqs[K]`.
     */
    explicit ObjValReq(PropReqs propReqs, const Logger& parentLogger) :
        ObjValReq {std::move(propReqs), false, parentLogger}
    {
    }

    /*
     * Returns a shared pointer to object value requirement, forwarding
     * the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP
    shared(PropReqs propReqs, const bool allowUnknownProps, const Logger& parentLogger)
    {
        return std::make_shared<ObjValReq>(std::move(propReqs), allowUnknownProps, parentLogger);
    }

    /*
     * Returns a shared pointer to object value requirement, forwarding
     * the parameters to the constructor.
     */
    static typename ValReq<ValT, ValOpsT>::SP shared(PropReqs propReqs, const Logger& parentLogger)
    {
        return std::make_shared<ObjValReq>(std::move(propReqs), parentLogger);
    }

protected:
    void _validate(const ValT& val) const override
    {
        ValHasTypeReq<ValT, ValOpsT>::_validate(val);

        auto& objVal = ValOpsT::asObj(val);
        const auto objValTypeStr = ValOpsT::typeStr(ValType::Obj);

        for (auto& keyPropReqPair : _mPropReqs) {
            auto& key = keyPropReqPair.first;

            if (keyPropReqPair.second.isRequired() && !ValOpsT::objValVal(objVal, key)) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                    this->_logger(), Error, this->_loc(objVal), "Missing mandatory {} {} `{}`.",
                    objValTypeStr, ValOpsT::objValPropName, key);
            }
        }

        for (auto it = ValOpsT::objValBegin(objVal); it != ValOpsT::objValEnd(objVal); ++it) {
            auto& key = ValOpsT::objValItKey(it);
            auto& propVal = ValOpsT::objValItVal(it);
            const auto keyPropReqPairIt = _mPropReqs.find(key);

            if (keyPropReqPairIt == _mPropReqs.end()) {
                /* No property requirement found */
                if (_mAllowUnknownProps) {
                    continue;
                } else {
                    BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_THROW_SPEC(
                        this->_logger(), Error, this->_loc(propVal), "Unknown {} {} `{}`.",
                        objValTypeStr, ValOpsT::objValPropName, key);
                }
            }

            try {
                keyPropReqPairIt->second.validate(propVal);
            } catch (const Error&) {
                BT_CPPLOGE_TEXT_LOC_APPEND_CAUSE_AND_RETHROW_SPEC(
                    this->_logger(), this->_loc(propVal), "Invalid {} {} `{}`.", objValTypeStr,
                    ValOpsT::objValPropName, key);
            }
        }
    }

private:
    PropReqs _mPropReqs;
    bool _mAllowUnknownProps;
};

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_VAL_REQ_HPP */
