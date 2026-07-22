/*
 * Copyright (c) 2022 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef BABELTRACE_CPP_COMMON_BT2C_EXC_HPP
#define BABELTRACE_CPP_COMMON_BT2C_EXC_HPP

#include <exception>
#include <new>
#include <stdexcept>
#include <string>

namespace bt2c {

/*
 * End of iteration.
 */
class End : public std::exception
{
public:
    explicit End() noexcept : std::exception {}
    {
    }
};

/*
 * General error.
 */
class Error : public std::runtime_error
{
public:
    explicit Error(std::string msg = "Error") : std::runtime_error {std::move(msg)}
    {
    }
};

/*
 * Overflow error.
 */
class OverflowError : public Error
{
public:
    explicit OverflowError() noexcept : Error {"Overflow error"}
    {
    }
};

/*
 * AddressInUse socket error.
 */
class AddressInUseSocketError : public Error
{
public:
    explicit AddressInUseSocketError() noexcept : Error {"AddressInUse socket error"}
    {
    }
};

/*
 * Memory error.
 */
class MemoryError : public std::bad_alloc
{
public:
    explicit MemoryError() noexcept : std::bad_alloc {}
    {
    }
};

/*
 * Not available right now: try again later.
 */
class TryAgain : public std::exception
{
public:
    explicit TryAgain() noexcept : std::exception {}
    {
    }
};

/*
 * No such file or directory.
 */
class NoSuchFileOrDirectoryError : public Error
{
public:
    explicit NoSuchFileOrDirectoryError() noexcept : Error {"No such file or directory"}
    {
    }
};

} /* namespace bt2c */

#endif /* BABELTRACE_CPP_COMMON_BT2C_EXC_HPP */
