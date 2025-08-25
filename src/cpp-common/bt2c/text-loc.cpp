/*
 * Copyright (c) 2016-2022 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "text-loc.hpp"

namespace bt2c {

TextLoc::TextLoc(const unsigned long long offset, const unsigned long long lineNo,
                 const unsigned long long colNo) noexcept :
    _mOffset {offset}, _mLineNo {lineNo}, _mColNo {colNo}
{
}

} /* namespace bt2c */
