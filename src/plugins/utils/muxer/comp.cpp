/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2023 Philippe Proulx <pproulx@efficios.com>
 */

#include "cpp-common/vendor/fmt/core.h"

#include "comp.hpp"

namespace bt2mux {

Comp::Comp(const bt2::SelfFilterComponent selfComp, const bt2::ConstMapValue params, void *) :
    bt2::UserFilterComponent<Comp, MsgIter> {selfComp, "PLUGIN/FLT.UTILS.MUXER"}
{
    BT_CPPLOGI("Initializing component.");

    this->live_mode = false;
    /* Either parameters expected, or live mode gets passed and decoded */
    if (params.hasEntry("live")) {
        live_mode = bool(params["live"]);
    } else if (!params.isEmpty()) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(
            bt2c::Error,
            "This component expects no parameters, or just the 'live' parameter: param-count={}",
            params.length());
    }

    /* Add initial available input port */
    this->_addAvailInputPort();

    /* Add single output port */
    try {
        this->_addOutputPort("out");
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("Failed to add a single output port.");
    }

    BT_CPPLOGI("Initialized component.");
}

void Comp::_getSupportedMipVersions(bt2::SelfComponentClass, bt2::ConstValue, bt2::LoggingLevel,
                                    const bt2::UnsignedIntegerRangeSet ranges)
{
    ranges.addRange(0, 1);
}

void Comp::_inputPortConnected(const bt2::SelfComponentInputPort, const bt2::ConstOutputPort)
{
    this->_addAvailInputPort();
}

void Comp::_addAvailInputPort()
{
    try {
        this->_addInputPort(fmt::format("in{}", this->_inputPorts().length()));
    } catch (const bt2c::Error&) {
        BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("Failed to add an available input port.");
    }

    BT_CPPLOGI("Added one available input port: name={}", this->_inputPorts().back().name());
}

} /* namespace bt2mux */
