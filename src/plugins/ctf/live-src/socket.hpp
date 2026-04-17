/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Antmicro
 * Copyright (C) 2026 Analog Devices
 *
 */
#ifndef BABELTRACE_PLUGINS_CTF_LIVE_SRC_SOCKET_HPP
#define BABELTRACE_PLUGINS_CTF_LIVE_SRC_SOCKET_HPP

#include <array>
#include <thread>

#include "cpp-common/bt2c/logging.hpp"

#include "plugins/ctf/common/src/item-seq/medium.hpp"

class CtfLiveSocketMedium;

class CtfLiveSocketServer
{
public:
    CtfLiveSocketServer();
    ~CtfLiveSocketServer();

    std::unique_ptr<CtfLiveSocketMedium> create_medium();

private:
    static constexpr int MAX_CONNECTIONS = 1;
    static constexpr int INCOMING_BUF_SIZE = 4096;
    using sock_type_t = int;

    void _clientLoop();
    void _socketServerLoop();
    std::thread _mSocketThread;
    sock_type_t _mSocketFd;
    sock_type_t _mClientFd;
    std::array<uint8_t, INCOMING_BUF_SIZE> _mReadBuf;
    bt2c::Logger _mLogger;
};

class CtfLiveSocketMedium : public ctf::src::Medium
{
public:
    CtfLiveSocketMedium();
    ~CtfLiveSocketMedium() override;

    ctf::src::Buf buf(bt2c::DataLen offset, bt2c::DataLen minSize) override;

private:
    CtfLiveSocketServer *_mServer;
};

#endif
