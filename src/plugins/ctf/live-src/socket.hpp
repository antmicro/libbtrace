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
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>

#include "cpp-common/bt2c/logging.hpp"

#include "plugins/ctf/common/src/item-seq/medium.hpp"

/*
 * Thread-safe byte queue that buffers incoming socket data and serves
 * it to readers on demand, throwing TryAgain when insufficient data is available.
 */
class CtfLiveSocketFifo
{
public:
    CtfLiveSocketFifo();

    ctf::src::Buf next(unsigned long offset, unsigned long count);
    void push(bt2s::span<uint8_t>);

private:
    void _waitForData();

    std::mutex _mMutex;
    // Used for notification from socket thread to readers.
    std::condition_variable _mCv;
    std::deque<uint8_t> _mByteQueue;
    unsigned long _mCurrentOffset;
    std::vector<uint8_t> _mCurrentBuf;
    bt2c::Logger _mLogger;
};

class CtfLiveSocketMedium;

/*
 * TCP server that accepts a single client connection on a local port and
 * streams incoming data to registered medium instances.
 */
class CtfLiveSocketServer
{
public:
    CtfLiveSocketServer(int port);
    ~CtfLiveSocketServer();

    std::unique_ptr<CtfLiveSocketMedium> create_medium();

private:
    static constexpr int MAX_CONNECTIONS = 1;
    static constexpr int INCOMING_BUF_SIZE = 4096;
    using sock_type_t = int;

    void _clientLoop();
    void _socketServerLoop();
    void _pushData(bt2s::span<uint8_t>);
    std::atomic<bool> _mKeepRunning;
    std::thread _mSocketThread;
    sock_type_t _mSocketFd;
    sock_type_t _mClientFd;
    std::array<uint8_t, INCOMING_BUF_SIZE> _mReadBuf;
    bt2c::Logger _mLogger;
    std::vector<std::unique_ptr<CtfLiveSocketFifo>> _mFifos;
};

/*
 * Adapter that bridges a socket server's FIFO to the CTF source Medium interface,
 * providing byte-offset-based reads to the live CTF plugin.
 */
class CtfLiveSocketMedium : public ctf::src::Medium
{
public:
    CtfLiveSocketMedium(CtfLiveSocketServer *, CtfLiveSocketFifo *);
    ~CtfLiveSocketMedium() override;

    // Buf may only be ever called from a single thread.
    ctf::src::Buf buf(bt2c::DataLen offset, bt2c::DataLen minSize) override;

private:
    CtfLiveSocketServer *_mServer;
    CtfLiveSocketFifo *_mFifo;
    bt2c::Logger _mLogger;
};

#endif
