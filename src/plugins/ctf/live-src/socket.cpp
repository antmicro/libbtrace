#include <memory>
#include <mutex>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "cpp-common/bt2/exc.hpp"
#include "cpp-common/bt2c/data-len.hpp"
#include "cpp-common/bt2c/exc.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/bt2s/make-unique.hpp"

#include "plugins/ctf/common/src/item-seq/medium.hpp"
#include "socket.hpp"

static std::string sockaddr_to_string(const sockaddr_in& addr)
{
    char buf[INET6_ADDRSTRLEN];
    auto *p = inet_ntop(addr.sin_family, &addr.sin_addr, buf, sizeof(buf));
    if (!p) {
        return std::string {"<invalid>"};
    }
    return std::string {p} + ":" + std::to_string(addr.sin_port);
}

CtfLiveSocketServer::CtfLiveSocketServer() :
    _mLogger("SOCKET", "PLUGIN/CTF/LIVE", bt2c::Logger::Level::Info)
{
    _mSocketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (_mSocketFd == -1) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "socket() call failed: ret={}", _mSocketFd);
    }

    sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(42674); // TODO: Configure from params in live-src
    memset(server.sin_zero, '\0', sizeof(server.sin_zero));
    auto err = bind(_mSocketFd, reinterpret_cast<sockaddr *>(&server), sizeof(server));
    if (err != 0) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "bind() failed: ret={}", err);
    }
    err = listen(_mSocketFd, MAX_CONNECTIONS);
    if (err != 0) {
        BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "listen() failed: ret={}", err);
    }

    _mSocketThread = std::thread([this] {
        this->_socketServerLoop();
    });
}

CtfLiveSocketServer::~CtfLiveSocketServer()
{
    BT_CPPLOGD("Cleaning up socket server={}", fmt::ptr(this));
    if (_mClientFd > 0) {
        shutdown(_mClientFd, SHUT_RDWR);
        close(_mClientFd);
    }
    if (_mSocketFd > 0) {
        close(_mSocketFd);
    }
    if (_mSocketThread.joinable()) {
        _mSocketThread.join();
    }
}

void CtfLiveSocketServer::_socketServerLoop()
{
    while (true) {
        sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);

        BT_CPPLOGD("Awaiting client connection");
        _mClientFd =
            accept(_mSocketFd, reinterpret_cast<sockaddr *>(&client_addr), &client_addr_size);
        if (_mClientFd < 0) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "accept() failed: ret={}", _mClientFd);
        }

        const auto cleanup = [this] {
            shutdown(_mClientFd, SHUT_RDWR);
            close(_mClientFd);
        };

        BT_CPPLOGI("Client connected ({}:{})", sockaddr_to_string(client_addr),
                   client_addr.sin_port);
        try {
            _clientLoop();
        } catch (const bt2c::Error&) {
            cleanup();
            BT_CPPLOGE_APPEND_CAUSE_AND_RETHROW("Error while reading data from client");
        }
        BT_CPPLOGD("Client disconnected");
        cleanup();
    }
}

void CtfLiveSocketServer::_clientLoop()
{
    while (true) {
        const auto n = recv(_mClientFd, _mReadBuf.data(), 1, 0);
        if (n == -1) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "recv() failed: ret={}", errno);
        }
        if (n == 0) {
            break;
        }
        _pushData(bt2s::span<uint8_t> {_mReadBuf.data(), (size_t) n});
    }
}

void CtfLiveSocketServer::_pushData(bt2s::span<uint8_t> buf)
{
    // BT_CPPLOGD("Pushing data to attached FIFOs: len={}", buf.size());
    for (auto& fifo : _mFifos) {
        fifo->push(buf);
    }
}

std::unique_ptr<CtfLiveSocketMedium> CtfLiveSocketServer::create_medium()
{
    auto fifo = bt2s::make_unique<CtfLiveSocketFifo>();
    auto *ptr = fifo.get();
    _mFifos.emplace_back(std::move(fifo));

    // The medium receives an unowned pointer, ownership of the fifo belongs to
    // the server.
    auto medium = bt2s::make_unique<CtfLiveSocketMedium>(this, ptr);
    BT_CPPLOGD("Created new medium for socket server: medium={}", fmt::ptr(medium.get()));
    return medium;
}

CtfLiveSocketMedium::CtfLiveSocketMedium(CtfLiveSocketServer *server, CtfLiveSocketFifo *fifo) :
    _mServer(server), _mFifo(fifo),
    _mLogger("MEDIUM", "PLUGIN/CTF/LIVE", bt2c::Logger::Level::Info)
{
}

CtfLiveSocketMedium::~CtfLiveSocketMedium()
{
    BT_CPPLOGD("Cleaning up socket medium={}", fmt::ptr(this));
}

ctf::src::Buf CtfLiveSocketMedium::buf(bt2c::DataLen offset, bt2c::DataLen minSize)
{
    // The medium only gets asked about whole byte offsets and min sizes.
    BT_ASSERT_DBG(offset.extraBitCount() == 0);
    BT_ASSERT_DBG(minSize.extraBitCount() == 0);
    BT_ASSERT_DBG(minSize.extraBitCount() == 0);
    BT_ASSERT_DBG(_mFifo);
    BT_CPPLOGD("buf(): offset={} minSize={}", offset.bytes(), minSize.bytes());
    return _mFifo->next(offset.bytes(), minSize.bytes());
}

CtfLiveSocketFifo::CtfLiveSocketFifo() :
    _mMutex(), _mCv(), _mByteQueue(), _mCurrentOffset(0), _mCurrentBuf(),
    _mLogger("FIFO", "PLUGIN/CTF/LIVE", bt2c::Logger::Level::Info)
{
}

static std::string span_to_hexdump(bt2s::span<uint8_t> buf)
{
    std::string str;
    str.reserve(buf.size() * 2);
    for (auto i = 0; i < buf.size(); ++i) {
        str += fmt::format("{:02x}", buf[i]);
    }
    return str;
}

ctf::src::Buf CtfLiveSocketFifo::next(unsigned long offset, unsigned long count)
{
    if (offset != _mCurrentOffset) {
        BT_ASSERT(offset >= _mCurrentOffset);
        {
            std::unique_lock<std::mutex> lk(_mMutex);
            const auto bytes_to_drop = offset - _mCurrentOffset;
            for (auto i = 0; i < bytes_to_drop; ++i) {
                _mByteQueue.pop_front();
            }
            _mCurrentOffset = offset;
        }
        BT_CPPLOGD("Advance to offset={}", offset);
    }

    std::unique_lock<std::mutex> lk(_mMutex);
    // If there's not enough data, return an empty buffer.
    if (_mByteQueue.size() < count) {
        BT_CPPLOGD("FIXME Not enough data this should probably block?");
        _mCv.wait(lk);
        throw bt2c::TryAgain();
    }
    // Resize the temp buffer if we need more space for the request.
    if (_mCurrentBuf.size() < count) {
        _mCurrentBuf.resize(count);
    }
    // Copy data to a temporary buffer. The data will persist until the next
    // call to next().
    for (auto i = 0; i < count; ++i) {
        _mCurrentBuf[i] = _mByteQueue[i];
    }
    BT_CPPLOGD("FIFO={} returning data len={}", fmt::ptr(this), count);
    BT_CPPLOGD("Data={}", span_to_hexdump(bt2s::span<uint8_t>(_mCurrentBuf.data(), count)));
    return ctf::src::Buf(_mCurrentBuf.data(), bt2c::DataLen::fromBytes(count));
}

void CtfLiveSocketFifo::push(bt2s::span<uint8_t> data)
{
    {
        std::lock_guard<std::mutex> lg {_mMutex};
        for (auto b : data) {
            _mByteQueue.push_back(b);
        }
    }
    _mCv.notify_one();
}

void CtfLiveSocketFifo::_waitForData()
{
    std::unique_lock<std::mutex> lk(_mMutex);
    _mCv.wait(lk);
}
