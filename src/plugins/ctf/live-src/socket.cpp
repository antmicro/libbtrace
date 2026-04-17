#include <memory>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "cpp-common/bt2/exc.hpp"
#include "cpp-common/bt2c/exc.hpp"
#include "cpp-common/bt2c/logging.hpp"

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
    _mLogger("SOCKET", "PLUGIN/CTF/LIVE", bt2c::Logger::Level::Debug)
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
        for (size_t i = 0; i < n; ++i) {
            std::fprintf(stderr, "%02x", _mReadBuf[i]);
        }
    }
}

std::unique_ptr<CtfLiveSocketMedium> CtfLiveSocketServer::create_medium()
{
    return {};
}

CtfLiveSocketMedium::CtfLiveSocketMedium()
{
}

CtfLiveSocketMedium::~CtfLiveSocketMedium()
{
}

ctf::src::Buf CtfLiveSocketMedium::buf(bt2c::DataLen offset, bt2c::DataLen minSize)
{
    return ctf::src::Buf();
}
