#include <memory>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "cpp-common/bt2/exc.hpp"
#include "cpp-common/bt2c/logging.hpp"

#include "socket.hpp"

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
    server.sin_port = htons(42674);
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
        const int client_fd =
            accept(_mSocketFd, reinterpret_cast<sockaddr *>(&client_addr), &client_addr_size);
        if (client_fd < 0) {
            BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "accept() failed: ret={}", client_fd);
        }

        BT_CPPLOGD("Connected to client");
        while (true) {
            const auto n = recv(client_fd, _mReadBuf.data(), 1, 0);
            if (n == -1) {
                BT_CPPLOGE_APPEND_CAUSE_AND_THROW(bt2c::Error, "recv() failed: ret={}", errno);
            }
            if (n == 0) {
                BT_CPPLOGD("Client disconnected");
                shutdown(client_fd, SHUT_RDWR);
                close(client_fd);
                break;
            }
            for (size_t i = 0; i < n; ++i) {
                std::fprintf(stderr, "%02x", _mReadBuf[i]);
            }
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
