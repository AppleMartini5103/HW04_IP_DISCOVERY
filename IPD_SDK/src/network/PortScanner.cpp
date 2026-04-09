#include "PortScanner.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#endif

bool port_check_tcp(const std::string& ip, uint16_t port, int timeout_ms) {
    if (port == 0) return false;

#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int cr = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    bool is_open = false;

#ifdef _WIN32
    if (cr == 0) {
        is_open = true;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
    if (cr == 0) {
        is_open = true;
    } else if (errno == EINPROGRESS) {
#endif
        fd_set writefds, errfds;
        FD_ZERO(&writefds);
        FD_ZERO(&errfds);
        FD_SET(sock, &writefds);
        FD_SET(sock, &errfds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int ret = select(static_cast<int>(sock) + 1, nullptr, &writefds, &errfds, &tv);
        if (ret > 0 && FD_ISSET(sock, &writefds) && !FD_ISSET(sock, &errfds)) {
            int err = 0;
#ifdef _WIN32
            int errlen = sizeof(err);
#else
            socklen_t errlen = sizeof(err);
#endif
            getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
            is_open = (err == 0);
        }
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    return is_open;
}
