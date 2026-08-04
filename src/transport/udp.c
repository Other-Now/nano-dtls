/* See nanodtls/udp.h for scope. Windows (Winsock2) and POSIX (BSD sockets)
 * behind one #ifdef boundary, kept in a single file since each platform's
 * body is short and the two never build in the same translation unit.
 *
 * ND_SOCK() casts nd_udp_fd (a uintptr_t on Windows, so it's wide enough to
 * hold a real SOCKET handle on 64-bit Windows) to whatever type each
 * platform's socket functions actually expect. Earlier drafts of this file
 * cast socket handles to `int` unconditionally before calling
 * connect()/send()/recv()/etc; on 64-bit Windows a SOCKET is a UINT_PTR, not
 * an int, so that cast silently truncated the handle -- caught before ever
 * running this against a real socket, not left as a "works on POSIX, breaks
 * on Windows" landmine. */
#include "nanodtls/udp.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define ND_SOCK(x) ((SOCKET)(x))
typedef int nd_ssize;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define ND_SOCK(x) ((int)(x))
typedef ssize_t nd_ssize;
#endif

nd_status nd_udp_global_init(void) {
#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return ND_ERR_BAD_ARG;
#endif
    return ND_OK;
}

void nd_udp_global_cleanup(void) {
#if defined(_WIN32)
    WSACleanup();
#endif
}

/* Manual, allocation-free uint16 -> decimal, avoiding a snprintf
 * portability wrinkle (MSVC's is fine, but this keeps the transport layer's
 * dependencies as small as the rest of this repo). out must be >= 6 bytes. */
static void port_to_str(uint16_t port, char *out) {
    char digits[5];
    int n = 0;
    uint16_t v = port;
    if (v == 0) {
        digits[n++] = '0';
    } else {
        while (v) {
            digits[n++] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    for (int i = 0; i < n; ++i) out[i] = digits[n - 1 - i];
    out[n] = '\0';
}

/* AF_INET, not AF_UNSPEC: a dual-stack AF_UNSPEC/wildcard bind picks IPv6
 * (`[::]`) first on both Windows and Linux, and Windows in particular
 * defaults IPV6_V6ONLY to *on* for such sockets -- so an IPv6 wildcard
 * listener never sees traffic addressed to 127.0.0.1 at all. Caught by a
 * real loopback test hanging (the server's recvfrom never woke up) rather
 * than left as a "works on some OS defaults, silently deaf on others"
 * landmine. IPv4-only keeps this minimal transport's behavior identical and
 * predictable across the CI matrix (Linux/macOS/Windows) instead of
 * depending on each platform's dual-stack defaults. */
static nd_status resolve(const char *host, uint16_t port, int passive, struct addrinfo **out_ai) {
    struct addrinfo hints;
    for (size_t i = 0; i < sizeof(hints); ++i) ((uint8_t *)&hints)[i] = 0;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (passive) hints.ai_flags = AI_PASSIVE;

    char port_str[6];
    port_to_str(port, port_str);
    return getaddrinfo(host, port_str, &hints, out_ai) == 0 ? ND_OK : ND_ERR_BAD_ARG;
}

static int fd_is_invalid(nd_udp_fd fd) {
#if defined(_WIN32)
    return ND_SOCK(fd) == INVALID_SOCKET;
#else
    return ND_SOCK(fd) < 0;
#endif
}

static void fd_close(nd_udp_fd fd) {
#if defined(_WIN32)
    closesocket(ND_SOCK(fd));
#else
    close(ND_SOCK(fd));
#endif
}

nd_status nd_udp_client_connect(nd_udp_socket *sock, const char *host, uint16_t port) {
    if (!sock || !host) return ND_ERR_BAD_ARG;
    struct addrinfo *ai = NULL;
    if (resolve(host, port, 0, &ai) != ND_OK) return ND_ERR_BAD_ARG;

    nd_udp_fd fd = (nd_udp_fd)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd_is_invalid(fd)) {
        freeaddrinfo(ai);
        return ND_ERR_BAD_ARG;
    }
    int rc = connect(ND_SOCK(fd), ai->ai_addr, (int)ai->ai_addrlen);
    freeaddrinfo(ai);
    if (rc != 0) {
        fd_close(fd);
        return ND_ERR_BAD_ARG;
    }
    sock->fd = fd;
    return ND_OK;
}

nd_status nd_udp_server_bind(nd_udp_socket *sock, uint16_t port) {
    if (!sock) return ND_ERR_BAD_ARG;

    struct addrinfo *ai = NULL;
    if (resolve(NULL, port, 1 /* AI_PASSIVE: wildcard bind address */, &ai) != ND_OK) return ND_ERR_BAD_ARG;

    nd_udp_fd fd = (nd_udp_fd)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd_is_invalid(fd)) {
        freeaddrinfo(ai);
        return ND_ERR_BAD_ARG;
    }
    int rc = bind(ND_SOCK(fd), ai->ai_addr, (int)ai->ai_addrlen);
    freeaddrinfo(ai);
    if (rc != 0) {
        fd_close(fd);
        return ND_ERR_BAD_ARG;
    }
    sock->fd = fd;
    return ND_OK;
}

nd_status nd_udp_server_accept_peer(nd_udp_socket *sock, uint8_t *buf, size_t buf_cap, size_t *out_len,
                                     int timeout_ms) {
    if (!sock || !buf || !out_len) return ND_ERR_BAD_ARG;

    if (timeout_ms >= 0) {
#if defined(_WIN32)
        DWORD tv = (DWORD)timeout_ms;
        setsockopt(ND_SOCK(sock->fd), SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(ND_SOCK(sock->fd), SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#endif
    }

    struct sockaddr_storage peer;
#if defined(_WIN32)
    int peer_len = (int)sizeof(peer);
#else
    socklen_t peer_len = (socklen_t)sizeof(peer);
#endif
    nd_ssize got = recvfrom(ND_SOCK(sock->fd), (char *)buf, (int)buf_cap, 0, (struct sockaddr *)&peer, &peer_len);
    if (got < 0) return ND_ERR_TRUNCATED;

    if (connect(ND_SOCK(sock->fd), (struct sockaddr *)&peer, peer_len) != 0) return ND_ERR_BAD_ARG;

    *out_len = (size_t)got;
    return ND_OK;
}

nd_status nd_udp_send(nd_udp_socket *sock, const uint8_t *data, size_t len) {
    if (!sock || !data) return ND_ERR_BAD_ARG;
    nd_ssize sent = send(ND_SOCK(sock->fd), (const char *)data, (int)len, 0);
    if (sent < 0 || (size_t)sent != len) return ND_ERR_BAD_LENGTH;
    return ND_OK;
}

nd_status nd_udp_recv(nd_udp_socket *sock, uint8_t *buf, size_t buf_cap, size_t *out_len, int timeout_ms) {
    if (!sock || !buf || !out_len) return ND_ERR_BAD_ARG;

    if (timeout_ms >= 0) {
#if defined(_WIN32)
        DWORD tv = (DWORD)timeout_ms;
        setsockopt(ND_SOCK(sock->fd), SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(ND_SOCK(sock->fd), SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#endif
    }

    nd_ssize got = recv(ND_SOCK(sock->fd), (char *)buf, (int)buf_cap, 0);
    if (got < 0) return ND_ERR_TRUNCATED; /* timeout or error: no datagram delivered */
    *out_len = (size_t)got;
    return ND_OK;
}

void nd_udp_close(nd_udp_socket *sock) {
    if (!sock) return;
    fd_close(sock->fd);
}
