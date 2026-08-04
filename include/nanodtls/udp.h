#ifndef NANODTLS_UDP_H
#define NANODTLS_UDP_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * A minimal cross-platform (Winsock / BSD sockets) UDP transport -- enough
 * to move DTLS datagrams for the Stage 3 handshake state machine and the
 * OpenSSL/self interop tests. Not a general sockets library: one socket
 * moves datagrams for exactly one peer (a real server fielding many
 * clients needs one nd_udp_socket per peer after nd_udp_server_accept_peer,
 * same shape as a trivial single-client demo server -- extending to a
 * multiplexed multi-client server is a straightforward but unbuilt
 * extension, not attempted here).
 * --------------------------------------------------------------------- */

#if defined(_WIN32)
typedef uintptr_t nd_udp_fd; /* SOCKET, without pulling <winsock2.h> into every includer */
#else
typedef int nd_udp_fd;
#endif

typedef struct nd_udp_socket {
    nd_udp_fd fd;
} nd_udp_socket;

/* Must be called once before any other nd_udp_* function (WSAStartup on
 * Windows; a no-op returning ND_OK on POSIX). nd_udp_global_cleanup() undoes
 * it (WSACleanup); call after all sockets are closed. */
nd_status nd_udp_global_init(void);
void nd_udp_global_cleanup(void);

/* Client role: opens a UDP socket and "connects" it to host:port (the usual
 * connected-UDP-socket trick -- send()/recv() without repeating the
 * address, and the OS filters out datagrams from anyone else). host must be
 * a numeric IPv4/IPv6 address or "localhost"; no DNS resolution beyond what
 * getaddrinfo does synchronously. */
nd_status nd_udp_client_connect(nd_udp_socket *sock, const char *host, uint16_t port);

/* Server role, part 1: binds to 0.0.0.0:port (IPv4 only -- see udp.c for
 * why: a dual-stack IPv6 wildcard bind is deaf to 127.0.0.1 traffic on
 * Windows by default). */
nd_status nd_udp_server_bind(nd_udp_socket *sock, uint16_t port);
/* Server role, part 2: blocks (up to timeout_ms -- same -1/0/positive
 * semantics as nd_udp_recv) for the first inbound datagram, copies its
 * payload into buf, and "connects" sock to that datagram's source address
 * -- from here on this socket behaves like a client socket scoped to that
 * one peer (send()/recv() need no address). This is the same "connect a UDP
 * socket to the first peer that writes to you" pattern many minimal UDP
 * servers use; it does not handle a second peer showing up mid-session. */
nd_status nd_udp_server_accept_peer(nd_udp_socket *sock, uint8_t *buf, size_t buf_cap, size_t *out_len,
                                     int timeout_ms);

nd_status nd_udp_send(nd_udp_socket *sock, const uint8_t *data, size_t len);
/* timeout_ms < 0 blocks indefinitely; 0 polls (returns ND_ERR_TRUNCATED
 * immediately if nothing is pending -- reusing that code for "no data
 * available" rather than adding a new status just for this). */
nd_status nd_udp_recv(nd_udp_socket *sock, uint8_t *buf, size_t buf_cap, size_t *out_len, int timeout_ms);

void nd_udp_close(nd_udp_socket *sock);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_UDP_H */
