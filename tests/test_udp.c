/* Real loopback socket I/O -- not a mock. Single-process: the client's
 * send() hands the datagram to the kernel and returns immediately (UDP is
 * connectionless, no handshake to wait for), so by the time the "server"
 * calls recv the datagram is already queued -- no actual thread or
 * artificial synchronization needed for this ordering to be reliable. */
#include "nanodtls/udp.h"

#include "test_util.h"

static void test_client_server_roundtrip(void) {
    CHECK(nd_udp_global_init() == ND_OK);

    nd_udp_socket server;
    CHECK(nd_udp_server_bind(&server, 41237) == ND_OK);

    nd_udp_socket client;
    CHECK(nd_udp_client_connect(&client, "127.0.0.1", 41237) == ND_OK);

    const uint8_t ping[] = "nano-dtls udp transport ping";
    CHECK(nd_udp_send(&client, ping, sizeof(ping)) == ND_OK);

    uint8_t recv_buf[128];
    size_t recv_len = 0;
    CHECK(nd_udp_server_accept_peer(&server, recv_buf, sizeof(recv_buf), &recv_len, 2000) == ND_OK);
    CHECK(recv_len == sizeof(ping));
    CHECK(nd_bytes_eq(recv_buf, ping, sizeof(ping)));

    /* server is now "connected" to the client's ephemeral port -- reply
     * with plain send()/recv(), no addresses needed either direction. */
    const uint8_t pong[] = "pong";
    CHECK(nd_udp_send(&server, pong, sizeof(pong)) == ND_OK);

    uint8_t reply_buf[16];
    size_t reply_len = 0;
    CHECK(nd_udp_recv(&client, reply_buf, sizeof(reply_buf), &reply_len, 2000) == ND_OK);
    CHECK(reply_len == sizeof(pong));
    CHECK(nd_bytes_eq(reply_buf, pong, sizeof(pong)));

    nd_udp_close(&client);
    nd_udp_close(&server);
    nd_udp_global_cleanup();
}

static void test_recv_timeout_on_silence(void) {
    CHECK(nd_udp_global_init() == ND_OK);

    nd_udp_socket server;
    CHECK(nd_udp_server_bind(&server, 41238) == ND_OK);
    nd_udp_socket client;
    CHECK(nd_udp_client_connect(&client, "127.0.0.1", 41238) == ND_OK);

    /* Nobody ever sends the server anything -- recv must time out cleanly
     * (an error status, not a hang) rather than block the test forever. */
    uint8_t buf[16];
    size_t len = 0;
    CHECK(nd_udp_recv(&server, buf, sizeof(buf), &len, 200) != ND_OK);

    nd_udp_close(&client);
    nd_udp_close(&server);
    nd_udp_global_cleanup();
}

int main(void) {
    test_client_server_roundtrip();
    test_recv_timeout_on_silence();
    return nd_test_summary("test_udp");
}
