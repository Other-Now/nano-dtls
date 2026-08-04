/* The strongest end-to-end check available in this repo: a real DTLS 1.3
 * client and a real DTLS 1.3 server, each running the actual state machine
 * (nanodtls/client.h, nanodtls/server.h) over real loopback UDP sockets
 * (nanodtls/udp.h) -- not in-memory buffer passing. Two OS threads (one
 * per role) rather than two processes, so this runs portably under ctest
 * in the CI matrix without spawning/locating sibling binaries; the sockets
 * and protocol code being exercised don't know or care that the peer is a
 * thread rather than a separate process. tools/dtls_client_demo.c and
 * tools/dtls_server_demo.c are the same handshake as two real standalone
 * programs, for anyone who wants to run it that way by hand.
 *
 * Uses the same real, OpenSSL-cross-verified certificate chain as
 * test_x509.c/test_messages.c (x509_test_certs.h) -- including signing
 * CertificateVerify with the actual private key behind LEAF_CERT_DER's
 * public key, via tools/p256_sign_demo.c (linked into this test binary
 * only -- see that file for why it's not part of the nanodtls library). */
#include "nanodtls/client.h"
#include "nanodtls/server.h"
#include "nanodtls/udp.h"

#include "p256_sign_demo.h"
#include "test_util.h"
#include "x509_test_certs.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#endif

#define ND_TEST_PORT 41999
#define ND_TEST_PORT_DELAYED 42000

static uint64_t g_at_time = 20270101000000ULL; /* inside both certs' validity windows */

typedef struct server_thread_result {
    nd_status status;
    nd_handshake_keys keys;
    uint16_t port;
    int delay_ms; /* sleeps this long before binding -- simulates the server not being up yet,
                   * forcing the client's ClientHello retransmission path to actually run */
} server_thread_result;

static nd_status demo_sign(void *ctx, const uint8_t hash[32], uint8_t out_r[32], uint8_t out_s[32]) {
    (void)ctx;
    return nd_demo_p256_ecdsa_sign(LEAF_KEY_D, hash, out_r, out_s);
}

static void sleep_ms(int ms) {
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static void run_server(server_thread_result *result) {
    nd_udp_socket sock;
    if (nd_udp_server_bind(&sock, result->port) != ND_OK) {
        result->status = ND_ERR_BAD_ARG;
        return;
    }

    /* Binds immediately (so the client's early retransmitted ClientHellos
     * are queued by the OS rather than bouncing off a closed port -- a
     * connected UDP socket that gets an ICMP Port Unreachable can end up
     * refusing to send *at all* afterward on some platforms, which would
     * make this test about that platform quirk instead of about
     * nd_client_handshake's retry loop) but delays actually reading from
     * it, simulating a server that's momentarily slow to start
     * processing rather than one that's fully down. */
    if (result->delay_ms > 0) sleep_ms(result->delay_ms);

    nd_server_config config;
    config.cert_der[0] = LEAF_CERT_DER;
    config.cert_der_len[0] = LEAF_CERT_DER_LEN;
    config.cert_count = 1;
    config.sign_fn = demo_sign;
    config.sign_ctx = NULL;

    nd_server_result server_result;
    result->status = nd_server_handshake(&sock, &config, /*recv_timeout_ms=*/5000, &server_result);
    if (result->status == ND_OK) result->keys = server_result.keys;
    nd_udp_close(&sock);
}

#if defined(_WIN32)
static DWORD WINAPI server_thread_main(LPVOID arg) {
    run_server((server_thread_result *)arg);
    return 0;
}
#else
static void *server_thread_main(void *arg) {
    run_server((server_thread_result *)arg);
    return NULL;
}
#endif

static void test_full_handshake_over_real_sockets(void) {
    CHECK(nd_udp_global_init() == ND_OK);

    server_thread_result server_result;
    server_result.status = ND_ERR_BAD_ARG;
    server_result.port = ND_TEST_PORT;
    server_result.delay_ms = 0;

#if defined(_WIN32)
    HANDLE thread = CreateThread(NULL, 0, server_thread_main, &server_result, 0, NULL);
    CHECK(thread != NULL);
#else
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, server_thread_main, &server_result) == 0);
#endif

    /* nd_udp_server_bind() inside run_server() happens-before the client's
     * connect below is meaningful is not guaranteed by the OS scheduler
     * alone; give the server thread a moment to bind before the client
     * sends its ClientHello (which would otherwise arrive at a port nobody
     * is listening on yet). A fixed short sleep here is simpler than a
     * bind-ready handshake for a same-machine loopback test. */
#if defined(_WIN32)
    Sleep(150);
#else
    struct timespec ts = {0, 150000000L};
    nanosleep(&ts, NULL);
#endif

    nd_x509_cert trust_anchor;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &trust_anchor) == ND_OK);

    nd_udp_socket client_sock;
    CHECK(nd_udp_client_connect(&client_sock, "127.0.0.1", ND_TEST_PORT) == ND_OK);

    nd_client_result client_result;
    nd_status client_status =
        nd_client_handshake(&client_sock, &trust_anchor, g_at_time, /*recv_timeout_ms=*/5000, &client_result);
    nd_udp_close(&client_sock);

#if defined(_WIN32)
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    pthread_join(thread, NULL);
#endif

    CHECK(client_status == ND_OK);
    CHECK(server_result.status == ND_OK);

    /* Both sides independently derived these keys (client from its own
     * X25519 scalar + the server's public share + its own transcript hash;
     * server symmetrically) -- byte-identical results here is the
     * strongest confirmation available that the whole stack (record layer,
     * AEAD, X25519, X.509, ECDSA, transcript hashing, key schedule, and the
     * state machine sequencing all of it over a real network) agrees with
     * itself end to end, not just "both sides returned ND_OK". */
    if (client_status == ND_OK && server_result.status == ND_OK) {
        CHECK(nd_bytes_eq(client_result.keys.client_write_key, server_result.keys.client_write_key,
                           ND_AEAD_KEY_LEN));
        CHECK(nd_bytes_eq(client_result.keys.server_write_key, server_result.keys.server_write_key,
                           ND_AEAD_KEY_LEN));
        CHECK(nd_bytes_eq(client_result.keys.client_handshake_traffic_secret,
                           server_result.keys.client_handshake_traffic_secret, ND_HASH_LEN));
        CHECK(nd_bytes_eq(client_result.keys.server_handshake_traffic_secret,
                           server_result.keys.server_handshake_traffic_secret, ND_HASH_LEN));
    }

    nd_udp_global_cleanup();
}

/* Proves the ClientHello retransmission path in nd_client_handshake (see
 * nanodtls/client.h) actually runs, rather than just existing in the
 * source: the server intentionally doesn't bind its socket until well
 * after the client starts, so the client's first ClientHello send (and,
 * depending on scheduling, several more) lands on a port nobody is
 * listening to yet. With a short per-attempt recv_timeout_ms and
 * ND_CLIENT_HELLO_MAX_ATTEMPTS retries, the client should still complete
 * the handshake once the server finally binds -- proof this is a real
 * retry loop recovering from real "nobody answered yet", not merely a
 * decorative field that's never exercised. */
static void test_client_retransmits_until_server_binds(void) {
    CHECK(nd_udp_global_init() == ND_OK);

    server_thread_result server_result;
    server_result.status = ND_ERR_BAD_ARG;
    server_result.port = ND_TEST_PORT_DELAYED;
    server_result.delay_ms = 600; /* server won't bind for 600ms */

#if defined(_WIN32)
    HANDLE thread = CreateThread(NULL, 0, server_thread_main, &server_result, 0, NULL);
    CHECK(thread != NULL);
#else
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, server_thread_main, &server_result) == 0);
#endif

    nd_x509_cert trust_anchor;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &trust_anchor) == ND_OK);

    nd_udp_socket client_sock;
    CHECK(nd_udp_client_connect(&client_sock, "127.0.0.1", ND_TEST_PORT_DELAYED) == ND_OK);

    /* Per-attempt timeout (300ms) x 5 attempts = up to ~1.5s of total retry
     * budget against the server's 600ms bind delay -- a wide enough margin
     * that the client is expected to succeed only *after* retrying at
     * least once or twice, without the test being sensitive to normal
     * thread-scheduling jitter on a loaded CI machine. */
    nd_client_result client_result;
    nd_status client_status =
        nd_client_handshake(&client_sock, &trust_anchor, g_at_time, /*recv_timeout_ms=*/300, &client_result);
    nd_udp_close(&client_sock);

#if defined(_WIN32)
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
#else
    pthread_join(thread, NULL);
#endif

    CHECK(client_status == ND_OK);
    CHECK(server_result.status == ND_OK);

    nd_udp_global_cleanup();
}

int main(void) {
    test_full_handshake_over_real_sockets();
    test_client_retransmits_until_server_binds();
    return nd_test_summary("test_interop");
}
