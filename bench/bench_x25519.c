/* ns/op micro-benchmark for X25519 scalar multiplication -- the expensive
 * per-handshake public-key operation (one nd_x25519_base() to generate a
 * key share, one nd_x25519_scalarmult() against the peer's share to get
 * the premaster secret). No OpenSSL comparison yet, same honest-baseline
 * framing as the other benchmarks in this repo: that lands in Stage 6. */
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "nanodtls/x25519.h"

#define ITERATIONS 2000

static double now_ns(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

int main(void) {
    uint8_t scalar[ND_X25519_LEN];
    uint8_t peer_pub[ND_X25519_LEN];
    uint8_t out[ND_X25519_LEN];
    for (size_t i = 0; i < ND_X25519_LEN; ++i) scalar[i] = (uint8_t)(i * 17 + 1);
    for (size_t i = 0; i < ND_X25519_LEN; ++i) peer_pub[i] = (uint8_t)(i * 31 + 2);

    volatile uint8_t sink = 0;

    double t0 = now_ns();
    for (int i = 0; i < ITERATIONS; ++i) {
        nd_x25519_base(scalar, out);
        scalar[0] = out[0]; /* vary the input each round so the compiler can't hoist anything */
        sink ^= out[0];
    }
    double t1 = now_ns();
    printf("nd_x25519_base:        %.0f ns/op (%d iterations)\n", (t1 - t0) / ITERATIONS,
           ITERATIONS);

    t0 = now_ns();
    for (int i = 0; i < ITERATIONS; ++i) {
        nd_x25519_scalarmult(scalar, peer_pub, out);
        scalar[0] = out[0];
        sink ^= out[0];
    }
    t1 = now_ns();
    printf("nd_x25519_scalarmult:  %.0f ns/op (%d iterations)\n", (t1 - t0) / ITERATIONS,
           ITERATIONS);

    printf("(sink=%u)\n", (unsigned)sink);
    return 0;
}
