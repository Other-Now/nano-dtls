/* ns/parse micro-benchmark for the Stage 1 record-header parsers.
 *
 * There's no OpenSSL/mbedTLS comparison here -- that arrives once Stage 2
 * (AEAD + key schedule) gives us something equivalent to compare against.
 * This is the zero baseline: how cheap is decoding the header itself. */
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "nanodtls/record.h"

#define ITERATIONS 2000000

static double now_ns(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static void bench_plaintext(void) {
    uint8_t buf[ND_PLAINTEXT_HDR_LEN + 4] = {
        22, 0xfe, 0xfd, 0, 3, 0, 0, 0, 0, 0, 0x2a, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
    };
    nd_plaintext_hdr hdr;
    const uint8_t *frag;
    size_t frag_len;
    volatile uint64_t sink = 0;

    double t0 = now_ns();
    for (int i = 0; i < ITERATIONS; ++i) {
        nd_plaintext_parse(buf, sizeof(buf), &hdr, &frag, &frag_len);
        sink += hdr.sequence_number;
    }
    double t1 = now_ns();

    printf("plaintext header parse: %.2f ns/op  (%d iterations, sink=%llu)\n",
           (t1 - t0) / ITERATIONS, ITERATIONS, (unsigned long long)sink);
}

static void bench_unified(void) {
    uint8_t buf[] = {0x2D, 0x00, 0x05, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
    nd_unified_hdr hdr;
    const uint8_t *payload;
    size_t payload_len;
    volatile uint64_t sink = 0;

    double t0 = now_ns();
    for (int i = 0; i < ITERATIONS; ++i) {
        nd_unified_parse(buf, sizeof(buf), 0, &hdr, &payload, &payload_len);
        sink += hdr.sequence_number;
    }
    double t1 = now_ns();

    printf("unified header parse:   %.2f ns/op  (%d iterations, sink=%llu)\n",
           (t1 - t0) / ITERATIONS, ITERATIONS, (unsigned long long)sink);
}

int main(void) {
    bench_plaintext();
    bench_unified();
    return 0;
}
