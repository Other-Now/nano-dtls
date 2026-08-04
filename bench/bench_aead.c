/* ns/op micro-benchmark for AEAD_CHACHA20_POLY1305 encrypt/decrypt at a
 * representative DTLS record payload size. Still a zero baseline: the
 * OpenSSL/mbedTLS side-by-side comparison the README promises is Stage 6,
 * once the record layer (Stage 4) actually drives real traffic through
 * this AEAD end to end. */
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "nanodtls/aead.h"

#define ITERATIONS 200000
#define PAYLOAD_LEN 1200 /* a representative sub-MTU DTLS record fragment */

static double now_ns(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

int main(void) {
    uint8_t key[ND_AEAD_KEY_LEN];
    uint8_t nonce[ND_AEAD_NONCE_LEN];
    uint8_t aad[13]; /* a DTLSPlaintext-header-sized AAD, for realism */
    uint8_t plaintext[PAYLOAD_LEN];
    uint8_t ciphertext[PAYLOAD_LEN];
    uint8_t decrypted[PAYLOAD_LEN];
    uint8_t tag[ND_AEAD_TAG_LEN];

    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(i * 7);
    for (size_t i = 0; i < sizeof(aad); ++i) aad[i] = (uint8_t)(i * 3);
    for (size_t i = 0; i < PAYLOAD_LEN; ++i) plaintext[i] = (uint8_t)(i * 13);

    volatile uint64_t sink = 0;

    double t0 = now_ns();
    for (int i = 0; i < ITERATIONS; ++i) {
        nd_aead_chacha20poly1305_encrypt(key, nonce, aad, sizeof(aad), plaintext, PAYLOAD_LEN,
                                          ciphertext, tag);
        sink += tag[0];
    }
    double t1 = now_ns();
    double encrypt_ns_per_op = (t1 - t0) / ITERATIONS;

    t0 = now_ns();
    for (int i = 0; i < ITERATIONS; ++i) {
        nd_aead_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad), ciphertext, PAYLOAD_LEN,
                                          tag, decrypted);
        sink += decrypted[0];
    }
    t1 = now_ns();
    double decrypt_ns_per_op = (t1 - t0) / ITERATIONS;

    printf("AEAD_CHACHA20_POLY1305 encrypt: %.1f ns/op (%.2f MB/s), %d-byte payload\n",
           encrypt_ns_per_op, (PAYLOAD_LEN / (encrypt_ns_per_op * 1e-9)) / (1024.0 * 1024.0),
           PAYLOAD_LEN);
    printf("AEAD_CHACHA20_POLY1305 decrypt: %.1f ns/op (%.2f MB/s), %d-byte payload\n",
           decrypt_ns_per_op, (PAYLOAD_LEN / (decrypt_ns_per_op * 1e-9)) / (1024.0 * 1024.0),
           PAYLOAD_LEN);
    printf("(sink=%llu)\n", (unsigned long long)sink);
    return 0;
}
