/* ChaCha20 per RFC 8439 section 2.3-2.4. Portable C11, no SIMD -- vectorized
 * paths are a Stage 6 optimization. */
#include "nanodtls/chacha20.h"

#include <string.h>

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define QR(a, b, c, d)                  \
    do {                                 \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d, 8);  \
        c += d; b ^= c; b = rotl32(b, 7);  \
    } while (0)

void nd_chacha20_block(const uint8_t key[ND_CHACHA20_KEY_LEN],
                        const uint8_t nonce[ND_CHACHA20_NONCE_LEN], uint32_t counter,
                        uint8_t out[ND_CHACHA20_BLOCK_LEN]) {
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) s[4 + i] = load_le32(key + i * 4);
    s[12] = counter;
    for (int i = 0; i < 3; ++i) s[13 + i] = load_le32(nonce + i * 4);

    uint32_t x[16];
    memcpy(x, s, sizeof(x));

    for (int round = 0; round < 10; ++round) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }

    for (int i = 0; i < 16; ++i) store_le32(out + i * 4, x[i] + s[i]);
}

nd_status nd_chacha20_xor(const uint8_t key[ND_CHACHA20_KEY_LEN],
                           const uint8_t nonce[ND_CHACHA20_NONCE_LEN], uint32_t initial_counter,
                           const uint8_t *in, uint8_t *out, size_t len) {
    if (!key || !nonce || (len > 0 && (!in || !out))) return ND_ERR_BAD_ARG;

    uint8_t block[ND_CHACHA20_BLOCK_LEN];
    uint32_t counter = initial_counter;
    size_t off = 0;
    while (off < len) {
        nd_chacha20_block(key, nonce, counter, block);
        size_t take = len - off;
        if (take > ND_CHACHA20_BLOCK_LEN) take = ND_CHACHA20_BLOCK_LEN;
        for (size_t i = 0; i < take; ++i) out[off + i] = (uint8_t)(in[off + i] ^ block[i]);
        off += take;
        ++counter;
    }
    return ND_OK;
}
