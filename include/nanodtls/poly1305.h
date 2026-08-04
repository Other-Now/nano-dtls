#ifndef NANODTLS_POLY1305_H
#define NANODTLS_POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ND_POLY1305_KEY_LEN 32u
#define ND_POLY1305_TAG_LEN 16u

/* Streaming Poly1305 (RFC 8439 section 2.5), radix-2^26 internally. Used by
 * the AEAD layer to MAC AAD + ciphertext without a combined buffer -- the
 * whole point on a zero-alloc/embedded path where records can be larger
 * than is comfortable to duplicate on the stack. `key` is single-use: never
 * call nd_poly1305_init() twice with the same key for two different
 * messages. */
typedef struct nd_poly1305_ctx {
    uint32_t r[5];
    uint32_t s[4];
    uint32_t h[5];
    uint8_t pad[16];
    uint8_t buf[16];
    size_t buf_len;
} nd_poly1305_ctx;

void nd_poly1305_init(nd_poly1305_ctx *ctx, const uint8_t key[ND_POLY1305_KEY_LEN]);
void nd_poly1305_update(nd_poly1305_ctx *ctx, const uint8_t *data, size_t len);
void nd_poly1305_final(nd_poly1305_ctx *ctx, uint8_t out_tag[ND_POLY1305_TAG_LEN]);

/* One-shot convenience wrapper over a single contiguous message. */
void nd_poly1305_mac(const uint8_t key[ND_POLY1305_KEY_LEN], const uint8_t *msg, size_t msg_len,
                      uint8_t out_tag[ND_POLY1305_TAG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_POLY1305_H */
