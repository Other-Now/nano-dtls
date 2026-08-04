#ifndef NANODTLS_SHA256_H
#define NANODTLS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ND_SHA256_DIGEST_LEN 32u
#define ND_SHA256_BLOCK_LEN 64u

/* Streaming SHA-256 (FIPS 180-4). No allocation: state lives entirely in
 * this struct, sized for a caller-owned instance (stack or static). */
typedef struct nd_sha256_ctx {
    uint32_t h[8];
    uint64_t total_len; /* bytes processed so far, across all update() calls */
    uint8_t buf[ND_SHA256_BLOCK_LEN];
    size_t buf_len;
} nd_sha256_ctx;

void nd_sha256_init(nd_sha256_ctx *ctx);
void nd_sha256_update(nd_sha256_ctx *ctx, const uint8_t *data, size_t len);
void nd_sha256_final(nd_sha256_ctx *ctx, uint8_t out[ND_SHA256_DIGEST_LEN]);

/* One-shot convenience wrapper. */
void nd_sha256(const uint8_t *data, size_t len, uint8_t out[ND_SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_SHA256_H */
