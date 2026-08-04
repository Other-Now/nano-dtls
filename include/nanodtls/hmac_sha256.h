#ifndef NANODTLS_HMAC_SHA256_H
#define NANODTLS_HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC-SHA256 (RFC 2104). One-shot only -- every nano-dtls use site (HKDF)
 * calls this per block, so there's no need for a streaming variant yet. */
void nd_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                     uint8_t out[ND_SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_HMAC_SHA256_H */
