#include "nanodtls/hmac_sha256.h"

#include <string.h>

void nd_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                     uint8_t out[ND_SHA256_DIGEST_LEN]) {
    uint8_t key_block[ND_SHA256_BLOCK_LEN];
    memset(key_block, 0, sizeof(key_block));
    if (key_len > ND_SHA256_BLOCK_LEN) {
        nd_sha256(key, key_len, key_block); /* fills the first 32 bytes; rest stays zero */
    } else {
        memcpy(key_block, key, key_len);
    }

    uint8_t ipad[ND_SHA256_BLOCK_LEN];
    uint8_t opad[ND_SHA256_BLOCK_LEN];
    for (size_t i = 0; i < ND_SHA256_BLOCK_LEN; ++i) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5c);
    }

    uint8_t inner[ND_SHA256_DIGEST_LEN];
    nd_sha256_ctx ctx;
    nd_sha256_init(&ctx);
    nd_sha256_update(&ctx, ipad, sizeof(ipad));
    nd_sha256_update(&ctx, data, data_len);
    nd_sha256_final(&ctx, inner);

    nd_sha256_init(&ctx);
    nd_sha256_update(&ctx, opad, sizeof(opad));
    nd_sha256_update(&ctx, inner, sizeof(inner));
    nd_sha256_final(&ctx, out);
}
