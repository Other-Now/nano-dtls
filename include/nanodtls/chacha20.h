#ifndef NANODTLS_CHACHA20_H
#define NANODTLS_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ND_CHACHA20_KEY_LEN 32u
#define ND_CHACHA20_NONCE_LEN 12u
#define ND_CHACHA20_BLOCK_LEN 64u

/* Generates one 64-byte keystream block (RFC 8439 section 2.3) for the given
 * 256-bit key, 96-bit nonce, and 32-bit block counter. */
void nd_chacha20_block(const uint8_t key[ND_CHACHA20_KEY_LEN],
                        const uint8_t nonce[ND_CHACHA20_NONCE_LEN], uint32_t counter,
                        uint8_t out[ND_CHACHA20_BLOCK_LEN]);

/* XORs len bytes of `in` with the ChaCha20 keystream starting at
 * initial_counter, writing to `out` (may alias `in` for in-place use). */
nd_status nd_chacha20_xor(const uint8_t key[ND_CHACHA20_KEY_LEN],
                           const uint8_t nonce[ND_CHACHA20_NONCE_LEN], uint32_t initial_counter,
                           const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_CHACHA20_H */
