#ifndef NANODTLS_AEAD_H
#define NANODTLS_AEAD_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ND_AEAD_KEY_LEN 32u
#define ND_AEAD_NONCE_LEN 12u
#define ND_AEAD_TAG_LEN 16u

/* AEAD_CHACHA20_POLY1305 (RFC 8439 section 2.8): nano-dtls's one cipher
 * suite for now. Chosen over AES-128-GCM specifically because ChaCha20 and
 * Poly1305 are naturally constant-time in software -- no S-box table
 * lookups to leak through cache timing -- which matters more here than a
 * hardware-AES fast path would on a target that may not have AES-NI/AES
 * instructions at all (see README). Zero-alloc: no combined buffer, the MAC
 * is fed AAD/ciphertext/lengths through streaming Poly1305. */
nd_status nd_aead_chacha20poly1305_encrypt(const uint8_t key[ND_AEAD_KEY_LEN],
                                            const uint8_t nonce[ND_AEAD_NONCE_LEN],
                                            const uint8_t *aad, size_t aad_len,
                                            const uint8_t *plaintext, size_t plaintext_len,
                                            uint8_t *ciphertext_out,
                                            uint8_t tag_out[ND_AEAD_TAG_LEN]);

/* Verifies the tag before decrypting; on mismatch returns ND_ERR_AUTH_FAILED
 * and does NOT write to plaintext_out. */
nd_status nd_aead_chacha20poly1305_decrypt(const uint8_t key[ND_AEAD_KEY_LEN],
                                            const uint8_t nonce[ND_AEAD_NONCE_LEN],
                                            const uint8_t *aad, size_t aad_len,
                                            const uint8_t *ciphertext, size_t ciphertext_len,
                                            const uint8_t tag[ND_AEAD_TAG_LEN],
                                            uint8_t *plaintext_out);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_AEAD_H */
