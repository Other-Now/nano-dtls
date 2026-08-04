/* AEAD_CHACHA20_POLY1305 construction per RFC 8439 section 2.8: the
 * Poly1305 one-time key is the first 32 bytes of the ChaCha20 keystream at
 * block counter 0; the message is ChaCha20-encrypted starting at counter 1;
 * the tag MACs (aad || pad16(aad) || ciphertext || pad16(ciphertext) ||
 * len(aad) || len(ciphertext)), the two lengths as 8-byte little-endian. */
#include "nanodtls/aead.h"

#include <string.h>

#include "nanodtls/chacha20.h"
#include "nanodtls/poly1305.h"

static void store_le64(uint8_t p[8], uint64_t x) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(x >> (8 * i));
}

static void mac_aad_and_ciphertext(nd_poly1305_ctx *mac, const uint8_t *aad, size_t aad_len,
                                    const uint8_t *ciphertext, size_t ciphertext_len) {
    static const uint8_t zeros[16] = {0};

    nd_poly1305_update(mac, aad, aad_len);
    size_t aad_pad = (16u - (aad_len % 16u)) % 16u;
    if (aad_pad) nd_poly1305_update(mac, zeros, aad_pad);

    nd_poly1305_update(mac, ciphertext, ciphertext_len);
    size_t ct_pad = (16u - (ciphertext_len % 16u)) % 16u;
    if (ct_pad) nd_poly1305_update(mac, zeros, ct_pad);

    uint8_t lens[16];
    store_le64(lens, (uint64_t)aad_len);
    store_le64(lens + 8, (uint64_t)ciphertext_len);
    nd_poly1305_update(mac, lens, sizeof(lens));
}

static void derive_otk(const uint8_t key[ND_AEAD_KEY_LEN], const uint8_t nonce[ND_AEAD_NONCE_LEN],
                        uint8_t otk[ND_POLY1305_KEY_LEN]) {
    uint8_t block0[ND_CHACHA20_BLOCK_LEN];
    nd_chacha20_block(key, nonce, 0, block0);
    memcpy(otk, block0, ND_POLY1305_KEY_LEN);
}

nd_status nd_aead_chacha20poly1305_encrypt(const uint8_t key[ND_AEAD_KEY_LEN],
                                            const uint8_t nonce[ND_AEAD_NONCE_LEN],
                                            const uint8_t *aad, size_t aad_len,
                                            const uint8_t *plaintext, size_t plaintext_len,
                                            uint8_t *ciphertext_out,
                                            uint8_t tag_out[ND_AEAD_TAG_LEN]) {
    if (!key || !nonce || (aad_len > 0 && !aad) ||
        (plaintext_len > 0 && (!plaintext || !ciphertext_out)) || !tag_out) {
        return ND_ERR_BAD_ARG;
    }

    nd_status st = nd_chacha20_xor(key, nonce, 1, plaintext, ciphertext_out, plaintext_len);
    if (st != ND_OK) return st;

    uint8_t otk[ND_POLY1305_KEY_LEN];
    derive_otk(key, nonce, otk);

    nd_poly1305_ctx mac;
    nd_poly1305_init(&mac, otk);
    mac_aad_and_ciphertext(&mac, aad, aad_len, ciphertext_out, plaintext_len);
    nd_poly1305_final(&mac, tag_out);
    return ND_OK;
}

nd_status nd_aead_chacha20poly1305_decrypt(const uint8_t key[ND_AEAD_KEY_LEN],
                                            const uint8_t nonce[ND_AEAD_NONCE_LEN],
                                            const uint8_t *aad, size_t aad_len,
                                            const uint8_t *ciphertext, size_t ciphertext_len,
                                            const uint8_t tag[ND_AEAD_TAG_LEN],
                                            uint8_t *plaintext_out) {
    if (!key || !nonce || (aad_len > 0 && !aad) ||
        (ciphertext_len > 0 && (!ciphertext || !plaintext_out)) || !tag) {
        return ND_ERR_BAD_ARG;
    }

    uint8_t otk[ND_POLY1305_KEY_LEN];
    derive_otk(key, nonce, otk);

    nd_poly1305_ctx mac;
    nd_poly1305_init(&mac, otk);
    mac_aad_and_ciphertext(&mac, aad, aad_len, ciphertext, ciphertext_len);
    uint8_t computed_tag[ND_AEAD_TAG_LEN];
    nd_poly1305_final(&mac, computed_tag);

    uint8_t diff = 0;
    for (size_t i = 0; i < ND_AEAD_TAG_LEN; ++i) diff = (uint8_t)(diff | (computed_tag[i] ^ tag[i]));
    if (diff != 0) return ND_ERR_AUTH_FAILED;

    return nd_chacha20_xor(key, nonce, 1, ciphertext, plaintext_out, ciphertext_len);
}
