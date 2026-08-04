#include "nanodtls/key_schedule.h"

#include "nanodtls/hmac_sha256.h"
#include "nanodtls/sha256.h"

nd_status nd_derive_handshake_keys(const char *label_prefix,
                                    const uint8_t shared_secret[ND_HASH_LEN],
                                    const uint8_t hello_transcript_hash[ND_HASH_LEN],
                                    nd_handshake_keys *out_keys) {
    if (!label_prefix || !shared_secret || !hello_transcript_hash || !out_keys) {
        return ND_ERR_BAD_ARG;
    }

    const uint8_t zero32[ND_HASH_LEN] = {0};
    uint8_t early_secret[ND_HASH_LEN];
    nd_status st = nd_hkdf_extract(zero32, ND_HASH_LEN, zero32, ND_HASH_LEN, early_secret);
    if (st != ND_OK) return st;

    uint8_t empty_hash[ND_HASH_LEN];
    nd_sha256((const uint8_t *)"", 0, empty_hash);
    uint8_t derived_early[ND_HASH_LEN];
    st = nd_derive_secret(early_secret, ND_HASH_LEN, label_prefix, "derived", empty_hash,
                           ND_HASH_LEN, derived_early);
    if (st != ND_OK) return st;

    st = nd_hkdf_extract(derived_early, ND_HASH_LEN, shared_secret, ND_HASH_LEN,
                          out_keys->handshake_secret);
    if (st != ND_OK) return st;

    st = nd_derive_secret(out_keys->handshake_secret, ND_HASH_LEN, label_prefix, "c hs traffic",
                           hello_transcript_hash, ND_HASH_LEN,
                           out_keys->client_handshake_traffic_secret);
    if (st != ND_OK) return st;
    st = nd_derive_secret(out_keys->handshake_secret, ND_HASH_LEN, label_prefix, "s hs traffic",
                           hello_transcript_hash, ND_HASH_LEN,
                           out_keys->server_handshake_traffic_secret);
    if (st != ND_OK) return st;

    st = nd_hkdf_expand_label(out_keys->client_handshake_traffic_secret, ND_HASH_LEN, label_prefix,
                               "key", NULL, 0, out_keys->client_write_key, ND_AEAD_KEY_LEN);
    if (st != ND_OK) return st;
    st = nd_hkdf_expand_label(out_keys->client_handshake_traffic_secret, ND_HASH_LEN, label_prefix,
                               "iv", NULL, 0, out_keys->client_write_iv, ND_AEAD_NONCE_LEN);
    if (st != ND_OK) return st;
    st = nd_hkdf_expand_label(out_keys->server_handshake_traffic_secret, ND_HASH_LEN, label_prefix,
                               "key", NULL, 0, out_keys->server_write_key, ND_AEAD_KEY_LEN);
    if (st != ND_OK) return st;
    st = nd_hkdf_expand_label(out_keys->server_handshake_traffic_secret, ND_HASH_LEN, label_prefix,
                               "iv", NULL, 0, out_keys->server_write_iv, ND_AEAD_NONCE_LEN);
    if (st != ND_OK) return st;

    return ND_OK;
}

nd_status nd_finished_compute(const char *label_prefix, const uint8_t base_key[ND_HASH_LEN],
                               const uint8_t transcript_hash[ND_HASH_LEN],
                               uint8_t out_verify_data[ND_HASH_LEN]) {
    if (!label_prefix || !base_key || !transcript_hash || !out_verify_data) {
        return ND_ERR_BAD_ARG;
    }
    uint8_t finished_key[ND_HASH_LEN];
    nd_status st = nd_hkdf_expand_label(base_key, ND_HASH_LEN, label_prefix, "finished", NULL, 0,
                                         finished_key, ND_HASH_LEN);
    if (st != ND_OK) return st;

    nd_hmac_sha256(finished_key, ND_HASH_LEN, transcript_hash, ND_HASH_LEN, out_verify_data);
    return ND_OK;
}

nd_status nd_finished_verify(const char *label_prefix, const uint8_t base_key[ND_HASH_LEN],
                              const uint8_t transcript_hash[ND_HASH_LEN],
                              const uint8_t received_verify_data[ND_HASH_LEN]) {
    if (!received_verify_data) return ND_ERR_BAD_ARG;
    uint8_t computed[ND_HASH_LEN];
    nd_status st = nd_finished_compute(label_prefix, base_key, transcript_hash, computed);
    if (st != ND_OK) return st;

    uint8_t diff = 0;
    for (size_t i = 0; i < ND_HASH_LEN; ++i) diff = (uint8_t)(diff | (computed[i] ^ received_verify_data[i]));
    return diff == 0 ? ND_OK : ND_ERR_AUTH_FAILED;
}
