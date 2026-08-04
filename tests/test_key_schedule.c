/* nd_derive_handshake_keys / Finished tests.
 *
 * 1. The handshake_secret and both handshake traffic secrets are checked
 *    against RFC 8448's real values (passing ND_HKDF_LABEL_PREFIX_TLS13,
 *    since that trace is genuinely TLS 1.3) -- these three fields are
 *    always 32 bytes (SHA-256's output length) regardless of which AEAD
 *    cipher suite is negotiated, so they're meaningfully comparable even
 *    though nano-dtls uses a different cipher suite than RFC 8448's trace.
 *    The write_key/write_iv fields are NOT comparable to RFC 8448 (they're
 *    AES-128-sized there, ChaCha20-Poly1305-sized here -- HKDF-Expand-Label
 *    bakes the requested length into what gets hashed, so different
 *    lengths produce genuinely unrelated output, not a truncation of each
 *    other) -- those are checked instead by an independent recomputation
 *    through the lower-level primitives already KAT-tested in
 *    tests/test_hkdf.c.
 * 2. A key-separation sanity check: TLS13 and DTLS13 prefixes must produce
 *    different handshake secrets for identical inputs (same property
 *    tests/test_hkdf.c already checks at the raw HKDF-Expand-Label level;
 *    this checks it survives all the way through the higher-level API).
 * 3. Finished compute/verify, including tamper detection.
 * 4. An end-to-end integration test: a "client" and a "server" each with
 *    their own X25519 keypair build real ClientHello/ServerHello messages
 *    through nano-dtls's own serializers, each independently computes the
 *    transcript hash and shared secret, and both sides' derived handshake
 *    keys are checked to be identical -- the real proof that Stage 1-3's
 *    pieces (X25519, ClientHello/ServerHello encoding, transcript hashing,
 *    the DTLS 1.3 key schedule with the correct "dtls13" label prefix) work
 *    together, not just in isolation. */
#include "nanodtls/hello.h"
#include "nanodtls/key_schedule.h"
#include "nanodtls/transcript.h"
#include "nanodtls/x25519.h"
#include "test_util.h"

static void hex32(const char *hex, uint8_t out[32]) { CHECK(nd_hex_decode(hex, out, 32) == 32); }

static void test_rfc8448_traffic_secrets(void) {
    uint8_t shared_secret[32];
    hex32("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
          shared_secret);
    uint8_t transcript_hash[32];
    hex32("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8",
          transcript_hash);

    nd_handshake_keys keys;
    CHECK(nd_derive_handshake_keys(ND_HKDF_LABEL_PREFIX_TLS13, shared_secret, transcript_hash,
                                    &keys) == ND_OK);

    uint8_t expected_hs[32], expected_client_hs[32], expected_server_hs[32];
    hex32("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac",
          expected_hs);
    hex32("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21",
          expected_client_hs);
    hex32("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38",
          expected_server_hs);

    CHECK(nd_bytes_eq(keys.handshake_secret, expected_hs, 32));
    CHECK(nd_bytes_eq(keys.client_handshake_traffic_secret, expected_client_hs, 32));
    CHECK(nd_bytes_eq(keys.server_handshake_traffic_secret, expected_server_hs, 32));

    /* write_key/write_iv: independent recomputation via the already-tested
     * lower-level primitive, not an RFC 8448 comparison (see file header). */
    uint8_t expected_client_key[32], expected_client_iv[12];
    uint8_t expected_server_key[32], expected_server_iv[12];
    CHECK(nd_hkdf_expand_label(keys.client_handshake_traffic_secret, 32,
                                ND_HKDF_LABEL_PREFIX_TLS13, "key", NULL, 0, expected_client_key,
                                32) == ND_OK);
    CHECK(nd_hkdf_expand_label(keys.client_handshake_traffic_secret, 32,
                                ND_HKDF_LABEL_PREFIX_TLS13, "iv", NULL, 0, expected_client_iv,
                                12) == ND_OK);
    CHECK(nd_hkdf_expand_label(keys.server_handshake_traffic_secret, 32,
                                ND_HKDF_LABEL_PREFIX_TLS13, "key", NULL, 0, expected_server_key,
                                32) == ND_OK);
    CHECK(nd_hkdf_expand_label(keys.server_handshake_traffic_secret, 32,
                                ND_HKDF_LABEL_PREFIX_TLS13, "iv", NULL, 0, expected_server_iv,
                                12) == ND_OK);

    CHECK(nd_bytes_eq(keys.client_write_key, expected_client_key, 32));
    CHECK(nd_bytes_eq(keys.client_write_iv, expected_client_iv, 12));
    CHECK(nd_bytes_eq(keys.server_write_key, expected_server_key, 32));
    CHECK(nd_bytes_eq(keys.server_write_iv, expected_server_iv, 12));
}

static void test_dtls13_prefix_diverges(void) {
    uint8_t shared_secret[32], transcript_hash[32];
    for (size_t i = 0; i < 32; ++i) shared_secret[i] = (uint8_t)i;
    for (size_t i = 0; i < 32; ++i) transcript_hash[i] = (uint8_t)(31 - i);

    nd_handshake_keys tls_keys, dtls_keys;
    CHECK(nd_derive_handshake_keys(ND_HKDF_LABEL_PREFIX_TLS13, shared_secret, transcript_hash,
                                    &tls_keys) == ND_OK);
    CHECK(nd_derive_handshake_keys(ND_HKDF_LABEL_PREFIX_DTLS13, shared_secret, transcript_hash,
                                    &dtls_keys) == ND_OK);

    CHECK(!nd_bytes_eq(tls_keys.handshake_secret, dtls_keys.handshake_secret, 32));
    CHECK(!nd_bytes_eq(tls_keys.client_handshake_traffic_secret,
                       dtls_keys.client_handshake_traffic_secret, 32));
    CHECK(!nd_bytes_eq(tls_keys.client_write_key, dtls_keys.client_write_key, 32));
}

static void test_finished_compute_and_verify(void) {
    uint8_t base_key[32], transcript_hash[32];
    for (size_t i = 0; i < 32; ++i) base_key[i] = (uint8_t)(i * 3 + 1);
    for (size_t i = 0; i < 32; ++i) transcript_hash[i] = (uint8_t)(i * 5 + 2);

    uint8_t verify_data[32];
    CHECK(nd_finished_compute(ND_HKDF_LABEL_PREFIX_DTLS13, base_key, transcript_hash,
                               verify_data) == ND_OK);

    CHECK(nd_finished_verify(ND_HKDF_LABEL_PREFIX_DTLS13, base_key, transcript_hash,
                              verify_data) == ND_OK);

    uint8_t tampered[32];
    for (size_t i = 0; i < 32; ++i) tampered[i] = verify_data[i];
    tampered[0] ^= 0x01;
    CHECK(nd_finished_verify(ND_HKDF_LABEL_PREFIX_DTLS13, base_key, transcript_hash, tampered) ==
          ND_ERR_AUTH_FAILED);

    uint8_t wrong_transcript[32];
    for (size_t i = 0; i < 32; ++i) wrong_transcript[i] = (uint8_t)(i);
    CHECK(nd_finished_verify(ND_HKDF_LABEL_PREFIX_DTLS13, base_key, wrong_transcript,
                              verify_data) == ND_ERR_AUTH_FAILED);
}

static void test_end_to_end_client_and_server_agree(void) {
    /* Two independent X25519 keypairs -- "client" and "server". */
    uint8_t client_priv[32], server_priv[32];
    for (size_t i = 0; i < 32; ++i) client_priv[i] = (uint8_t)(i * 7 + 11);
    for (size_t i = 0; i < 32; ++i) server_priv[i] = (uint8_t)(i * 13 + 5);

    nd_client_hello_params ch_params;
    nd_server_hello_params sh_params;
    for (size_t i = 0; i < ND_RANDOM_LEN; ++i) ch_params.random[i] = (uint8_t)(i + 1);
    for (size_t i = 0; i < ND_RANDOM_LEN; ++i) sh_params.random[i] = (uint8_t)(200 - i);
    CHECK(nd_x25519_base(client_priv, ch_params.x25519_public_key) == ND_OK);
    CHECK(nd_x25519_base(server_priv, sh_params.x25519_public_key) == ND_OK);

    uint8_t client_hello[256], server_hello[256];
    size_t ch_len, sh_len;
    CHECK(nd_client_hello_serialize(&ch_params, client_hello, sizeof(client_hello), &ch_len) ==
          ND_OK);
    CHECK(nd_server_hello_serialize(&sh_params, server_hello, sizeof(server_hello), &sh_len) ==
          ND_OK);

    /* Both sides hash the same two messages in the same order. */
    nd_transcript client_transcript, server_transcript;
    nd_transcript_init(&client_transcript);
    nd_transcript_add(&client_transcript, client_hello, ch_len);
    nd_transcript_add(&client_transcript, server_hello, sh_len);
    uint8_t client_hash[32];
    nd_transcript_snapshot(&client_transcript, client_hash);

    nd_transcript_init(&server_transcript);
    nd_transcript_add(&server_transcript, client_hello, ch_len);
    nd_transcript_add(&server_transcript, server_hello, sh_len);
    uint8_t server_hash[32];
    nd_transcript_snapshot(&server_transcript, server_hash);

    CHECK(nd_bytes_eq(client_hash, server_hash, 32));

    /* Each side computes the X25519 shared secret from its OWN private key
     * and the OTHER side's public key -- this is the actual DH step, not a
     * shortcut. */
    uint8_t client_shared[32], server_shared[32];
    CHECK(nd_x25519_scalarmult(client_priv, sh_params.x25519_public_key, client_shared) ==
          ND_OK);
    CHECK(nd_x25519_scalarmult(server_priv, ch_params.x25519_public_key, server_shared) ==
          ND_OK);
    CHECK(nd_bytes_eq(client_shared, server_shared, 32));

    nd_handshake_keys client_keys, server_keys;
    CHECK(nd_derive_handshake_keys(ND_HKDF_LABEL_PREFIX_DTLS13, client_shared, client_hash,
                                    &client_keys) == ND_OK);
    CHECK(nd_derive_handshake_keys(ND_HKDF_LABEL_PREFIX_DTLS13, server_shared, server_hash,
                                    &server_keys) == ND_OK);

    CHECK(nd_bytes_eq(client_keys.handshake_secret, server_keys.handshake_secret, 32));
    CHECK(nd_bytes_eq(client_keys.client_write_key, server_keys.client_write_key, 32));
    CHECK(nd_bytes_eq(client_keys.client_write_iv, server_keys.client_write_iv, 12));
    CHECK(nd_bytes_eq(client_keys.server_write_key, server_keys.server_write_key, 32));
    CHECK(nd_bytes_eq(client_keys.server_write_iv, server_keys.server_write_iv, 12));

    /* And the client's Finished, computed by "client" and independently
     * recomputed by "server" against the same base key, must agree. */
    uint8_t client_finished[32], server_side_check[32];
    CHECK(nd_finished_compute(ND_HKDF_LABEL_PREFIX_DTLS13,
                               client_keys.client_handshake_traffic_secret, client_hash,
                               client_finished) == ND_OK);
    CHECK(nd_finished_compute(ND_HKDF_LABEL_PREFIX_DTLS13,
                               server_keys.client_handshake_traffic_secret, server_hash,
                               server_side_check) == ND_OK);
    CHECK(nd_bytes_eq(client_finished, server_side_check, 32));
    CHECK(nd_finished_verify(ND_HKDF_LABEL_PREFIX_DTLS13,
                              server_keys.client_handshake_traffic_secret, server_hash,
                              client_finished) == ND_OK);
}

int main(void) {
    test_rfc8448_traffic_secrets();
    test_dtls13_prefix_diverges();
    test_finished_compute_and_verify();
    test_end_to_end_client_and_server_agree();
    return nd_test_summary("test_key_schedule");
}
