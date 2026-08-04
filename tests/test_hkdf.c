/* HKDF known-answer tests.
 *
 * 1. RFC 5869 Appendix A.1, Test Case 1 -- validates raw HKDF-Extract/Expand.
 * 2. The early-secret -> handshake-secret -> handshake-traffic-secret ->
 *    write-key/IV chain from RFC 8448 section 3 ("Simple 1-RTT Handshake")
 *    -- validates HKDF-Expand-Label / Derive-Secret against a real,
 *    published TLS 1.3 handshake trace. Every constant below (including the
 *    "hash of ClientHello..ServerHello" step 5 uses) is quoted directly
 *    from RFC 8448, not derived locally, so this chain doesn't depend on
 *    transcribing the (much larger) ClientHello/ServerHello byte sequences
 *    -- exactly the point of RFC 8448 being a fully worked example. */
#include "nanodtls/hkdf.h"
#include "nanodtls/sha256.h"
#include "test_util.h"

static void test_rfc5869_case1(void) {
    uint8_t ikm[22], salt[13], info[10];
    CHECK(nd_hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, sizeof(ikm)) == 22);
    CHECK(nd_hex_decode("000102030405060708090a0b0c", salt, sizeof(salt)) == 13);
    CHECK(nd_hex_decode("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info)) == 10);

    uint8_t expected_prk[32];
    CHECK(nd_hex_decode("077709362c2e32df0ddc3f0dc47bba63 90b6c73bb50f9c3122ec844ad7c2b3e5",
                        expected_prk, sizeof(expected_prk)) == 32);

    uint8_t prk[32];
    CHECK(nd_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk) == ND_OK);
    CHECK(nd_bytes_eq(prk, expected_prk, sizeof(expected_prk)));

    uint8_t expected_okm[42];
    CHECK(nd_hex_decode("3cb25f25faacd57a90434f64d0362f2a"
                        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        "34007208d5b887185865",
                        expected_okm, sizeof(expected_okm)) == 42);

    uint8_t okm[42];
    CHECK(nd_hkdf_expand(prk, sizeof(prk), info, sizeof(info), okm, sizeof(okm)) == ND_OK);
    CHECK(nd_bytes_eq(okm, expected_okm, sizeof(expected_okm)));
}

/* Decodes a space-separated RFC hex dump into `out`, asserting the exact
 * expected byte count (all values in this chain are 32, 16, or 12 bytes). */
static void hex32(const char *hex, uint8_t out[32]) {
    CHECK(nd_hex_decode(hex, out, 32) == 32);
}

static void test_rfc8448_handshake_secret_chain(void) {
    uint8_t zero32[32] = {0};

    /* Step 1: Early Secret = HKDF-Extract(salt=0, ikm=0). */
    uint8_t early_secret[32];
    CHECK(nd_hkdf_extract(zero32, 32, zero32, 32, early_secret) == ND_OK);
    uint8_t expected_early[32];
    hex32("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a",
          expected_early);
    CHECK(nd_bytes_eq(early_secret, expected_early, 32));

    /* Step 2: derived = Derive-Secret(early_secret, "derived", Transcript-Hash("")). */
    uint8_t empty_hash[32];
    nd_sha256((const uint8_t *)"", 0, empty_hash);
    uint8_t derived_early[32];
    CHECK(nd_derive_secret(early_secret, 32, ND_HKDF_LABEL_PREFIX_TLS13, "derived", empty_hash, 32,
                            derived_early) == ND_OK);
    uint8_t expected_derived[32];
    hex32("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba",
          expected_derived);
    CHECK(nd_bytes_eq(derived_early, expected_derived, 32));

    /* Step 3: the x25519 ECDHE shared secret (given directly by RFC 8448). */
    uint8_t shared_secret[32];
    hex32("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
          shared_secret);

    /* Step 4: Handshake Secret = HKDF-Extract(derived_early, shared_secret). */
    uint8_t handshake_secret[32];
    CHECK(nd_hkdf_extract(derived_early, 32, shared_secret, 32, handshake_secret) == ND_OK);
    uint8_t expected_hs[32];
    hex32("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac",
          expected_hs);
    CHECK(nd_bytes_eq(handshake_secret, expected_hs, 32));

    /* Step 5: transcript hash of ClientHello..ServerHello, quoted directly
     * from RFC 8448 (not recomputed here -- see file header). */
    uint8_t transcript_hash[32];
    hex32("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8",
          transcript_hash);

    /* Step 6: the two handshake traffic secrets. */
    uint8_t client_hs_traffic[32];
    CHECK(nd_derive_secret(handshake_secret, 32, ND_HKDF_LABEL_PREFIX_TLS13, "c hs traffic",
                            transcript_hash, 32, client_hs_traffic) == ND_OK);
    uint8_t expected_client_hs[32];
    hex32("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21",
          expected_client_hs);
    CHECK(nd_bytes_eq(client_hs_traffic, expected_client_hs, 32));

    uint8_t server_hs_traffic[32];
    CHECK(nd_derive_secret(handshake_secret, 32, ND_HKDF_LABEL_PREFIX_TLS13, "s hs traffic",
                            transcript_hash, 32, server_hs_traffic) == ND_OK);
    uint8_t expected_server_hs[32];
    hex32("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38",
          expected_server_hs);
    CHECK(nd_bytes_eq(server_hs_traffic, expected_server_hs, 32));

    /* Step 7: write keys/IVs derived from those traffic secrets. RFC 8448's
     * worked example uses TLS_AES_128_GCM_SHA256 (16-byte keys); this still
     * validates the HKDF-Expand-Label mechanism itself, independent of
     * which AEAD nano-dtls actually wires up for record protection
     * (ChaCha20-Poly1305, 32-byte keys) -- the label/context/length
     * encoding is identical either way. */
    uint8_t server_key[16], server_iv[12], client_key[16], client_iv[12];
    CHECK(nd_hkdf_expand_label(server_hs_traffic, 32, ND_HKDF_LABEL_PREFIX_TLS13, "key", NULL, 0,
                                server_key, 16) == ND_OK);
    CHECK(nd_hkdf_expand_label(server_hs_traffic, 32, ND_HKDF_LABEL_PREFIX_TLS13, "iv", NULL, 0,
                                server_iv, 12) == ND_OK);
    CHECK(nd_hkdf_expand_label(client_hs_traffic, 32, ND_HKDF_LABEL_PREFIX_TLS13, "key", NULL, 0,
                                client_key, 16) == ND_OK);
    CHECK(nd_hkdf_expand_label(client_hs_traffic, 32, ND_HKDF_LABEL_PREFIX_TLS13, "iv", NULL, 0,
                                client_iv, 12) == ND_OK);

    uint8_t expected_server_key[16], expected_server_iv[12];
    uint8_t expected_client_key[16], expected_client_iv[12];
    CHECK(nd_hex_decode("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc", expected_server_key,
                        16) == 16);
    CHECK(nd_hex_decode("5d 31 3e b2 67 12 76 ee 13 00 0b 30", expected_server_iv, 12) == 12);
    CHECK(nd_hex_decode("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01", expected_client_key,
                        16) == 16);
    CHECK(nd_hex_decode("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f", expected_client_iv, 12) == 12);

    CHECK(nd_bytes_eq(server_key, expected_server_key, 16));
    CHECK(nd_bytes_eq(server_iv, expected_server_iv, 12));
    CHECK(nd_bytes_eq(client_key, expected_client_key, 16));
    CHECK(nd_bytes_eq(client_iv, expected_client_iv, 12));
}

static void test_dtls13_prefix_differs_from_tls13(void) {
    /* RFC 9147 section 5.9: DTLS 1.3 deliberately uses a different
     * HKDF-Expand-Label prefix ("dtls13") than TLS 1.3 ("tls13 ") for key
     * separation. Confirm the two prefixes actually diverge for identical
     * secret/label/context inputs -- if this ever matched, DTLS 1.3 traffic
     * keys would collide with TLS 1.3 traffic keys derived the same way. */
    uint8_t secret[32];
    for (size_t i = 0; i < sizeof(secret); ++i) secret[i] = (uint8_t)i;

    uint8_t tls_out[32], dtls_out[32];
    CHECK(nd_hkdf_expand_label(secret, sizeof(secret), ND_HKDF_LABEL_PREFIX_TLS13, "c hs traffic",
                                NULL, 0, tls_out, sizeof(tls_out)) == ND_OK);
    CHECK(nd_hkdf_expand_label(secret, sizeof(secret), ND_HKDF_LABEL_PREFIX_DTLS13, "c hs traffic",
                                NULL, 0, dtls_out, sizeof(dtls_out)) == ND_OK);
    CHECK(!nd_bytes_eq(tls_out, dtls_out, sizeof(tls_out)));
}

int main(void) {
    test_rfc5869_case1();
    test_rfc8448_handshake_secret_chain();
    test_dtls13_prefix_differs_from_tls13();
    return nd_test_summary("test_hkdf");
}
