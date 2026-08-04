/* ECDSA-P256-SHA256 verification tests. Unlike this repo's other KATs (RFC
 * 5869/7748/8439/8448 test vectors, transcribed from the actual RFC text),
 * there is no small official P-256 ECDSA KAT worth hand-transcribing here --
 * NIST's real ones (SP 800-186/CAVP) are enormous machine-readable files.
 * Instead this vector was *generated*, not hand-typed: a real P-256 keypair,
 * message, SHA-256 hash, and ECDSA signature produced by the OpenSSL 3.5.7
 * installed on this machine (scratchpad/gen_p256_kat.py), with OpenSSL's own
 * `dgst -verify` confirming the signature is valid before it was ever handed
 * to nano-dtls. That is: an independent, trusted implementation is the
 * ground truth nano-dtls is checked against here, the same role RFC text
 * plays elsewhere in this repo. Every hex constant below was extracted
 * programmatically (length-asserted at generation time), not eyeballed. */
#include "nanodtls/p256.h"

#include "test_util.h"

static const char KAT_HASH[] = "6ff47be5c21162836aaa53ee435ce628f3fdee6a87f9596c3f868db06c7d15a1";
static const char KAT_R[] = "dd4f17bfb9722b0cf018fdeb900442921f8b34ac9d56698996678715b8cb865b";
static const char KAT_S[] = "9f3c9daaf31c355627af2988827fc3617103e3428f05f408d8cd620b7fdee22b";
static const char KAT_QX[] = "e3d107d8e8fd4b19d052795f58b4bd2cf51dec6227a42114a53e1a2717b98c6e";
static const char KAT_QY[] = "7e6edbcfb6df9bff8d045f16923fa0d258ff23bd07787799694a3042311eb2d7";
static const char KAT_R_BAD[] = "dd4f17bfb9722b0cf018fdeb900442921f8b34ac9d56698996678715b8cb8650";

/* Every constant above decodes to exactly 32 bytes: gen_p256_kat.py strips
 * the DER INTEGER's leading 0x00 sign byte (if present) and left-pads back
 * to 32, so KAT_R/KAT_S are already in the fixed-width form
 * nd_p256_ecdsa_verify expects. */

static void decode32(const char *hex, uint8_t out[32]) { CHECK(nd_hex_decode(hex, out, 32) == 32); }

static void test_openssl_generated_signature_verifies(void) {
    uint8_t hash[32], r[32], s[32], qx[32], qy[32];
    decode32(KAT_HASH, hash);
    decode32(KAT_R, r);
    decode32(KAT_S, s);
    decode32(KAT_QX, qx);
    decode32(KAT_QY, qy);

    CHECK(nd_p256_point_is_valid(qx, qy) == ND_OK);
    CHECK(nd_p256_ecdsa_verify(qx, qy, hash, r, s) == ND_OK);
}

static void test_tampered_signature_rejected(void) {
    uint8_t hash[32], r_bad[32], s[32], qx[32], qy[32];
    decode32(KAT_HASH, hash);
    decode32(KAT_R_BAD, r_bad);
    decode32(KAT_S, s);
    decode32(KAT_QX, qx);
    decode32(KAT_QY, qy);

    CHECK(nd_p256_ecdsa_verify(qx, qy, hash, r_bad, s) == ND_ERR_AUTH_FAILED);
}

static void test_tampered_hash_rejected(void) {
    uint8_t hash[32], r[32], s[32], qx[32], qy[32];
    decode32(KAT_HASH, hash);
    decode32(KAT_R, r);
    decode32(KAT_S, s);
    decode32(KAT_QX, qx);
    decode32(KAT_QY, qy);
    hash[0] ^= 0x01; /* flip one bit of the signed message hash */

    CHECK(nd_p256_ecdsa_verify(qx, qy, hash, r, s) == ND_ERR_AUTH_FAILED);
}

static void test_wrong_public_key_rejected(void) {
    /* Curve base point G is a valid point but (almost certainly) not the
     * key that produced this signature -- confirms verify checks the actual
     * key, not just "is this a point on the curve". */
    uint8_t hash[32], r[32], s[32];
    decode32(KAT_HASH, hash);
    decode32(KAT_R, r);
    decode32(KAT_S, s);
    uint8_t gx[32], gy[32];
    CHECK(nd_hex_decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", gx, 32) == 32);
    CHECK(nd_hex_decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", gy, 32) == 32);

    CHECK(nd_p256_point_is_valid(gx, gy) == ND_OK);
    CHECK(nd_p256_ecdsa_verify(gx, gy, hash, r, s) == ND_ERR_AUTH_FAILED);
}

static void test_point_validity_rejects_garbage(void) {
    uint8_t zero[32] = {0};
    /* (0, 0) is not on y^2 = x^3 - 3x + b for P-256's b. */
    CHECK(nd_p256_point_is_valid(zero, zero) == ND_ERR_BAD_ARG);

    uint8_t gx[32], gy_wrong[32];
    CHECK(nd_hex_decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", gx, 32) == 32);
    for (int i = 0; i < 32; ++i) gy_wrong[i] = 0x42; /* not G's real Y */
    CHECK(nd_p256_point_is_valid(gx, gy_wrong) == ND_ERR_BAD_ARG);
}

static void test_base_point_g_is_valid(void) {
    uint8_t gx[32], gy[32];
    CHECK(nd_hex_decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", gx, 32) == 32);
    CHECK(nd_hex_decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", gy, 32) == 32);
    CHECK(nd_p256_point_is_valid(gx, gy) == ND_OK);
}

int main(void) {
    test_base_point_g_is_valid();
    test_openssl_generated_signature_verifies();
    test_tampered_signature_rejected();
    test_tampered_hash_rejected();
    test_wrong_public_key_rejected();
    test_point_validity_rejects_garbage();
    return nd_test_summary("test_p256");
}
