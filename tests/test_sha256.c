/* SHA-256 known-answer tests. Digests confirmed against
 * https://www.rfc-editor.org/rfc/rfc4231.txt and standard NIST/FIPS 180-4
 * short test vectors ("" and "abc"). */
#include "nanodtls/sha256.h"
#include "test_util.h"

static void check_digest(const char *msg, size_t msg_len, const char *expected_hex) {
    uint8_t expected[ND_SHA256_DIGEST_LEN];
    CHECK(nd_hex_decode(expected_hex, expected, sizeof(expected)) == ND_SHA256_DIGEST_LEN);

    uint8_t got[ND_SHA256_DIGEST_LEN];
    nd_sha256((const uint8_t *)msg, msg_len, got);
    CHECK(nd_bytes_eq(got, expected, ND_SHA256_DIGEST_LEN));
}

static void test_empty_string(void) {
    check_digest("", 0,
                 "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855");
}

static void test_abc(void) {
    check_digest("abc", 3,
                 "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad");
}

static void test_streaming_matches_one_shot(void) {
    /* Feed "abc" one byte at a time through the streaming API and confirm
     * it matches the one-shot digest -- exercises the buffered-update path
     * that the one-shot wrapper alone never touches. */
    const char *msg = "abc";
    nd_sha256_ctx ctx;
    nd_sha256_init(&ctx);
    for (size_t i = 0; i < 3; ++i) nd_sha256_update(&ctx, (const uint8_t *)msg + i, 1);
    uint8_t got[ND_SHA256_DIGEST_LEN];
    nd_sha256_final(&ctx, got);

    uint8_t expected[ND_SHA256_DIGEST_LEN];
    nd_sha256((const uint8_t *)msg, 3, expected);
    CHECK(nd_bytes_eq(got, expected, ND_SHA256_DIGEST_LEN));
}

static void test_multi_block(void) {
    /* 64 'a' bytes: exactly one full SHA-256 block, then padding needs a
     * second block -- exercises the buf_len==BLOCK_LEN compress-and-reset
     * path plus the "already at a block boundary" padding case. */
    uint8_t msg[64];
    for (int i = 0; i < 64; ++i) msg[i] = 'a';
    uint8_t got[ND_SHA256_DIGEST_LEN];
    nd_sha256(msg, sizeof(msg), got);

    /* Cross-check via streaming in two 32-byte chunks. */
    nd_sha256_ctx ctx;
    nd_sha256_init(&ctx);
    nd_sha256_update(&ctx, msg, 32);
    nd_sha256_update(&ctx, msg + 32, 32);
    uint8_t got2[ND_SHA256_DIGEST_LEN];
    nd_sha256_final(&ctx, got2);
    CHECK(nd_bytes_eq(got, got2, ND_SHA256_DIGEST_LEN));
}

int main(void) {
    test_empty_string();
    test_abc();
    test_streaming_matches_one_shot();
    test_multi_block();
    return nd_test_summary("test_sha256");
}
