/* nd_record_protect/unprotect compose two already-KAT-tested layers (the
 * unified header, test_record.c; AEAD_CHACHA20_POLY1305, test_chacha20poly1305.c)
 * so what needs checking here is the composition itself: round-trip
 * correctness, that the sequence number actually advances, tamper
 * detection, and -- the strongest check -- that the nonce/AAD this file
 * builds internally match an independent, by-hand reconstruction through
 * the same lower-level primitives test_chacha20poly1305.c already trusts. */
#include "nanodtls/protect.h"

#include "nanodtls/aead.h"
#include "nanodtls/record.h"
#include "test_util.h"

static void fill(uint8_t *buf, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)(seed + i * 7);
}

static void test_round_trip_single_record(void) {
    uint8_t key[ND_AEAD_KEY_LEN], iv[ND_AEAD_NONCE_LEN];
    fill(key, sizeof(key), 1);
    fill(iv, sizeof(iv), 2);

    nd_record_protection p;
    nd_record_protection_init(&p, key, iv, /*epoch=*/2);
    nd_record_unprotection u;
    nd_record_unprotection_init(&u, key, iv, /*epoch=*/2);

    const uint8_t msg[] = "EncryptedExtensions-stand-in-body";
    uint8_t record[512];
    size_t record_len;
    CHECK(nd_record_protect(&p, 22 /* handshake */, msg, sizeof(msg) - 1, record, sizeof(record), &record_len) ==
          ND_OK);
    CHECK(p.next_send_sequence == 1);

    uint8_t plaintext[512];
    size_t plaintext_len;
    uint8_t content_type;
    CHECK(nd_record_unprotect(&u, record, record_len, plaintext, sizeof(plaintext), &plaintext_len,
                               &content_type) == ND_OK);
    CHECK(content_type == 22);
    CHECK(plaintext_len == sizeof(msg) - 1);
    CHECK(nd_bytes_eq(plaintext, msg, plaintext_len));
    CHECK(u.highest_seen_sequence == 0);
}

static void test_sequence_number_advances_across_records(void) {
    uint8_t key[ND_AEAD_KEY_LEN], iv[ND_AEAD_NONCE_LEN];
    fill(key, sizeof(key), 3);
    fill(iv, sizeof(iv), 4);
    nd_record_protection p;
    nd_record_protection_init(&p, key, iv, 2);
    nd_record_unprotection u;
    nd_record_unprotection_init(&u, key, iv, 2);

    for (uint64_t i = 0; i < 5; ++i) {
        uint8_t msg[4] = {(uint8_t)i, 0, 0, 0};
        uint8_t record[128];
        size_t record_len;
        CHECK(nd_record_protect(&p, 23, msg, sizeof(msg), record, sizeof(record), &record_len) == ND_OK);
        CHECK(p.next_send_sequence == i + 1);

        uint8_t plaintext[128];
        size_t plaintext_len;
        uint8_t content_type;
        CHECK(nd_record_unprotect(&u, record, record_len, plaintext, sizeof(plaintext), &plaintext_len,
                                   &content_type) == ND_OK);
        CHECK(content_type == 23);
        CHECK(plaintext[0] == (uint8_t)i);
        CHECK(u.highest_seen_sequence == i);
    }
}

static void test_tampered_ciphertext_rejected_state_unchanged(void) {
    uint8_t key[ND_AEAD_KEY_LEN], iv[ND_AEAD_NONCE_LEN];
    fill(key, sizeof(key), 5);
    fill(iv, sizeof(iv), 6);
    nd_record_protection p;
    nd_record_protection_init(&p, key, iv, 2);
    nd_record_unprotection u;
    nd_record_unprotection_init(&u, key, iv, 2);

    const uint8_t msg[] = "tamper-me";
    uint8_t record[128];
    size_t record_len;
    CHECK(nd_record_protect(&p, 20, msg, sizeof(msg) - 1, record, sizeof(record), &record_len) == ND_OK);
    record[record_len - 1] ^= 0x01; /* flip a tag byte */

    uint8_t plaintext[128];
    size_t plaintext_len;
    uint8_t content_type;
    CHECK(nd_record_unprotect(&u, record, record_len, plaintext, sizeof(plaintext), &plaintext_len,
                               &content_type) == ND_ERR_AUTH_FAILED);
    CHECK(u.highest_seen_sequence == 0); /* an unauthenticated record must not move the high-water mark */
}

static void test_wrong_epoch_rejected(void) {
    uint8_t key[ND_AEAD_KEY_LEN], iv[ND_AEAD_NONCE_LEN];
    fill(key, sizeof(key), 7);
    fill(iv, sizeof(iv), 8);
    nd_record_protection p;
    nd_record_protection_init(&p, key, iv, /*epoch=*/2);
    nd_record_unprotection u;
    nd_record_unprotection_init(&u, key, iv, /*epoch=*/3); /* mismatched */

    const uint8_t msg[] = "epoch-mismatch";
    uint8_t record[128];
    size_t record_len;
    CHECK(nd_record_protect(&p, 22, msg, sizeof(msg) - 1, record, sizeof(record), &record_len) == ND_OK);

    uint8_t plaintext[128];
    size_t plaintext_len;
    uint8_t content_type;
    CHECK(nd_record_unprotect(&u, record, record_len, plaintext, sizeof(plaintext), &plaintext_len,
                               &content_type) == ND_ERR_UNSUPPORTED);
}

/* Independently reconstructs record #0's ciphertext by hand -- computing
 * the nonce and AAD exactly as nanodtls/protect.h documents them, then
 * calling the already-KAT-tested AEAD primitive directly -- and checks it
 * matches nd_record_protect's output byte for byte. This is the strongest
 * check available without a real external DTLS 1.3 peer: proof the nonce
 * (write_iv XOR 64-bit sequence_number, epoch NOT included) and AAD (the
 * unified header bytes) match this file's own documented and RFC-cited
 * construction, not just proof the two nanodtls functions agree with each
 * other (which alone would pass even if a bug were introduced consistently
 * on both sides of this file). */
static void test_nonce_and_aad_match_independent_reconstruction(void) {
    uint8_t key[ND_AEAD_KEY_LEN], iv[ND_AEAD_NONCE_LEN];
    fill(key, sizeof(key), 9);
    fill(iv, sizeof(iv), 10);
    nd_record_protection p;
    nd_record_protection_init(&p, key, iv, 2);

    const uint8_t msg[] = "nonce-and-aad-check";
    uint8_t content_type = 22;
    uint8_t record[128];
    size_t record_len;
    CHECK(nd_record_protect(&p, content_type, msg, sizeof(msg) - 1, record, sizeof(record), &record_len) == ND_OK);

    /* Unified header with seq_len=16, length_present=1, cid absent is fixed
     * 5 bytes: 1 flags byte + 2 seq bytes + 2 length bytes. */
    size_t header_len = 5;
    CHECK(record_len == header_len + (sizeof(msg) - 1) + 1 /* content-type byte */ + ND_AEAD_TAG_LEN);

    /* sequence_number is 0 for the first record on a fresh
     * nd_record_protection, so the padded-sequence XOR is an XOR with all
     * zero bytes -- nonce == write_iv exactly for this one record. */
    uint8_t nonce[ND_AEAD_NONCE_LEN];
    for (int i = 0; i < ND_AEAD_NONCE_LEN; ++i) nonce[i] = iv[i];

    uint8_t inner[64];
    for (size_t i = 0; i < sizeof(msg) - 1; ++i) inner[i] = msg[i];
    inner[sizeof(msg) - 1] = content_type;
    size_t inner_len = sizeof(msg); /* (sizeof(msg)-1) content bytes + 1 content-type byte */

    uint8_t expect_ciphertext[64], expect_tag[ND_AEAD_TAG_LEN];
    CHECK(nd_aead_chacha20poly1305_encrypt(key, nonce, record, header_len, inner, inner_len, expect_ciphertext,
                                            expect_tag) == ND_OK);

    CHECK(nd_bytes_eq(record + header_len, expect_ciphertext, inner_len));
    CHECK(nd_bytes_eq(record + header_len + inner_len, expect_tag, ND_AEAD_TAG_LEN));
}

/* Stage 6's hot-path pass replaced nd_record_protect's original
 * two-pass "serialize a dummy zeroed payload through nd_unified_serialize,
 * then overwrite it with the real ciphertext" approach (a wasted
 * memset+memcpy of the whole ciphertext length on every record) with a
 * direct 5-byte header write for the one fixed shape this build ever uses
 * (no CID, 16-bit sequence number, explicit length) -- see
 * src/record_protect.c's write_fixed_shape_header. That duplicates a few
 * lines of nd_unified_serialize's bit assembly, so this checks the two
 * never drift apart: for several epoch/sequence/length combinations, the
 * header nd_record_protect actually emits (record[0..5)) must equal
 * calling nd_unified_serialize directly with the equivalent
 * nd_unified_hdr. */
static void test_header_matches_nd_unified_serialize(void) {
    uint8_t key[ND_AEAD_KEY_LEN], iv[ND_AEAD_NONCE_LEN];
    fill(key, sizeof(key), 11);
    fill(iv, sizeof(iv), 12);

    struct {
        uint16_t epoch;
        uint64_t start_sequence;
        size_t plaintext_len;
    } cases[] = {
        {2, 0, 4},
        {2, 1, 100},
        {3, 65535, 1},
        {0, 300, 50},
    };

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        nd_record_protection p;
        nd_record_protection_init(&p, key, iv, cases[c].epoch);
        p.next_send_sequence = cases[c].start_sequence;

        uint8_t plaintext[128];
        fill(plaintext, cases[c].plaintext_len, (uint8_t)(c + 1));

        uint8_t record[256];
        size_t record_len;
        CHECK(nd_record_protect(&p, 22, plaintext, cases[c].plaintext_len, record, sizeof(record), &record_len) ==
              ND_OK);

        size_t ciphertext_len = cases[c].plaintext_len + 1 /* content-type byte */ + ND_AEAD_TAG_LEN;

        nd_unified_hdr hdr;
        hdr.cid_present = 0;
        hdr.cid = NULL;
        hdr.cid_len = 0;
        hdr.seq_len_is_16bit = 1;
        hdr.length_present = 1;
        hdr.epoch_low2 = (uint8_t)(cases[c].epoch & 0x3u);
        hdr.sequence_number = (uint16_t)(cases[c].start_sequence & 0xFFFFu);
        hdr.length = 0; /* ignored by nd_unified_serialize -- it derives the wire length from payload_len below */

        uint8_t expect_payload[256];
        for (size_t i = 0; i < ciphertext_len; ++i) expect_payload[i] = 0; /* content doesn't matter, only the header does */
        uint8_t expect_record[256];
        size_t expect_len;
        CHECK(nd_unified_serialize(&hdr, expect_payload, ciphertext_len, expect_record, sizeof(expect_record),
                                    &expect_len) == ND_OK);

        size_t header_len = expect_len - ciphertext_len;
        CHECK(header_len == 5);
        CHECK(nd_bytes_eq(record, expect_record, header_len));
    }
}

int main(void) {
    test_round_trip_single_record();
    test_sequence_number_advances_across_records();
    test_tampered_ciphertext_rejected_state_unchanged();
    test_wrong_epoch_rejected();
    test_nonce_and_aad_match_independent_reconstruction();
    test_header_matches_nd_unified_serialize();
    return nd_test_summary("test_protect");
}
