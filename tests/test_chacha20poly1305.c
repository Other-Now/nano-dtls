/* ChaCha20 / Poly1305 / AEAD_CHACHA20_POLY1305 known-answer tests, all three
 * vectors quoted from RFC 8439: section 2.3.2 (block function), section
 * 2.5.2 (Poly1305 MAC), section 2.8.2 (the "Sunscreen" AEAD example). */
#include "nanodtls/aead.h"
#include "nanodtls/chacha20.h"
#include "nanodtls/poly1305.h"
#include "test_util.h"

static void test_chacha20_block(void) {
    uint8_t key[32];
    CHECK(nd_hex_decode("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f "
                        "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
                        key, sizeof(key)) == 32);
    uint8_t nonce[12];
    CHECK(nd_hex_decode("00 00 00 09 00 00 00 4a 00 00 00 00", nonce, sizeof(nonce)) == 12);

    uint8_t expected[64];
    CHECK(nd_hex_decode("10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4"
                        "c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e"
                        "d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2"
                        "b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e",
                        expected, sizeof(expected)) == 64);

    uint8_t got[64];
    nd_chacha20_block(key, nonce, 1, got);
    CHECK(nd_bytes_eq(got, expected, sizeof(got)));
}

static void test_poly1305_mac(void) {
    uint8_t key[32];
    CHECK(nd_hex_decode("85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 "
                        "01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b",
                        key, sizeof(key)) == 32);

    /* "Cryptographic Forum Research Group", 34 bytes -- decoded from the
     * RFC's own hex dump rather than an ASCII literal + hand-counted
     * length, so the byte count can't drift from what's actually tested. */
    uint8_t msg[34];
    CHECK(nd_hex_decode("43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f 72 75 6d 20"
                        "52 65 73 65 61 72 63 68 20 47 72 6f 75 70",
                        msg, sizeof(msg)) == 34);

    uint8_t expected[16];
    CHECK(nd_hex_decode("a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9", expected,
                        sizeof(expected)) == 16);

    uint8_t got[16];
    nd_poly1305_mac(key, msg, sizeof(msg), got);
    CHECK(nd_bytes_eq(got, expected, sizeof(expected)));
}

static void test_aead_sunscreen(void) {
    uint8_t plaintext[114];
    CHECK(nd_hex_decode("4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c 65 6d 65 6e 20 6f 66 20 74"
                        "68 65 20 63 6c 61 73 73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63 6f 75"
                        "6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f 6e 6c 79 20 6f 6e 65 20 74 69 70"
                        "20 66 6f 72 20 74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73 63 72 65 65"
                        "6e 20 77 6f 75 6c 64 20 62 65 20 69 74 2e",
                        plaintext, sizeof(plaintext)) == 114);

    uint8_t aad[12];
    CHECK(nd_hex_decode("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7", aad, sizeof(aad)) == 12);

    uint8_t key[32];
    CHECK(nd_hex_decode("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f "
                        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f",
                        key, sizeof(key)) == 32);

    /* nonce = constant (07 00 00 00) || iv (40 41 42 43 44 45 46 47), per
     * RFC 8439 section 2.8.2. */
    uint8_t nonce[12];
    CHECK(nd_hex_decode("07 00 00 00 40 41 42 43 44 45 46 47", nonce, sizeof(nonce)) == 12);

    uint8_t expected_ct[114];
    CHECK(nd_hex_decode("d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
                        "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
                        "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
                        "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
                        "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
                        "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
                        "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
                        "61 16",
                        expected_ct, sizeof(expected_ct)) == 114);

    uint8_t expected_tag[16];
    CHECK(nd_hex_decode("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91", expected_tag,
                        sizeof(expected_tag)) == 16);

    uint8_t ciphertext[114];
    uint8_t tag[16];
    CHECK(nd_aead_chacha20poly1305_encrypt(key, nonce, aad, sizeof(aad), plaintext,
                                           sizeof(plaintext), ciphertext, tag) == ND_OK);
    CHECK(nd_bytes_eq(ciphertext, expected_ct, sizeof(expected_ct)));
    CHECK(nd_bytes_eq(tag, expected_tag, sizeof(expected_tag)));

    /* Round-trip: decrypt should recover the exact plaintext and verify. */
    uint8_t recovered[114];
    CHECK(nd_aead_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad), ciphertext,
                                           sizeof(ciphertext), tag, recovered) == ND_OK);
    CHECK(nd_bytes_eq(recovered, plaintext, sizeof(plaintext)));

    /* A flipped ciphertext byte must fail authentication and must NOT
     * silently produce plaintext -- the entire point of an AEAD. */
    uint8_t tampered[114];
    for (size_t i = 0; i < sizeof(tampered); ++i) tampered[i] = ciphertext[i];
    tampered[0] ^= 0x01;
    uint8_t decrypt_out[114] = {0};
    CHECK(nd_aead_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad), tampered,
                                           sizeof(tampered), tag, decrypt_out) ==
          ND_ERR_AUTH_FAILED);

    /* A flipped tag byte must also fail. */
    uint8_t bad_tag[16];
    for (size_t i = 0; i < 16; ++i) bad_tag[i] = tag[i];
    bad_tag[0] ^= 0x01;
    CHECK(nd_aead_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad), ciphertext,
                                           sizeof(ciphertext), bad_tag, decrypt_out) ==
          ND_ERR_AUTH_FAILED);
}

static void test_aead_empty_plaintext_and_aad(void) {
    /* Edge case none of the RFC vectors exercise: zero-length AAD and
     * zero-length plaintext (a bare "authenticate nothing" call). Confirms
     * the length-prefixed MAC trailer and the streaming Poly1305 buffer
     * flush both behave when there's genuinely no data. */
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[16];
    CHECK(nd_aead_chacha20poly1305_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, tag) == ND_OK);

    uint8_t tag2[16];
    CHECK(nd_aead_chacha20poly1305_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, tag2) == ND_OK);
    CHECK(nd_bytes_eq(tag, tag2, 16)); /* deterministic for the same key/nonce */

    CHECK(nd_aead_chacha20poly1305_decrypt(key, nonce, NULL, 0, NULL, 0, tag, NULL) == ND_OK);
}

int main(void) {
    test_chacha20_block();
    test_poly1305_mac();
    test_aead_sunscreen();
    test_aead_empty_plaintext_and_aad();
    return nd_test_summary("test_chacha20poly1305");
}
