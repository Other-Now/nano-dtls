/* Runs a subset of nano-dtls's actual crypto (SHA-256, HMAC-SHA256, HKDF,
 * AEAD_CHACHA20_POLY1305, X25519) on bare-metal Cortex-M3 under QEMU, with
 * zero heap allocation and zero libc beyond the three <string.h> functions
 * this repo provides its own freestanding implementations of (see
 * freestanding_stubs.c) -- proof the crypto has no hidden OS/malloc/libc
 * dependency, not a re-proof of protocol correctness (that's what the
 * host-side test suite's real RFC KATs already do exhaustively). Checks
 * here are self-consistency properties (determinism, round-trip agreement,
 * tamper detection) rather than hardcoded hex constants, so nothing here
 * risks a hand-transcription error the way a copied KAT could. */
#include "nanodtls/aead.h"
#include "nanodtls/hkdf.h"
#include "nanodtls/hmac_sha256.h"
#include "nanodtls/sha256.h"
#include "nanodtls/x25519.h"
#include "uart.h"

static int g_checks = 0;
static int g_failures = 0;

static void check(int cond, const char *label) {
    g_checks++;
    if (!cond) {
        g_failures++;
        uart_puts("  FAIL: ");
        uart_puts(label);
        uart_puts("\n");
    } else {
        uart_puts("  ok:   ");
        uart_puts(label);
        uart_puts("\n");
    }
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (a[i] != b[i]) return 0;
    return 1;
}

static void put_dec(int v) {
    char buf[12];
    int i = 11;
    buf[i--] = '\0';
    if (v == 0) {
        buf[i--] = '0';
    } else {
        while (v > 0 && i >= 0) {
            buf[i--] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    uart_puts(&buf[i + 1]);
}

int main(void) {
    uart_puts("\n=== nano-dtls bare-metal Cortex-M3 (QEMU lm3s6965evb) crypto smoke test ===\n");

    /* SHA-256: deterministic, and sensitive to its input (a basic sanity
     * check, not a security property) */
    uint8_t msg1[] = "nano-dtls embedded smoke test";
    uint8_t h1[32], h2[32], h3[32];
    nd_sha256(msg1, sizeof(msg1) - 1, h1);
    nd_sha256(msg1, sizeof(msg1) - 1, h2);
    check(bytes_eq(h1, h2, 32), "SHA-256 deterministic");

    uint8_t msg2[sizeof(msg1)];
    for (size_t i = 0; i < sizeof(msg1); ++i) msg2[i] = msg1[i];
    msg2[0] ^= 1;
    nd_sha256(msg2, sizeof(msg2) - 1, h3);
    check(!bytes_eq(h1, h3, 32), "SHA-256 sensitive to input");

    /* AEAD_CHACHA20_POLY1305: round-trip, and tamper detection */
    uint8_t key[ND_AEAD_KEY_LEN];
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)i;
    uint8_t nonce[ND_AEAD_NONCE_LEN];
    for (size_t i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(i * 3);
    uint8_t aad[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t plaintext[64];
    for (size_t i = 0; i < sizeof(plaintext); ++i) plaintext[i] = (uint8_t)(i * 7);
    uint8_t ciphertext[64], tag[ND_AEAD_TAG_LEN], decrypted[64];

    nd_aead_chacha20poly1305_encrypt(key, nonce, aad, sizeof(aad), plaintext, sizeof(plaintext), ciphertext, tag);
    nd_status st = nd_aead_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad), ciphertext, sizeof(ciphertext), tag,
                                                     decrypted);
    check(st == ND_OK, "AEAD decrypt succeeds with correct tag");
    check(bytes_eq(plaintext, decrypted, sizeof(plaintext)), "AEAD round-trip recovers plaintext");

    tag[0] ^= 1;
    st = nd_aead_chacha20poly1305_decrypt(key, nonce, aad, sizeof(aad), ciphertext, sizeof(ciphertext), tag,
                                           decrypted);
    check(st == ND_ERR_AUTH_FAILED, "AEAD rejects a tampered tag");

    /* X25519: an independent Alice/Bob key exchange lands on the same
     * shared secret from both directions (the strongest available check
     * without embedding a hex constant here). */
    uint8_t alice_priv[ND_X25519_LEN], bob_priv[ND_X25519_LEN];
    for (size_t i = 0; i < ND_X25519_LEN; ++i) {
        alice_priv[i] = (uint8_t)(i + 1);
        bob_priv[i] = (uint8_t)(255 - i);
    }
    uint8_t alice_pub[ND_X25519_LEN], bob_pub[ND_X25519_LEN];
    nd_x25519_base(alice_priv, alice_pub);
    nd_x25519_base(bob_priv, bob_pub);
    uint8_t shared1[ND_X25519_LEN], shared2[ND_X25519_LEN];
    nd_x25519_scalarmult(alice_priv, bob_pub, shared1);
    nd_x25519_scalarmult(bob_priv, alice_pub, shared2);
    check(bytes_eq(shared1, shared2, ND_X25519_LEN), "X25519 DH agreement (Alice == Bob)");

    /* HKDF-Extract: deterministic for the same inputs */
    uint8_t prk1[ND_HASH_LEN], prk2[ND_HASH_LEN];
    nd_hkdf_extract(NULL, 0, key, sizeof(key), prk1);
    nd_hkdf_extract(NULL, 0, key, sizeof(key), prk2);
    check(bytes_eq(prk1, prk2, ND_HASH_LEN), "HKDF-Extract deterministic");

    uart_puts("\n=== ");
    put_dec(g_checks);
    uart_puts(" checks, ");
    put_dec(g_failures);
    uart_puts(" failures ===\n");
    uart_puts(g_failures == 0 ? "RESULT: PASS\n" : "RESULT: FAIL\n");

    while (1) {
    }
    return 0;
}
