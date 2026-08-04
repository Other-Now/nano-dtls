/* A dudect-style ("Dude, is my code constant time?", Reparaz/Balasch/
 * Verbauwhede) statistical timing check for the two primitives in this
 * repo that claim constant-time behavior with respect to secret data:
 * AEAD_CHACHA20_POLY1305 (the key/plaintext must not leak through timing)
 * and X25519's scalar multiplication (the private scalar must not leak).
 * P-256 (nanodtls/p256.h) deliberately makes no such claim -- it only ever
 * handles public keys/signatures -- so it isn't tested here.
 *
 * Method: two input classes are measured in randomly-interleaved order
 * (to spread out any systematic drift -- CPU frequency scaling, cache
 * state, OS scheduling noise -- evenly across both classes rather than
 * letting it correlate with one class), using the CPU cycle counter
 * (RDTSC) rather than wall-clock time for resolution. Welch's t-test
 * compares the two classes' timing distributions; dudect's own rule of
 * thumb is that |t| > 4.5 is a strong signal of a real difference (at
 * that threshold, a difference this large virtually never arises from
 * measurement noise alone) -- i.e. evidence of a timing leak. This is a
 * necessarily weaker check than a real dudect run against, say,
 * ChaCha20-Poly1305 with hundreds of millions of samples and outlier
 * trimming; it's still a real, executed statistical test against actual
 * measured cycles, not just an assertion that the code "looks"
 * constant-time. */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <intrin.h>
static uint64_t nd_dudect_rdtsc(void) { return __rdtsc(); }
#else
static uint64_t nd_dudect_rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#endif

#include "nanodtls/aead.h"
#include "nanodtls/x25519.h"

static uint64_t rng_state = 0xC0FFEEC0FFEEULL;
static uint64_t xorshift64(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}
static void random_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; ++i) out[i] = (uint8_t)(xorshift64() & 0xffu);
}

#define N_SAMPLES 20000
#define N_SAMPLES_X25519 3000 /* X25519 scalarmult costs ~0.7ms/call; keep the total runtime reasonable */

static double welch_t_stat(const double *a, size_t na, const double *b, size_t nb) {
    double ma = 0, mb = 0;
    for (size_t i = 0; i < na; ++i) ma += a[i];
    ma /= (double)na;
    for (size_t i = 0; i < nb; ++i) mb += b[i];
    mb /= (double)nb;

    double va = 0, vb = 0;
    for (size_t i = 0; i < na; ++i) va += (a[i] - ma) * (a[i] - ma);
    va /= (double)(na - 1);
    for (size_t i = 0; i < nb; ++i) vb += (b[i] - mb) * (b[i] - mb);
    vb /= (double)(nb - 1);

    double se = sqrt(va / (double)na + vb / (double)nb);
    if (se == 0.0) return 0.0;
    return (ma - mb) / se;
}

/* Class 0: fixed all-zero key. Class 1: a fresh random key each sample.
 * Plaintext/AAD/nonce are held fixed across both classes so only the key
 * differs -- isolating whether decrypt time depends on secret key bits.
 *
 * Both classes' ciphertext+tag are pre-computed (outside the timed region)
 * with their OWN matching key, so both decrypts always succeed -- an
 * earlier version of this check reused one buffer across both classes and
 * ended up timing a successful decrypt against a mismatched-tag/ciphertext
 * *failed* one, which is expected to differ in timing (this AEAD verifies
 * the tag before decrypting, so a failure skips real work) and has nothing
 * to do with a secret-dependent leak. Caught by the reported |t| being
 * implausibly large (~57) for a supposedly-constant-time primitive, which
 * prompted rechecking the harness rather than the primitive. */
static void check_chacha20poly1305(void) {
    static double t0[N_SAMPLES], t1[N_SAMPLES];
    uint8_t nonce[ND_AEAD_NONCE_LEN] = {0};
    uint8_t aad[13] = {0};
    uint8_t plaintext[256];
    random_bytes(plaintext, sizeof(plaintext));
    uint8_t decrypted[256];

    uint8_t fixed_key[ND_AEAD_KEY_LEN] = {0};
    uint8_t fixed_ciphertext[256], fixed_tag[ND_AEAD_TAG_LEN];
    nd_aead_chacha20poly1305_encrypt(fixed_key, nonce, aad, sizeof(aad), plaintext, sizeof(plaintext),
                                      fixed_ciphertext, fixed_tag);

    for (int i = 0; i < N_SAMPLES; ++i) {
        int class1_first = (int)(xorshift64() & 1u);
        uint8_t random_key[ND_AEAD_KEY_LEN];
        random_bytes(random_key, sizeof(random_key));
        uint8_t random_ciphertext[256], random_tag[ND_AEAD_TAG_LEN];
        nd_aead_chacha20poly1305_encrypt(random_key, nonce, aad, sizeof(aad), plaintext, sizeof(plaintext),
                                          random_ciphertext, random_tag);

        if (class1_first) {
            uint64_t c0 = nd_dudect_rdtsc();
            nd_aead_chacha20poly1305_decrypt(random_key, nonce, aad, sizeof(aad), random_ciphertext,
                                              sizeof(random_ciphertext), random_tag, decrypted);
            uint64_t c1 = nd_dudect_rdtsc();
            t1[i] = (double)(c1 - c0);

            uint64_t c2 = nd_dudect_rdtsc();
            nd_aead_chacha20poly1305_decrypt(fixed_key, nonce, aad, sizeof(aad), fixed_ciphertext,
                                              sizeof(fixed_ciphertext), fixed_tag, decrypted);
            uint64_t c3 = nd_dudect_rdtsc();
            t0[i] = (double)(c3 - c2);
        } else {
            uint64_t c0 = nd_dudect_rdtsc();
            nd_aead_chacha20poly1305_decrypt(fixed_key, nonce, aad, sizeof(aad), fixed_ciphertext,
                                              sizeof(fixed_ciphertext), fixed_tag, decrypted);
            uint64_t c1 = nd_dudect_rdtsc();
            t0[i] = (double)(c1 - c0);

            uint64_t c2 = nd_dudect_rdtsc();
            nd_aead_chacha20poly1305_decrypt(random_key, nonce, aad, sizeof(aad), random_ciphertext,
                                              sizeof(random_ciphertext), random_tag, decrypted);
            uint64_t c3 = nd_dudect_rdtsc();
            t1[i] = (double)(c3 - c2);
        }
    }

    double t = welch_t_stat(t0, N_SAMPLES, t1, N_SAMPLES);
    printf("AEAD_CHACHA20_POLY1305 decrypt, fixed-key vs random-key: Welch t = %.3f  (%s)\n", t,
           (fabs(t) > 4.5) ? "POSSIBLE LEAK" : "no significant difference");
}

/* Class 0: fixed all-zero scalar. Class 1: a fresh random scalar each
 * sample. u_in is held fixed across both classes. */
static void check_x25519(void) {
    static double t0[N_SAMPLES_X25519], t1[N_SAMPLES_X25519];
    uint8_t u_in[ND_X25519_LEN] = {9, 0}; /* the standard basepoint */
    uint8_t u_out[ND_X25519_LEN];
    uint8_t fixed_scalar[ND_X25519_LEN] = {0};

    for (int i = 0; i < N_SAMPLES_X25519; ++i) {
        int class1_first = (int)(xorshift64() & 1u);
        uint8_t random_scalar[ND_X25519_LEN];
        random_bytes(random_scalar, sizeof(random_scalar));

        if (class1_first) {
            uint64_t c0 = nd_dudect_rdtsc();
            nd_x25519_scalarmult(random_scalar, u_in, u_out);
            uint64_t c1 = nd_dudect_rdtsc();
            t1[i] = (double)(c1 - c0);

            uint64_t c2 = nd_dudect_rdtsc();
            nd_x25519_scalarmult(fixed_scalar, u_in, u_out);
            uint64_t c3 = nd_dudect_rdtsc();
            t0[i] = (double)(c3 - c2);
        } else {
            uint64_t c0 = nd_dudect_rdtsc();
            nd_x25519_scalarmult(fixed_scalar, u_in, u_out);
            uint64_t c1 = nd_dudect_rdtsc();
            t0[i] = (double)(c1 - c0);

            uint64_t c2 = nd_dudect_rdtsc();
            nd_x25519_scalarmult(random_scalar, u_in, u_out);
            uint64_t c3 = nd_dudect_rdtsc();
            t1[i] = (double)(c3 - c2);
        }
    }

    double t = welch_t_stat(t0, N_SAMPLES_X25519, t1, N_SAMPLES_X25519);
    printf("X25519 scalarmult, fixed-scalar vs random-scalar: Welch t = %.3f  (%s)\n", t,
           (fabs(t) > 4.5) ? "POSSIBLE LEAK" : "no significant difference");
}

int main(void) {
    printf("dudect-style constant-time check (%d samples/class, RDTSC cycle counts)\n", N_SAMPLES);
    printf("threshold: |t| > 4.5 is dudect's conventional signal of a real timing difference\n\n");
    check_chacha20poly1305();
    check_x25519();
    return 0;
}
