#ifndef NANODTLS_P256_H
#define NANODTLS_P256_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ND_P256_COORD_LEN 32u
#define ND_P256_SCALAR_LEN 32u

/* ---------------------------------------------------------------------
 * ECDSA-P256-SHA256 signature verification (FIPS 186-4 section 6.4 / SEC1),
 * built for Stage 5 (X.509 CertificateVerify and certificate-chain
 * signature checks). Every input here is public: a peer's public key, a
 * message hash, and a signature someone else produced. There is no secret
 * scalar on this path (nano-dtls never holds a P-256 private key), so --
 * unlike X25519/ChaCha20/Poly1305 elsewhere in this repo -- this
 * implementation makes NO constant-time claim. Double-and-add scalar
 * multiplication and data-dependent branches are fine here specifically
 * because nothing processed is secret; see README "Honest scope".
 *
 * The field/scalar arithmetic underneath (src/crypto/p256.c) intentionally
 * favors a simple, obviously-correct binary long-division reduction over a
 * hand-derived NIST fast-reduction formula: this is verification-only code,
 * off nano-dtls's Stage 6 hot path, so correctness-by-inspection wins over
 * speed. Domain parameters (p, a, b, n, G) are machine-generated from
 * `openssl ecparam -name prime256v1 -param_enc explicit -text` rather than
 * hand-transcribed, for the same reason.
 * --------------------------------------------------------------------- */

/* qx/qy: the peer's public key, uncompressed point coordinates (the 32-byte
 * X and Y that follow the leading 0x04 in a SubjectPublicKeyInfo BIT
 * STRING), big-endian.
 * hash: SHA-256(message) -- the caller hashes; this only does curve math.
 * r, s: the raw ECDSA-Sig-Value integers, each big-endian and left-padded
 * to exactly 32 bytes (nd_asn1's DER INTEGER reader strips any DER sign
 * byte and left-pads before calling this).
 * Returns ND_OK if the signature verifies, ND_ERR_AUTH_FAILED otherwise
 * (bad r/s range, invalid point, or a genuine mismatch) -- never a parse
 * error, since every input here is a fixed-size buffer already validated
 * by the caller's DER parse. */
nd_status nd_p256_ecdsa_verify(const uint8_t qx[ND_P256_COORD_LEN], const uint8_t qy[ND_P256_COORD_LEN],
                                const uint8_t hash[32], const uint8_t r[ND_P256_SCALAR_LEN],
                                const uint8_t s[ND_P256_SCALAR_LEN]);

/* Returns ND_OK iff (qx, qy) is a point actually on the P-256 curve (and in
 * field range) -- an invalid-curve-attack guard callers should run on any
 * SubjectPublicKeyInfo key before trusting it for verification. */
nd_status nd_p256_point_is_valid(const uint8_t qx[ND_P256_COORD_LEN], const uint8_t qy[ND_P256_COORD_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_P256_H */
