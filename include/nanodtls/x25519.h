#ifndef NANODTLS_X25519_H
#define NANODTLS_X25519_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ND_X25519_LEN 32u

/* X25519 (RFC 7748 section 5): the Diffie-Hellman function over Curve25519.
 * Applies the scalar clamping from section 5 internally, so `scalar` is a
 * raw 32-byte private key, not a pre-clamped one. `u_in` is the peer's
 * u-coordinate (their public key, or the fixed basepoint for
 * nd_x25519_base()). Never returns an error for the all-zero output --
 * per RFC 7748 section 6.1, callers MUST check for an all-zero shared
 * secret themselves and abort the handshake if seen (a small-order/invalid
 * point was supplied); this is a protocol-layer check, not something the
 * scalar multiplication itself can safely assume. */
nd_status nd_x25519_scalarmult(const uint8_t scalar[ND_X25519_LEN],
                                const uint8_t u_in[ND_X25519_LEN],
                                uint8_t u_out[ND_X25519_LEN]);

/* nd_x25519_scalarmult(scalar, {9, 0, 0, ..., 0}, u_out) -- derives a public
 * key from a private scalar against the standard basepoint. */
nd_status nd_x25519_base(const uint8_t scalar[ND_X25519_LEN], uint8_t u_out[ND_X25519_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_X25519_H */
