#ifndef ND_TOOLS_P256_SIGN_DEMO_H
#define ND_TOOLS_P256_SIGN_DEMO_H
/* Demo-grade ECDSA-P256-SHA256 signing -- deliberately NOT part of the
 * nanodtls library (contrast with nanodtls/p256.h, which is verify-only;
 * see that header for why). Exists only so this repo's own demo/interop
 * server (tools/dtls_server_demo.c) has something to sign a
 * CertificateVerify with, via the nd_sign_fn callback nanodtls/server.h
 * defines -- a real integration would plug in an HSM or OS keystore there
 * instead of this.
 *
 * Two things make this explicitly not production-grade, beyond "not
 * constant-time" (which nanodtls/p256.h already flags for the verify-only
 * arithmetic this reuses):
 *   1. The per-signature nonce k comes from an OS CSPRNG
 *      (nanodtls/random.h), not RFC 6979 deterministic derivation -- a
 *      real signer should prefer deterministic k to remove "what if the
 *      RNG is bad this one time" from the risk surface entirely.
 *   2. It reuses src/crypto/p256_internal.h's point/bignum arithmetic,
 *      which was written and is exercised for PUBLIC verification --
 *      k*G here operates on a value (k) that guards a real private key,
 *      through non-constant-time double-and-add. A real signer needs
 *      side-channel-hardened scalar multiplication this repo doesn't
 *      provide.
 * See README "Honest scope". */
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* privkey_d: raw 32-byte big-endian P-256 private scalar.
 * hash: SHA-256(message) to sign.
 * Retries internally (bounded) if a drawn nonce yields r=0 or s=0 --
 * astronomically unlikely, standard ECDSA hygiene. */
nd_status nd_demo_p256_ecdsa_sign(const uint8_t privkey_d[32], const uint8_t hash[32], uint8_t out_r[32],
                                   uint8_t out_s[32]);

#ifdef __cplusplus
}
#endif

#endif /* ND_TOOLS_P256_SIGN_DEMO_H */
