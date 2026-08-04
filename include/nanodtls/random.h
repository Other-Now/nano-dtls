#ifndef NANODTLS_RANDOM_H
#define NANODTLS_RANDOM_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OS CSPRNG (BCryptGenRandom on Windows, /dev/urandom on POSIX). Used for
 * the per-connection ephemeral values every DTLS role needs regardless of
 * long-term identity: ClientHello/ServerHello Random, and the client's
 * ephemeral X25519 private scalar. This is NOT the same category of
 * operation this repo draws a line around in nanodtls/p256.h/x509.h (no
 * long-term private-key custody, no signing) -- generating a fresh
 * ephemeral key for one connection is ordinary, required client/server
 * behavior, not the kind of secret-key operation this repo otherwise keeps
 * out of the shipped library (see tools/p256_sign_demo.h for that
 * boundary). */
nd_status nd_random_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_RANDOM_H */
