#ifndef NANODTLS_TRANSCRIPT_H
#define NANODTLS_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/hkdf.h"
#include "nanodtls/sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The TLS 1.3 / DTLS 1.3 "Transcript-Hash" (RFC 8446 section 4.4.1) is just
 * a running SHA-256 over every handshake message's bytes, in order --
 * ClientHello, then ServerHello, then EncryptedExtensions, and so on. The
 * key schedule needs the hash-so-far at several different points in that
 * sequence (Derive-Secret(..., "c hs traffic", Transcript-Hash(CH..SH)),
 * then later Derive-Secret(..., "c ap traffic", Transcript-Hash(CH..SF)),
 * etc.), so this wraps nd_sha256_ctx with a non-destructive snapshot: you
 * can ask for the hash so far without ending the ability to add more
 * messages afterward. */
typedef struct nd_transcript {
    nd_sha256_ctx ctx;
} nd_transcript;

void nd_transcript_init(nd_transcript *t);

/* Adds one handshake message's raw bytes (the Handshake-header-wrapped
 * message, i.e. what nd_handshake_serialize/nd_client_hello_serialize
 * produce concatenated) to the running hash. */
void nd_transcript_add(nd_transcript *t, const uint8_t *msg, size_t msg_len);

/* Writes SHA-256(messages added so far) to out_hash without disturbing t --
 * more messages can be added afterward and hashed as if this call never
 * happened. */
void nd_transcript_snapshot(const nd_transcript *t, uint8_t out_hash[ND_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_TRANSCRIPT_H */
