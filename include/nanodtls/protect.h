#ifndef NANODTLS_PROTECT_H
#define NANODTLS_PROTECT_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/aead.h"
#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * Applies AEAD_CHACHA20_POLY1305 to DTLS 1.3 unified-header records (RFC
 * 9147 section 4, section 4.5; nonce/AAD construction per RFC 8446 section
 * 5.3 as referenced by RFC 9147). Per-record nonce = write_iv XOR the
 * 64-bit sequence_number (RFC 9147: unlike DTLS 1.2, the epoch is NOT
 * folded into the nonce -- each epoch already has its own derived
 * key/IV). AAD = the unified header bytes exactly as they appear on the
 * wire.
 *
 * Known, documented scope gap: this does NOT implement DTLS 1.3's record
 * number encryption (RFC 9147 section 4.2.3, an additional keystream-based
 * obfuscation of the on-wire sequence-number bits, conceptually similar to
 * QUIC header protection). Sequence numbers travel in the clear inside the
 * unified header. See README "Honest scope".
 * --------------------------------------------------------------------- */

#define ND_RECORD_PROTECT_MAX_INNER 2048u /* plaintext + 1-byte content type; generous for this build's messages */

typedef struct nd_record_protection {
    uint8_t write_key[ND_AEAD_KEY_LEN];
    uint8_t write_iv[ND_AEAD_NONCE_LEN];
    uint64_t next_send_sequence;
    uint16_t epoch;
} nd_record_protection;

typedef struct nd_record_unprotection {
    uint8_t read_key[ND_AEAD_KEY_LEN];
    uint8_t read_iv[ND_AEAD_NONCE_LEN];
    uint64_t highest_seen_sequence;
    uint16_t epoch;
} nd_record_unprotection;

void nd_record_protection_init(nd_record_protection *p, const uint8_t key[ND_AEAD_KEY_LEN],
                                const uint8_t iv[ND_AEAD_NONCE_LEN], uint16_t epoch);
void nd_record_unprotection_init(nd_record_unprotection *u, const uint8_t key[ND_AEAD_KEY_LEN],
                                  const uint8_t iv[ND_AEAD_NONCE_LEN], uint16_t epoch);

/* Wraps plaintext[0..plaintext_len) with content_type into a DTLSInnerPlaintext
 * (RFC 8446 section 5.2: content || content_type; this build never adds the
 * optional zero padding), encrypts it, and serializes a full unified-header
 * record into out_buf. Always sends a 16-bit sequence number and an
 * explicit length (simplest correct choice; RFC 9147 permits the more
 * compact 8-bit/implicit-length forms as an optimization this build doesn't
 * need). Advances p->next_send_sequence on success. */
nd_status nd_record_protect(nd_record_protection *p, uint8_t content_type, const uint8_t *plaintext,
                             size_t plaintext_len, uint8_t *out_buf, size_t out_buf_cap, size_t *out_len);

/* Parses one unified-header record from buf, reconstructs its full
 * epoch/sequence number, decrypts, and strips the DTLSInnerPlaintext
 * content-type trailer. Returns ND_ERR_UNSUPPORTED if the record's
 * reconstructed epoch doesn't match u->epoch (key/epoch updates aren't
 * implemented). On ND_ERR_AUTH_FAILED, u->highest_seen_sequence is left
 * untouched -- an unauthenticated record must not perturb replay-window
 * state (Stage 4 territory, but this layer already keeps that invariant). */
nd_status nd_record_unprotect(nd_record_unprotection *u, const uint8_t *buf, size_t buf_len, uint8_t *plaintext_out,
                               size_t plaintext_cap, size_t *plaintext_len, uint8_t *out_content_type);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_PROTECT_H */
