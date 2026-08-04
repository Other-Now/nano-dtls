#ifndef NANODTLS_KEY_SCHEDULE_H
#define NANODTLS_KEY_SCHEDULE_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/aead.h"
#include "nanodtls/hkdf.h"
#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * The (D)TLS 1.3 key schedule (RFC 8446 section 7.1), the no-PSK path
 * through Early Secret -> Handshake Secret -> the two handshake traffic
 * secrets -> per-direction write key/IV:
 *
 *   0 -> HKDF-Extract = Early Secret
 *          |
 *          v
 *   Derive-Secret(., "derived", "")
 *          |
 *          v
 *   (EC)DHE -> HKDF-Extract = Handshake Secret
 *          |
 *          +--> Derive-Secret(., "c hs traffic", Transcript-Hash(CH..SH))
 *          |                 = client_handshake_traffic_secret
 *          +--> Derive-Secret(., "s hs traffic", Transcript-Hash(CH..SH))
 *                            = server_handshake_traffic_secret
 *
 * label_prefix is an explicit, required argument -- exactly like
 * nd_hkdf_expand_label -- rather than something this function silently
 * defaults, because that silent default is precisely the Stage 2 bug this
 * project already shipped and fixed once (see PLAN.md Stage 3 / README):
 * DTLS 1.3 real traffic keys MUST use ND_HKDF_LABEL_PREFIX_DTLS13. Passing
 * ND_HKDF_LABEL_PREFIX_TLS13 only makes sense for testing against RFC 8448,
 * which is a genuine TLS 1.3 trace.
 *
 * write_key/write_iv are sized for nano-dtls's one cipher suite
 * (AEAD_CHACHA20_POLY1305: 32-byte key, 12-byte IV, see nanodtls/aead.h).
 * --------------------------------------------------------------------- */

typedef struct nd_handshake_keys {
    uint8_t handshake_secret[ND_HASH_LEN];               /* kept for the eventual Master Secret */
    uint8_t client_handshake_traffic_secret[ND_HASH_LEN]; /* also the Finished "base key" */
    uint8_t server_handshake_traffic_secret[ND_HASH_LEN];
    uint8_t client_write_key[ND_AEAD_KEY_LEN];
    uint8_t client_write_iv[ND_AEAD_NONCE_LEN];
    uint8_t server_write_key[ND_AEAD_KEY_LEN];
    uint8_t server_write_iv[ND_AEAD_NONCE_LEN];
} nd_handshake_keys;

/* shared_secret: the raw X25519 output (nd_x25519_scalarmult's u_out).
 * hello_transcript_hash: Transcript-Hash(ClientHello .. ServerHello), i.e.
 * nd_transcript_snapshot() after adding both hello messages. */
nd_status nd_derive_handshake_keys(const char *label_prefix,
                                    const uint8_t shared_secret[ND_HASH_LEN],
                                    const uint8_t hello_transcript_hash[ND_HASH_LEN],
                                    nd_handshake_keys *out_keys);

/* ---------------------------------------------------------------------
 * Finished (RFC 8446 section 4.4.4):
 *   finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
 *   verify_data  = HMAC(finished_key, Transcript-Hash(Handshake Context))
 *
 * BaseKey is client_handshake_traffic_secret for the client's Finished, or
 * server_handshake_traffic_secret for the server's -- whichever side is
 * finishing. transcript_hash is the hash of every handshake message up to
 * (but not including) this Finished itself.
 * --------------------------------------------------------------------- */

nd_status nd_finished_compute(const char *label_prefix, const uint8_t base_key[ND_HASH_LEN],
                               const uint8_t transcript_hash[ND_HASH_LEN],
                               uint8_t out_verify_data[ND_HASH_LEN]);

/* Constant-time-compares against a freshly computed verify_data. Returns
 * ND_ERR_AUTH_FAILED (not ND_ERR_BAD_ARG) on mismatch -- this is an
 * authentication check, the same distinction nd_aead_*_decrypt makes. */
nd_status nd_finished_verify(const char *label_prefix, const uint8_t base_key[ND_HASH_LEN],
                              const uint8_t transcript_hash[ND_HASH_LEN],
                              const uint8_t received_verify_data[ND_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_KEY_SCHEDULE_H */
