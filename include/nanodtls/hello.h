#ifndef NANODTLS_HELLO_H
#define NANODTLS_HELLO_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"
#include "nanodtls/x25519.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ND_RANDOM_LEN 32u

/* nano-dtls speaks exactly one cipher suite and one key-exchange group (see
 * README "Honest scope"), so these codepoints are fixed rather than
 * negotiable -- there is nothing to select between yet. */
#define ND_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303u /* confirmed against the
                                                            * RFC 8448 ClientHello trace */
#define ND_NAMED_GROUP_X25519 0x001Du
#define ND_DTLS_1_3_VERSION 0xfefcu /* supported_versions codepoint, RFC 9147 sec 5.3 */
#define ND_DTLS_1_2_LEGACY_VERSION 0xfefdu /* legacy_version field, RFC 9147 sec 5.3 */

/* ---------------------------------------------------------------------
 * ClientHello (RFC 9147 section 5.3): the DTLS 1.3 ClientHello adds one
 * field the TLS 1.3 ClientHello doesn't have -- legacy_cookie, sitting
 * between legacy_session_id and cipher_suites -- and otherwise matches
 * RFC 8446 section 4.1.2:
 *
 *   struct {
 *       ProtocolVersion legacy_version = {254,253};       -- DTLS 1.2
 *       Random random;
 *       opaque legacy_session_id<0..32>;
 *       opaque legacy_cookie<0..2^8-1>;                    -- DTLS-only
 *       CipherSuite cipher_suites<2..2^16-2>;
 *       opaque legacy_compression_methods<1..2^8-1>;
 *       Extension extensions<8..2^16-1>;
 *   } ClientHello;
 *
 * nano-dtls always sends an empty legacy_session_id and legacy_cookie (DTLS
 * doesn't use TLS 1.3's middlebox-compatibility session-id trick, and the
 * cookie is only populated in response to a HelloRetryRequest -- not built
 * yet), one cipher suite, and four extensions: supported_versions
 * ({0xfefc}), supported_groups ({x25519}), key_share (one X25519
 * KeyShareEntry), and signature_algorithms (required by RFC 8446 to be
 * present, even though nano-dtls can't verify a certificate chain yet --
 * see PLAN.md Stage 5).
 *
 * This produces the ClientHello *body* only -- wrap it in a Handshake
 * header (nd_handshake_serialize) and then a record header
 * (nd_plaintext_serialize) to get an on-wire flight.
 * --------------------------------------------------------------------- */

typedef struct nd_client_hello_params {
    uint8_t random[ND_RANDOM_LEN];
    uint8_t x25519_public_key[ND_X25519_LEN]; /* our key share to offer */
} nd_client_hello_params;

nd_status nd_client_hello_serialize(const nd_client_hello_params *params, uint8_t *out_buf,
                                     size_t out_buf_cap, size_t *out_len);

/* Parses a ClientHello, the server-role mirror of nd_server_hello_parse:
 * extracts the random (for the transcript/key schedule) and the peer's
 * X25519 public key from the mandatory key_share extension. Like
 * nd_server_hello_parse, returns ND_ERR_UNSUPPORTED (not a parse failure)
 * for any syntactically valid ClientHello this minimal one-suite/one-group
 * server doesn't handle: cipher_suites not offering
 * TLS_CHACHA20_POLY1305_SHA256, supported_versions missing or not offering
 * DTLS 1.3, or key_share missing/not X25519. legacy_cookie and
 * legacy_session_id are read past (RFC 9147: DTLS's cookie exchange for
 * HelloRetryRequest isn't implemented, so any cookie value is ignored
 * rather than validated) but not returned -- nothing downstream of this
 * minimal server needs them. */
typedef struct nd_client_hello {
    uint8_t random[ND_RANDOM_LEN];
    uint8_t x25519_public_key[ND_X25519_LEN];
} nd_client_hello;

nd_status nd_client_hello_parse(const uint8_t *buf, size_t buf_len, nd_client_hello *out_hello);

/* ---------------------------------------------------------------------
 * ServerHello (RFC 9147 section 5.3): identical to the TLS 1.3 ServerHello
 * (RFC 8446 section 4.1.3) except legacy_version = {254,253}. Parsing
 * extracts exactly what a minimal one-suite/one-group client needs for the
 * key schedule: the random (goes into the transcript hash, not used
 * directly here), the negotiated cipher suite, the selected_version from
 * the mandatory supported_versions extension, and the peer's X25519 public
 * key from the mandatory key_share extension. Anything else in the
 * extensions list is ignored.
 *
 * Returns ND_ERR_UNSUPPORTED (not a parse failure) if supported_versions or
 * key_share is missing, if the selected version isn't DTLS 1.3, or if the
 * key_share group isn't X25519 or its key isn't 32 bytes -- all
 * syntactically valid outcomes this minimal build just doesn't handle.
 * --------------------------------------------------------------------- */

typedef struct nd_server_hello {
    uint8_t random[ND_RANDOM_LEN];
    uint16_t cipher_suite;
    uint16_t selected_version;
    uint8_t key_share[ND_X25519_LEN];
} nd_server_hello;

nd_status nd_server_hello_parse(const uint8_t *buf, size_t buf_len, nd_server_hello *out_hello);

/* Serializes a ServerHello with nano-dtls's fixed cipher suite, selected
 * version (DTLS 1.3), and a single X25519 KeyShareServerHello -- the mirror
 * of nd_client_hello_serialize, built primarily so tests (and, later, a
 * server role) don't need to hand-construct wire bytes. There is no
 * server-role state machine yet; this only produces the message body. */
typedef struct nd_server_hello_params {
    uint8_t random[ND_RANDOM_LEN];
    uint8_t x25519_public_key[ND_X25519_LEN];
} nd_server_hello_params;

nd_status nd_server_hello_serialize(const nd_server_hello_params *params, uint8_t *out_buf,
                                     size_t out_buf_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_HELLO_H */
