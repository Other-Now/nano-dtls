#ifndef NANODTLS_MESSAGES_H
#define NANODTLS_MESSAGES_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/hkdf.h"
#include "nanodtls/p256.h"
#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * The three handshake message bodies between ServerHello and Finished
 * (RFC 8446 sections 4.3.1, 4.4.2, 4.4.3; unchanged by DTLS 1.3 per RFC 9147
 * section 5.2, which only wraps the same TLS 1.3 messages in DTLS framing).
 * nano-dtls only ever verifies a peer's CertificateVerify -- it has no
 * private key and never authenticates itself with a certificate, so there
 * is no serialize/sign side for CertificateVerify here (see nanodtls/p256.h,
 * nanodtls/x509.h: nothing in this repo's PKI code performs a private-key
 * operation).
 * --------------------------------------------------------------------- */

/* EncryptedExtensions (RFC 8446 section 4.3.1): nano-dtls sends and expects
 * an empty extensions list -- its ClientHello offers nothing (beyond the
 * mandatory ones already handled in ServerHello) that would provoke a
 * server response here. */
nd_status nd_encrypted_extensions_serialize(uint8_t *out_buf, size_t out_buf_cap, size_t *out_len);
/* Validates structure only; any extensions present are ignored (same
 * "accept but don't act on" posture as signature_algorithms in ClientHello). */
nd_status nd_encrypted_extensions_parse(const uint8_t *buf, size_t buf_len);

/* Certificate (RFC 8446 section 4.4.2): certificate_request_context is
 * always empty on the wire (client-certificate auth, which would echo a
 * CertificateRequest's context, isn't implemented). Each CertificateEntry's
 * per-entry extensions are always empty too. */
#define ND_CERTIFICATE_MSG_MAX_CERTS 4u

typedef struct nd_certificate_msg {
    const uint8_t *cert_der[ND_CERTIFICATE_MSG_MAX_CERTS]; /* zero-copy, each one DER certificate */
    size_t cert_der_len[ND_CERTIFICATE_MSG_MAX_CERTS];
    size_t cert_count;
} nd_certificate_msg;

nd_status nd_certificate_serialize(const nd_certificate_msg *msg, uint8_t *out_buf, size_t out_buf_cap,
                                    size_t *out_len);
/* Returns ND_ERR_UNSUPPORTED if the wire chain has more than
 * ND_CERTIFICATE_MSG_MAX_CERTS entries. */
nd_status nd_certificate_parse(const uint8_t *buf, size_t buf_len, nd_certificate_msg *out_msg);

/* CertificateVerify (RFC 8446 section 4.4.3). nano-dtls implements exactly
 * one SignatureScheme, matching its one-cipher-suite/one-group posture
 * elsewhere: ecdsa_secp256r1_sha256. */
#define ND_SIGSCHEME_ECDSA_SECP256R1_SHA256 0x0403u

typedef struct nd_certificate_verify_msg {
    uint16_t algorithm;
    const uint8_t *signature; /* zero-copy: DER ECDSA-Sig-Value, SEQUENCE{INTEGER r, INTEGER s} */
    size_t signature_len;
} nd_certificate_verify_msg;

nd_status nd_certificate_verify_parse(const uint8_t *buf, size_t buf_len, nd_certificate_verify_msg *out_msg);

#define ND_CERT_VERIFY_CONTEXT_SERVER "TLS 1.3, server CertificateVerify"
#define ND_CERT_VERIFY_CONTEXT_CLIENT "TLS 1.3, client CertificateVerify"
/* 64 octets of 0x20 + a context string (33 bytes: "TLS 1.3, server/client
 * CertificateVerify") + one separator byte + a SHA-256 transcript hash --
 * rounded up by one byte of slack rather than hand-trusting the exact
 * strlen() here. */
#define ND_CERT_VERIFY_CONTENT_MAX (64u + 34u + 1u + ND_HASH_LEN)

/* Builds the exact content that CertificateVerify's signature covers (RFC
 * 8446 section 4.4.3): 64 bytes of 0x20, then context_string's bytes, then
 * a single 0x00 separator byte, then transcript_hash. Pass
 * ND_CERT_VERIFY_CONTEXT_SERVER/_CLIENT depending on which side is
 * finishing -- there is no default, same reasoning as this repo's HKDF
 * label_prefix parameter (see nanodtls/hkdf.h). */
nd_status nd_certificate_verify_content(const char *context_string, const uint8_t transcript_hash[ND_HASH_LEN],
                                         uint8_t *out_buf, size_t out_buf_cap, size_t *out_len);

/* Verifies msg's signature covers transcript_hash under context_string,
 * using the peer's P-256 public key (from nd_x509_parse'd leaf cert).
 * Returns ND_ERR_UNSUPPORTED for any algorithm other than
 * ecdsa_secp256r1_sha256, ND_ERR_AUTH_FAILED for a well-formed but invalid
 * signature. */
nd_status nd_certificate_verify_check(const nd_certificate_verify_msg *msg, const char *context_string,
                                       const uint8_t transcript_hash[ND_HASH_LEN],
                                       const uint8_t peer_qx[ND_P256_COORD_LEN],
                                       const uint8_t peer_qy[ND_P256_COORD_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_MESSAGES_H */
