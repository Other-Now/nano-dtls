#ifndef NANODTLS_X509_H
#define NANODTLS_X509_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/p256.h"
#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * A minimal X.509v3 certificate parser and chain verifier (RFC 5280), for
 * Stage 5's PKI touch: enough to check that a DTLS peer's Certificate
 * message chains to a trusted root. Deliberately, explicitly NOT a general
 * X.509 implementation -- see README "Honest scope":
 *
 *   - ECDSA-P256-SHA256 only. No RSA, no Ed25519, no other curve.
 *   - Name comparison is raw DER byte equality between an issuer field and
 *     the signer's subject field -- not RFC 5280's string-preparation/
 *     case-folding comparison rules. Fine for chains built by one CA tool
 *     (e.g. openssl) issuing consistently-encoded names; not a general
 *     Name-matching implementation.
 *   - No hostname/SAN matching, no policy constraints, no path-length
 *     constraint enforcement, no CRL/OCSP revocation checking.
 *   - basicConstraints cA is read (best-effort: false if the extension is
 *     simply absent, matching RFC 5280's default) and enforced for every
 *     signer in a verified chain; other extensions are parsed only far
 *     enough to skip over them.
 *
 * As with nanodtls/p256.h: nothing on this path handles a secret (there is
 * no private-key operation here at all), so there is no constant-time
 * claim -- correctness and readability are what matter for PKI code.
 * --------------------------------------------------------------------- */

typedef struct nd_x509_cert {
    const uint8_t *tbs_der; /* whole TBSCertificate TLV, zero-copy into the caller's DER buffer --
                              * exactly the bytes the signature covers */
    size_t tbs_der_len;
    const uint8_t *issuer_der; /* whole issuer Name TLV, zero-copy */
    size_t issuer_der_len;
    const uint8_t *subject_der; /* whole subject Name TLV, zero-copy */
    size_t subject_der_len;
    uint64_t not_before; /* canonical UTC YYYYMMDDHHMMSS, e.g. 20260804052052 */
    uint64_t not_after;
    uint8_t pubkey_qx[ND_P256_COORD_LEN];
    uint8_t pubkey_qy[ND_P256_COORD_LEN];
    int is_ca; /* basicConstraints cA (default false if the extension is absent) */
    uint8_t sig_r[ND_P256_SCALAR_LEN];
    uint8_t sig_s[ND_P256_SCALAR_LEN];
} nd_x509_cert;

/* Parses one DER-encoded X.509v3 certificate. Returns ND_ERR_UNSUPPORTED
 * for a well-formed certificate this minimal build doesn't handle (RSA
 * key/signature, a curve other than P-256, a compressed EC point). */
nd_status nd_x509_parse(const uint8_t *der, size_t der_len, nd_x509_cert *out);

/* Verifies cert's signature was produced by issuer_qx/issuer_qy over
 * SHA-256(cert->tbs_der) -- i.e. that issuer's private key actually signed
 * this certificate's TBSCertificate bytes. */
nd_status nd_x509_verify_signature(const nd_x509_cert *cert, const uint8_t issuer_qx[ND_P256_COORD_LEN],
                                    const uint8_t issuer_qy[ND_P256_COORD_LEN]);

/* Verifies a chain: chain[0] is the leaf, chain[i+1] must have signed
 * chain[i], and trust_anchor must have signed chain[chain_len-1] (pass
 * chain_len == 1 for "leaf signed directly by the trust anchor"). Checks,
 * for every cert in the chain and the anchor: at_time within
 * [not_before, not_after]; for every signer (chain[1..] and trust_anchor):
 * issuer/subject DER-byte linkage, is_ca set, and a valid ECDSA signature.
 * at_time is caller-supplied (canonical YYYYMMDDHHMMSS, see nd_x509_cert)
 * rather than read from the system clock -- this repo makes no clock
 * assumption; a caller wanting "now" supplies it themselves. */
nd_status nd_x509_verify_chain(const nd_x509_cert *chain, size_t chain_len, const nd_x509_cert *trust_anchor,
                                uint64_t at_time);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_X509_H */
