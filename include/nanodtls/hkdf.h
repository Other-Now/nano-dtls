#ifndef NANODTLS_HKDF_H
#define NANODTLS_HKDF_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ND_HASH_LEN 32u /* SHA-256 output length -- the only hash nano-dtls implements so far */

/* HKDF-Expand-Label's label prefix (RFC 8446 section 7.1) is protocol-
 * specific: DTLS 1.3 deliberately uses a DIFFERENT prefix than TLS 1.3 for
 * key separation (RFC 9147 section 5.9) -- "dtls13", six characters, no
 * trailing space (DTLS is one letter longer than TLS, so dropping the space
 * keeps the label the same total length). Every real DTLS 1.3 handshake
 * MUST use ND_HKDF_LABEL_PREFIX_DTLS13; ND_HKDF_LABEL_PREFIX_TLS13 exists
 * only because RFC 8448's key-schedule KATs are a TLS 1.3 trace (see
 * tests/test_hkdf.c) -- nano-dtls itself never negotiates plain TLS. */
#define ND_HKDF_LABEL_PREFIX_TLS13 "tls13 "
#define ND_HKDF_LABEL_PREFIX_DTLS13 "dtls13"

/* HKDF-Extract (RFC 5869 section 2.2). salt=NULL (or salt_len=0) uses a
 * HashLen all-zero salt, per the RFC. */
nd_status nd_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                           size_t ikm_len, uint8_t out_prk[ND_HASH_LEN]);

/* HKDF-Expand (RFC 5869 section 2.3). info_len is bounded by a fixed
 * internal stack buffer (see hkdf.c) -- generous for every TLS 1.3 label
 * (a few dozen bytes at most), never large enough to need allocation. */
nd_status nd_hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len);

/* HKDF-Expand-Label (RFC 8446 section 7.1): wraps HKDF-Expand with the
 * HkdfLabel = { Length, label_prefix + Label, Context } encoding. Pass one
 * of the ND_HKDF_LABEL_PREFIX_* constants above -- there is no default,
 * because silently defaulting to the wrong protocol's prefix is exactly the
 * kind of bug that would pass every KAT (which test the primitive, not
 * which prefix a caller chose) while being wrong for actual DTLS 1.3 use.
 * label_prefix + label together, and context, are bounded well below the
 * RFC's 255-byte ceiling (see hkdf.c) -- every real label and transcript
 * hash fits comfortably. */
nd_status nd_hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label_prefix,
                                const char *label, const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len);

/* Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
 * Transcript-Hash(Messages), Hash.length). The caller supplies the
 * already-computed transcript hash (or NULL/0 for Transcript-Hash("")). */
nd_status nd_derive_secret(const uint8_t *secret, size_t secret_len, const char *label_prefix,
                            const char *label, const uint8_t *transcript_hash,
                            size_t transcript_hash_len, uint8_t out[ND_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_HKDF_H */
