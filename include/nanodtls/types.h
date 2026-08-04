#ifndef NANODTLS_TYPES_H
#define NANODTLS_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IANA "TLS ContentType" registry values used by DTLS 1.3
 * (RFC 8446 section 5.1, RFC 9146, RFC 9147 sections 4 and 7). */
typedef enum nd_content_type {
    ND_CT_INVALID = 0,
    ND_CT_CHANGE_CIPHER_SPEC = 20,
    ND_CT_ALERT = 21,
    ND_CT_HANDSHAKE = 22,
    ND_CT_APPLICATION_DATA = 23,
    ND_CT_HEARTBEAT = 24,
    ND_CT_TLS12_CID = 25, /* RFC 9146: DTLS 1.2 Connection ID */
    ND_CT_ACK = 26,       /* RFC 9147 section 7: DTLS 1.3 reliability */
} nd_content_type;

/* legacy_record_version wire values. RFC 9147 section 4 requires receivers to
 * ignore this field; it is kept only because it occupies wire bytes in the
 * DTLSPlaintext header. */
typedef enum nd_legacy_version {
    ND_VERSION_DTLS1_0 = 0xfeff,
    ND_VERSION_DTLS1_2 = 0xfefd, /* value RFC 9147 senders emit */
} nd_legacy_version;

typedef enum nd_status {
    ND_OK = 0,
    ND_ERR_TRUNCATED,   /* buffer shorter than the header/record requires */
    ND_ERR_BAD_LENGTH,  /* declared length overruns the supplied buffer */
    ND_ERR_NOT_UNIFIED, /* first byte doesn't match the unified-header pattern */
    ND_ERR_BAD_ARG,     /* NULL pointer, zero-size output, or out-of-range field */
    ND_ERR_AUTH_FAILED, /* AEAD tag verification failed; plaintext is NOT written */
    ND_ERR_UNSUPPORTED, /* well-formed but not something this minimal build handles
                          * (e.g. a ServerHello missing key_share/supported_versions,
                          * or negotiating a group/version nano-dtls doesn't implement) */
} nd_status;

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_TYPES_H */
