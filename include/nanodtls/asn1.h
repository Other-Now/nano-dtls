#ifndef NANODTLS_ASN1_H
#define NANODTLS_ASN1_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * A minimal, zero-copy DER (Distinguished Encoding Rules, ITU-T X.690)
 * tag-length-value reader -- exactly as much ASN.1 as X.509 (RFC 5280)
 * certificate parsing needs, in the same style as this repo's other
 * parsers: no allocation, pointers into the caller's buffer, bounds-checked.
 *
 * Scoped deliberately: only the *low tag form* (tag number <= 30, i.e. a
 * single tag byte) is supported -- every tag X.509 actually uses (SEQUENCE,
 * SET, INTEGER, BIT STRING, OBJECT IDENTIFIER, the string types, UTCTime/
 * GeneralizedTime, and the context-specific [0]-[3] tags) fits in one byte.
 * Indefinite-length encoding (BER, not DER) is rejected -- DER requires
 * definite lengths, so encountering the indefinite-length octet (0x80) in
 * something claiming to be DER is itself a well-formedness error. See
 * nanodtls/x509.h for the certificate-level "honest scope" notes.
 * --------------------------------------------------------------------- */

#define ND_ASN1_TAG_INTEGER 0x02u
#define ND_ASN1_TAG_BIT_STRING 0x03u
#define ND_ASN1_TAG_OCTET_STRING 0x04u
#define ND_ASN1_TAG_NULL 0x05u
#define ND_ASN1_TAG_OID 0x06u
#define ND_ASN1_TAG_UTF8_STRING 0x0Cu
#define ND_ASN1_TAG_PRINTABLE_STRING 0x13u
#define ND_ASN1_TAG_UTC_TIME 0x17u
#define ND_ASN1_TAG_GENERALIZED_TIME 0x18u
#define ND_ASN1_TAG_SEQUENCE 0x30u /* constructed bit already set (0x20 | 0x10) */
#define ND_ASN1_TAG_SET 0x31u
#define ND_ASN1_TAG_CTX(n) (0xA0u | (uint8_t)(n)) /* context-specific, constructed, [n] */

typedef struct nd_asn1_tlv {
    uint8_t tag;
    int constructed;
    size_t header_len;   /* bytes consumed by the tag+length octets */
    const uint8_t *value; /* points into the caller's buffer; not copied */
    size_t value_len;
} nd_asn1_tlv;

/* Parses one TLV starting at buf[0]. On success, out->value/value_len point
 * into buf (zero-copy); out->header_len + out->value_len is the total size
 * of this TLV (tag + length + contents) within buf. */
nd_status nd_asn1_parse_tlv(const uint8_t *buf, size_t buf_len, nd_asn1_tlv *out);

typedef struct nd_asn1_reader {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} nd_asn1_reader;

void nd_asn1_reader_init(nd_asn1_reader *r, const uint8_t *buf, size_t len);
int nd_asn1_reader_done(const nd_asn1_reader *r);
/* Reads the next sibling TLV and advances past it. */
nd_status nd_asn1_reader_next(nd_asn1_reader *r, nd_asn1_tlv *out);

/* Reads an INTEGER's content as an unsigned big-endian value, stripping a
 * single DER sign-extension 0x00 byte if present, and left-zero-pads into
 * out[0..out_len). Returns ND_ERR_BAD_LENGTH if the integer (after
 * stripping) doesn't fit in out_len bytes, or if it's empty/negative
 * (negative INTEGERs -- top bit set with no stripped sign byte -- aren't
 * meaningful for any field this repo reads: serial numbers are opaque
 * bytes, and r/s/coordinates are always non-negative). */
nd_status nd_asn1_read_uint_fixed(const nd_asn1_tlv *tlv, uint8_t *out, size_t out_len);

/* Reads a BIT STRING's content, skipping the leading "number of unused
 * bits in the last octet" byte, requiring it to be 0 (every BIT STRING
 * this repo parses -- public keys, signatures -- is byte-aligned). */
nd_status nd_asn1_read_bitstring_bytes(const nd_asn1_tlv *tlv, const uint8_t **out_bytes,
                                        size_t *out_len);

/* Encodes an ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }) from two
 * raw 32-byte big-endian unsigned scalars -- the DER mirror of the parsing
 * nd_x509_parse/nd_certificate_verify_check already do for an r/s pair
 * (minimal-length encoding, with the one leading 0x00 DER requires when a
 * value's top bit is set). This is formatting, not a private-key
 * operation: the actual ECDSA signing that produces r/s happens outside
 * this library (see tools/p256_sign_demo.h) -- this function only encodes
 * whatever r/s it's given. */
nd_status nd_asn1_write_ecdsa_sig_value(const uint8_t r[32], const uint8_t s[32], uint8_t *out_buf,
                                         size_t out_buf_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_ASN1_H */
