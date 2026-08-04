/* See nanodtls/asn1.h for scope. */
#include "nanodtls/asn1.h"

nd_status nd_asn1_parse_tlv(const uint8_t *buf, size_t buf_len, nd_asn1_tlv *out) {
    if (!buf || !out) return ND_ERR_BAD_ARG;
    if (buf_len < 2) return ND_ERR_TRUNCATED;

    uint8_t tag = buf[0];
    if ((tag & 0x1Fu) == 0x1Fu) return ND_ERR_UNSUPPORTED; /* high tag-number form: unused by X.509 */

    size_t pos = 1;
    uint8_t len0 = buf[pos++];
    size_t value_len;
    if ((len0 & 0x80u) == 0) {
        value_len = len0;
    } else {
        size_t nbytes = (size_t)(len0 & 0x7Fu);
        if (nbytes == 0) return ND_ERR_UNSUPPORTED; /* indefinite length: not valid DER */
        if (nbytes > sizeof(size_t)) return ND_ERR_BAD_LENGTH;
        if (pos + nbytes > buf_len) return ND_ERR_TRUNCATED;
        value_len = 0;
        for (size_t i = 0; i < nbytes; ++i) value_len = (value_len << 8) | buf[pos++];
    }
    if (pos + value_len < pos) return ND_ERR_BAD_LENGTH; /* overflow guard */
    if (pos + value_len > buf_len) return ND_ERR_BAD_LENGTH;

    out->tag = tag;
    out->constructed = (tag & 0x20u) != 0;
    out->header_len = pos;
    out->value = buf + pos;
    out->value_len = value_len;
    return ND_OK;
}

void nd_asn1_reader_init(nd_asn1_reader *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}

int nd_asn1_reader_done(const nd_asn1_reader *r) { return r->pos >= r->len; }

nd_status nd_asn1_reader_next(nd_asn1_reader *r, nd_asn1_tlv *out) {
    if (r->pos >= r->len) return ND_ERR_TRUNCATED;
    nd_status st = nd_asn1_parse_tlv(r->buf + r->pos, r->len - r->pos, out);
    if (st != ND_OK) return st;
    r->pos += out->header_len + out->value_len;
    return ND_OK;
}

nd_status nd_asn1_read_uint_fixed(const nd_asn1_tlv *tlv, uint8_t *out, size_t out_len) {
    if (!tlv || !out) return ND_ERR_BAD_ARG;
    if (tlv->tag != ND_ASN1_TAG_INTEGER) return ND_ERR_BAD_ARG;
    const uint8_t *p = tlv->value;
    size_t n = tlv->value_len;
    if (n == 0) return ND_ERR_BAD_LENGTH;
    /* DER prepends a 0x00 precisely when the value's natural top bit is set,
     * to keep a non-negative INTEGER from reading as two's-complement
     * negative -- so a set top bit right after stripping that byte is the
     * ordinary, expected case (this is exactly why the byte is there), not
     * a sign to reject. Only check for "genuinely negative" when no 0x00
     * was stripped, i.e. when there was nothing disambiguating the sign. */
    int stripped = 0;
    if (n > 1 && p[0] == 0x00) {
        p++;
        n--;
        stripped = 1;
    }
    if (n == 0 || n > out_len) return ND_ERR_BAD_LENGTH;
    if (!stripped && (p[0] & 0x80u) != 0) return ND_ERR_UNSUPPORTED; /* genuinely negative: not expected/handled */
    size_t pad = out_len - n;
    for (size_t i = 0; i < pad; ++i) out[i] = 0;
    for (size_t i = 0; i < n; ++i) out[pad + i] = p[i];
    return ND_OK;
}

nd_status nd_asn1_read_bitstring_bytes(const nd_asn1_tlv *tlv, const uint8_t **out_bytes, size_t *out_len) {
    if (!tlv || !out_bytes || !out_len) return ND_ERR_BAD_ARG;
    if (tlv->tag != ND_ASN1_TAG_BIT_STRING) return ND_ERR_BAD_ARG;
    if (tlv->value_len < 1) return ND_ERR_BAD_LENGTH;
    if (tlv->value[0] != 0x00) return ND_ERR_UNSUPPORTED; /* non-byte-aligned: unused by X.509 keys/sigs */
    *out_bytes = tlv->value + 1;
    *out_len = tlv->value_len - 1;
    return ND_OK;
}

/* Minimal-length DER INTEGER encoding of a 32-byte unsigned big-endian
 * value into out (caller-sized >= 34 bytes): strips leading zero bytes down
 * to the shortest representation (keeping at least one byte for a zero
 * value), then prepends one more 0x00 iff the remaining top bit is set
 * (DER's sign-disambiguation rule -- the exact inverse of what
 * nd_asn1_read_uint_fixed strips on the way in). Returns the number of
 * bytes written. */
static size_t der_encode_uint32(const uint8_t val[32], uint8_t *out) {
    size_t start = 0;
    while (start < 31 && val[start] == 0) start++;
    size_t n = 32 - start;
    int need_pad = (val[start] & 0x80u) != 0;
    size_t len = n + (size_t)(need_pad ? 1 : 0);
    out[0] = ND_ASN1_TAG_INTEGER;
    out[1] = (uint8_t)len; /* len <= 33: always fits DER's short length form */
    size_t pos = 2;
    if (need_pad) out[pos++] = 0x00;
    for (size_t i = 0; i < n; ++i) out[pos + i] = val[start + i];
    return pos + n;
}

nd_status nd_asn1_write_ecdsa_sig_value(const uint8_t r[32], const uint8_t s[32], uint8_t *out_buf,
                                         size_t out_buf_cap, size_t *out_len) {
    if (!r || !s || !out_buf || !out_len) return ND_ERR_BAD_ARG;

    uint8_t body[2 * 36];
    size_t r_len = der_encode_uint32(r, body);
    size_t s_len = der_encode_uint32(s, body + r_len);
    size_t body_len = r_len + s_len;
    if (body_len > 127) return ND_ERR_BAD_LENGTH; /* never happens for P-256 (max ~35+35=70); guards the short-length-form assumption below */
    if (2 + body_len > out_buf_cap) return ND_ERR_BAD_LENGTH;

    out_buf[0] = ND_ASN1_TAG_SEQUENCE;
    out_buf[1] = (uint8_t)body_len;
    for (size_t i = 0; i < body_len; ++i) out_buf[2 + i] = body[i];
    *out_len = 2 + body_len;
    return ND_OK;
}
