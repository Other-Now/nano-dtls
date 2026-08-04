/* EncryptedExtensions / Certificate / CertificateVerify. See
 * nanodtls/messages.h for scope. The tiny writer/reader below deliberately
 * mirrors src/handshake/hello.c's (rather than sharing it) -- both are
 * small, file-local, and this repo's existing convention (see every
 * tests/test_*.c's own local helpers) is a little duplication over a new
 * cross-file dependency for ~40 lines. */
#include "nanodtls/messages.h"

#include <string.h>

#include "nanodtls/asn1.h"
#include "nanodtls/sha256.h"

typedef struct writer {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int overflow;
} writer;

static void w_init(writer *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = 0;
}
static void w_bytes(writer *w, const uint8_t *data, size_t n) {
    if (w->overflow || w->len + n > w->cap) {
        w->overflow = 1;
        return;
    }
    if (n) memcpy(w->buf + w->len, data, n);
    w->len += n;
}
static void w_u8(writer *w, uint8_t v) { w_bytes(w, &v, 1); }
static void w_u16(writer *w, uint16_t v) {
    const uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    w_bytes(w, b, 2);
}
static size_t w_reserve_u16_len(writer *w) {
    size_t pos = w->len;
    w_u16(w, 0);
    return pos;
}
static void w_patch_u16_len(writer *w, size_t pos) {
    if (w->overflow) return;
    size_t body = w->len - pos - 2;
    w->buf[pos] = (uint8_t)(body >> 8);
    w->buf[pos + 1] = (uint8_t)body;
}
static size_t w_reserve_u24_len(writer *w) {
    size_t pos = w->len;
    const uint8_t z[3] = {0, 0, 0};
    w_bytes(w, z, 3);
    return pos;
}
static void w_patch_u24_len(writer *w, size_t pos) {
    if (w->overflow) return;
    size_t body = w->len - pos - 3;
    w->buf[pos] = (uint8_t)(body >> 16);
    w->buf[pos + 1] = (uint8_t)(body >> 8);
    w->buf[pos + 2] = (uint8_t)body;
}

typedef struct reader {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} reader;

static void r_init(reader *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}
static int r_bytes(reader *r, uint8_t *out, size_t n) {
    if (r->pos + n > r->len) return 0;
    if (n) memcpy(out, r->buf + r->pos, n);
    r->pos += n;
    return 1;
}
static int r_u8(reader *r, uint8_t *out) { return r_bytes(r, out, 1); }
static int r_u16(reader *r, uint16_t *out) {
    uint8_t b[2];
    if (!r_bytes(r, b, 2)) return 0;
    *out = (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
    return 1;
}
static int r_u24(reader *r, uint32_t *out) {
    uint8_t b[3];
    if (!r_bytes(r, b, 3)) return 0;
    *out = ((uint32_t)b[0] << 16) | ((uint32_t)b[1] << 8) | b[2];
    return 1;
}
static int r_skip(reader *r, size_t n) {
    if (r->pos + n > r->len) return 0;
    r->pos += n;
    return 1;
}
static int r_view(reader *r, size_t n, const uint8_t **out) {
    if (r->pos + n > r->len) return 0;
    *out = r->buf + r->pos;
    r->pos += n;
    return 1;
}

nd_status nd_encrypted_extensions_serialize(uint8_t *out_buf, size_t out_buf_cap, size_t *out_len) {
    if (!out_buf || !out_len) return ND_ERR_BAD_ARG;
    if (out_buf_cap < 2) return ND_ERR_BAD_LENGTH;
    out_buf[0] = 0;
    out_buf[1] = 0;
    *out_len = 2;
    return ND_OK;
}

nd_status nd_encrypted_extensions_parse(const uint8_t *buf, size_t buf_len) {
    if (!buf) return ND_ERR_BAD_ARG;
    reader r;
    r_init(&r, buf, buf_len);
    uint16_t ext_len;
    if (!r_u16(&r, &ext_len)) return ND_ERR_TRUNCATED;
    if (!r_skip(&r, ext_len)) return ND_ERR_BAD_LENGTH;
    if (r.pos != r.len) return ND_ERR_BAD_LENGTH; /* trailing garbage past the extensions list */
    return ND_OK;
}

nd_status nd_certificate_serialize(const nd_certificate_msg *msg, uint8_t *out_buf, size_t out_buf_cap,
                                    size_t *out_len) {
    if (!msg || !out_buf || !out_len) return ND_ERR_BAD_ARG;
    if (msg->cert_count == 0 || msg->cert_count > ND_CERTIFICATE_MSG_MAX_CERTS) return ND_ERR_BAD_ARG;

    writer w;
    w_init(&w, out_buf, out_buf_cap);
    w_u8(&w, 0x00); /* certificate_request_context: always empty */

    size_t list_len_pos = w_reserve_u24_len(&w);
    for (size_t i = 0; i < msg->cert_count; ++i) {
        size_t entry_len_pos = w_reserve_u24_len(&w);
        w_bytes(&w, msg->cert_der[i], msg->cert_der_len[i]);
        w_patch_u24_len(&w, entry_len_pos);
        size_t ext_len_pos = w_reserve_u16_len(&w); /* per-entry extensions: always empty */
        w_patch_u16_len(&w, ext_len_pos);
    }
    w_patch_u24_len(&w, list_len_pos);

    if (w.overflow) return ND_ERR_BAD_LENGTH;
    *out_len = w.len;
    return ND_OK;
}

nd_status nd_certificate_parse(const uint8_t *buf, size_t buf_len, nd_certificate_msg *out_msg) {
    if (!buf || !out_msg) return ND_ERR_BAD_ARG;

    reader r;
    r_init(&r, buf, buf_len);
    uint8_t ctx_len;
    if (!r_u8(&r, &ctx_len)) return ND_ERR_TRUNCATED;
    if (!r_skip(&r, ctx_len)) return ND_ERR_BAD_LENGTH;

    uint32_t list_len;
    if (!r_u24(&r, &list_len)) return ND_ERR_TRUNCATED;
    const uint8_t *list_data;
    if (!r_view(&r, list_len, &list_data)) return ND_ERR_BAD_LENGTH;

    reader lr;
    r_init(&lr, list_data, list_len);
    size_t count = 0;
    while (lr.pos < lr.len) {
        if (count >= ND_CERTIFICATE_MSG_MAX_CERTS) return ND_ERR_UNSUPPORTED;
        uint32_t cert_len;
        if (!r_u24(&lr, &cert_len)) return ND_ERR_TRUNCATED;
        const uint8_t *cert_data;
        if (!r_view(&lr, cert_len, &cert_data)) return ND_ERR_BAD_LENGTH;
        uint16_t ext_len;
        if (!r_u16(&lr, &ext_len)) return ND_ERR_TRUNCATED;
        if (!r_skip(&lr, ext_len)) return ND_ERR_BAD_LENGTH;

        out_msg->cert_der[count] = cert_data;
        out_msg->cert_der_len[count] = cert_len;
        count++;
    }
    if (count == 0) return ND_ERR_BAD_ARG;
    out_msg->cert_count = count;
    return ND_OK;
}

nd_status nd_certificate_verify_parse(const uint8_t *buf, size_t buf_len, nd_certificate_verify_msg *out_msg) {
    if (!buf || !out_msg) return ND_ERR_BAD_ARG;
    reader r;
    r_init(&r, buf, buf_len);
    if (!r_u16(&r, &out_msg->algorithm)) return ND_ERR_TRUNCATED;
    uint16_t sig_len;
    if (!r_u16(&r, &sig_len)) return ND_ERR_TRUNCATED;
    const uint8_t *sig;
    if (!r_view(&r, sig_len, &sig)) return ND_ERR_BAD_LENGTH;
    if (r.pos != r.len) return ND_ERR_BAD_LENGTH;
    out_msg->signature = sig;
    out_msg->signature_len = sig_len;
    return ND_OK;
}

nd_status nd_certificate_verify_content(const char *context_string, const uint8_t transcript_hash[ND_HASH_LEN],
                                         uint8_t *out_buf, size_t out_buf_cap, size_t *out_len) {
    if (!context_string || !transcript_hash || !out_buf || !out_len) return ND_ERR_BAD_ARG;
    size_t ctx_len = strlen(context_string);
    size_t total = 64u + ctx_len + 1u + ND_HASH_LEN;
    if (total > out_buf_cap) return ND_ERR_BAD_LENGTH;

    size_t pos = 0;
    for (int i = 0; i < 64; ++i) out_buf[pos++] = 0x20;
    memcpy(out_buf + pos, context_string, ctx_len);
    pos += ctx_len;
    out_buf[pos++] = 0x00;
    memcpy(out_buf + pos, transcript_hash, ND_HASH_LEN);
    pos += ND_HASH_LEN;

    *out_len = pos;
    return ND_OK;
}

nd_status nd_certificate_verify_check(const nd_certificate_verify_msg *msg, const char *context_string,
                                       const uint8_t transcript_hash[ND_HASH_LEN],
                                       const uint8_t peer_qx[ND_P256_COORD_LEN],
                                       const uint8_t peer_qy[ND_P256_COORD_LEN]) {
    if (!msg || !context_string || !transcript_hash || !peer_qx || !peer_qy) return ND_ERR_BAD_ARG;
    if (msg->algorithm != ND_SIGSCHEME_ECDSA_SECP256R1_SHA256) return ND_ERR_UNSUPPORTED;

    uint8_t content[ND_CERT_VERIFY_CONTENT_MAX];
    size_t content_len;
    nd_status st = nd_certificate_verify_content(context_string, transcript_hash, content, sizeof(content), &content_len);
    if (st != ND_OK) return st;
    uint8_t hash[ND_HASH_LEN];
    nd_sha256(content, content_len, hash);

    nd_asn1_tlv seq_tlv;
    st = nd_asn1_parse_tlv(msg->signature, msg->signature_len, &seq_tlv);
    if (st != ND_OK) return st;
    if (seq_tlv.tag != ND_ASN1_TAG_SEQUENCE) return ND_ERR_BAD_ARG;

    nd_asn1_reader sr;
    nd_asn1_reader_init(&sr, seq_tlv.value, seq_tlv.value_len);
    nd_asn1_tlv r_tlv, s_tlv;
    st = nd_asn1_reader_next(&sr, &r_tlv);
    if (st != ND_OK) return st;
    st = nd_asn1_reader_next(&sr, &s_tlv);
    if (st != ND_OK) return st;

    uint8_t r[ND_P256_SCALAR_LEN], s[ND_P256_SCALAR_LEN];
    st = nd_asn1_read_uint_fixed(&r_tlv, r, ND_P256_SCALAR_LEN);
    if (st != ND_OK) return st;
    st = nd_asn1_read_uint_fixed(&s_tlv, s, ND_P256_SCALAR_LEN);
    if (st != ND_OK) return st;

    return nd_p256_ecdsa_verify(peer_qx, peer_qy, hash, r, s);
}
