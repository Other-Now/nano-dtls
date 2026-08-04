/* See nanodtls/protect.h for scope and the nonce/AAD construction this
 * follows (RFC 9147 section 4 + 4.5, RFC 8446 section 5.2/5.3). */
#include "nanodtls/protect.h"

#include <string.h>

#include "nanodtls/record.h"

void nd_record_protection_init(nd_record_protection *p, const uint8_t key[ND_AEAD_KEY_LEN],
                                const uint8_t iv[ND_AEAD_NONCE_LEN], uint16_t epoch) {
    memcpy(p->write_key, key, ND_AEAD_KEY_LEN);
    memcpy(p->write_iv, iv, ND_AEAD_NONCE_LEN);
    p->next_send_sequence = 0;
    p->epoch = epoch;
}

void nd_record_unprotection_init(nd_record_unprotection *u, const uint8_t key[ND_AEAD_KEY_LEN],
                                  const uint8_t iv[ND_AEAD_NONCE_LEN], uint16_t epoch) {
    memcpy(u->read_key, key, ND_AEAD_KEY_LEN);
    memcpy(u->read_iv, iv, ND_AEAD_NONCE_LEN);
    u->highest_seen_sequence = 0;
    u->epoch = epoch;
}

/* nonce = write_iv XOR (sequence_number, big-endian, right-aligned into the
 * 12-byte IV -- the high 4 bytes of the padded sequence are zero). */
static void build_nonce(uint8_t out[ND_AEAD_NONCE_LEN], const uint8_t iv[ND_AEAD_NONCE_LEN], uint64_t seq) {
    uint8_t seq_bytes[ND_AEAD_NONCE_LEN];
    memset(seq_bytes, 0, ND_AEAD_NONCE_LEN);
    for (int i = 0; i < 8; ++i) seq_bytes[ND_AEAD_NONCE_LEN - 1 - i] = (uint8_t)(seq >> (8 * i));
    for (int i = 0; i < ND_AEAD_NONCE_LEN; ++i) out[i] = iv[i] ^ seq_bytes[i];
}

/* Stage 6 hot-path note: nd_unified_serialize's wire "length" field is
 * derived from its payload_len argument (see src/record.c), not read back
 * out of a caller-supplied header field -- so getting it right without
 * physically handing over the (not-yet-encrypted) ciphertext bytes meant
 * either serializing a full dummy-payload-sized buffer first (a wasted
 * memset+memcpy of up to ND_RECORD_PROTECT_MAX_INNER+ND_AEAD_TAG_LEN bytes
 * on every single record -- exactly the AEAD-adjacent traffic Stage 6
 * is supposed to be optimizing) or writing this fixed-shape header
 * directly. This duplicates a few lines of nd_unified_serialize's bit
 * assembly (for exactly the shape nd_record_protect always uses: no
 * connection ID, 16-bit sequence number, explicit length) -- verified
 * byte-for-byte equal to nd_unified_serialize's own output in
 * tests/test_protect.c, so a future change to the wire format's bit
 * layout can't silently drift between the two without a test noticing. */
static size_t write_fixed_shape_header(uint8_t *out, uint16_t epoch_low2, uint16_t seq16, uint16_t length) {
    out[0] = (uint8_t)(ND_UNIFIED_FIXED_BITS_VAL | ND_UNIFIED_SEQLEN_BIT | ND_UNIFIED_LEN_BIT |
                        (epoch_low2 & ND_UNIFIED_EPOCH_MASK));
    out[1] = (uint8_t)(seq16 >> 8);
    out[2] = (uint8_t)seq16;
    out[3] = (uint8_t)(length >> 8);
    out[4] = (uint8_t)length;
    return 5;
}
#define ND_FIXED_SHAPE_HEADER_LEN 5u

nd_status nd_record_protect(nd_record_protection *p, uint8_t content_type, const uint8_t *plaintext,
                             size_t plaintext_len, uint8_t *out_buf, size_t out_buf_cap, size_t *out_len) {
    if (!p || !plaintext || !out_buf || !out_len) return ND_ERR_BAD_ARG;
    if (plaintext_len + 1 > ND_RECORD_PROTECT_MAX_INNER) return ND_ERR_BAD_LENGTH;

    uint8_t inner[ND_RECORD_PROTECT_MAX_INNER];
    memcpy(inner, plaintext, plaintext_len);
    inner[plaintext_len] = content_type;
    size_t inner_len = plaintext_len + 1;
    size_t ciphertext_len = inner_len + ND_AEAD_TAG_LEN;
    size_t header_len = ND_FIXED_SHAPE_HEADER_LEN;
    size_t total_len = header_len + ciphertext_len;
    if (total_len > out_buf_cap) return ND_ERR_BAD_LENGTH;

    write_fixed_shape_header(out_buf, (uint16_t)(p->epoch & 0x3u), (uint16_t)(p->next_send_sequence & 0xFFFFu),
                              (uint16_t)ciphertext_len);

    uint8_t nonce[ND_AEAD_NONCE_LEN];
    build_nonce(nonce, p->write_iv, p->next_send_sequence);

    uint8_t tag[ND_AEAD_TAG_LEN];
    nd_status st = nd_aead_chacha20poly1305_encrypt(p->write_key, nonce, out_buf, header_len, inner, inner_len,
                                                     out_buf + header_len, tag);
    if (st != ND_OK) return st;
    memcpy(out_buf + header_len + inner_len, tag, ND_AEAD_TAG_LEN);

    p->next_send_sequence++;
    *out_len = total_len;
    return ND_OK;
}

nd_status nd_record_unprotect(nd_record_unprotection *u, const uint8_t *buf, size_t buf_len, uint8_t *plaintext_out,
                               size_t plaintext_cap, size_t *plaintext_len, uint8_t *out_content_type) {
    if (!u || !buf || !plaintext_out || !plaintext_len || !out_content_type) return ND_ERR_BAD_ARG;

    nd_unified_hdr hdr;
    const uint8_t *payload;
    size_t payload_len;
    nd_status st = nd_unified_parse(buf, buf_len, 0 /* no connection ID support */, &hdr, &payload, &payload_len);
    if (st != ND_OK) return st;

    uint16_t full_epoch = nd_reconstruct_epoch(u->epoch, hdr.epoch_low2);
    if (full_epoch != u->epoch) return ND_ERR_UNSUPPORTED; /* epoch/key update: not implemented */

    int wire_bits = hdr.seq_len_is_16bit ? 16 : 8;
    uint64_t full_seq = nd_reconstruct_sequence_number(u->highest_seen_sequence, hdr.sequence_number, wire_bits);

    if (payload_len < ND_AEAD_TAG_LEN) return ND_ERR_BAD_LENGTH;
    size_t ciphertext_len = payload_len - ND_AEAD_TAG_LEN;
    if (ciphertext_len > ND_RECORD_PROTECT_MAX_INNER) return ND_ERR_BAD_LENGTH;
    const uint8_t *ciphertext = payload;
    const uint8_t *tag = payload + ciphertext_len;
    size_t header_len = (size_t)(payload - buf);

    uint8_t nonce[ND_AEAD_NONCE_LEN];
    build_nonce(nonce, u->read_iv, full_seq);

    uint8_t inner[ND_RECORD_PROTECT_MAX_INNER];
    st = nd_aead_chacha20poly1305_decrypt(u->read_key, nonce, buf, header_len, ciphertext, ciphertext_len, tag, inner);
    if (st != ND_OK) return st; /* auth failure: highest_seen_sequence intentionally untouched */

    /* RFC 8446 section 5.2: strip trailing zero padding to find the real
     * content_type; this build never emits padding, but a peer's record is
     * still parsed generally. */
    size_t i = ciphertext_len;
    while (i > 0 && inner[i - 1] == 0) i--;
    if (i == 0) return ND_ERR_BAD_ARG; /* no content-type byte found: malformed inner plaintext */
    uint8_t content_type = inner[i - 1];
    size_t content_len = i - 1;
    if (content_len > plaintext_cap) return ND_ERR_BAD_LENGTH;
    memcpy(plaintext_out, inner, content_len);

    if (full_seq > u->highest_seen_sequence) u->highest_seen_sequence = full_seq;

    *plaintext_len = content_len;
    *out_content_type = content_type;
    return ND_OK;
}
