#include "nanodtls/handshake.h"

#include <string.h>

nd_status nd_handshake_parse(const uint8_t *buf, size_t buf_len, nd_handshake_hdr *out_hdr,
                              const uint8_t **out_fragment, size_t *out_fragment_len) {
    if (!buf || !out_hdr || !out_fragment || !out_fragment_len) return ND_ERR_BAD_ARG;
    if (buf_len < ND_HANDSHAKE_HDR_LEN) return ND_ERR_TRUNCATED;

    out_hdr->msg_type = buf[0];
    out_hdr->length = ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    out_hdr->message_seq = (uint16_t)((buf[4] << 8) | buf[5]);
    out_hdr->fragment_offset =
        ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 8) | (uint32_t)buf[8];
    out_hdr->fragment_length =
        ((uint32_t)buf[9] << 16) | ((uint32_t)buf[10] << 8) | (uint32_t)buf[11];

    if ((size_t)out_hdr->fragment_length > buf_len - ND_HANDSHAKE_HDR_LEN) {
        return ND_ERR_BAD_LENGTH;
    }

    *out_fragment = buf + ND_HANDSHAKE_HDR_LEN;
    *out_fragment_len = out_hdr->fragment_length;
    return ND_OK;
}

nd_status nd_handshake_serialize(const nd_handshake_hdr *hdr, const uint8_t *fragment,
                                  size_t fragment_len, uint8_t *out_buf, size_t out_buf_cap,
                                  size_t *out_len) {
    if (!hdr || !out_buf || !out_len) return ND_ERR_BAD_ARG;
    if (fragment_len > 0 && !fragment) return ND_ERR_BAD_ARG;
    if (hdr->length > 0xFFFFFFu || hdr->fragment_offset > 0xFFFFFFu ||
        hdr->fragment_length > 0xFFFFFFu) {
        return ND_ERR_BAD_ARG; /* these three fields are 24-bit on the wire */
    }
    if (hdr->fragment_length != fragment_len) return ND_ERR_BAD_ARG;

    size_t total = ND_HANDSHAKE_HDR_LEN + fragment_len;
    if (out_buf_cap < total) return ND_ERR_BAD_LENGTH;

    out_buf[0] = hdr->msg_type;
    out_buf[1] = (uint8_t)(hdr->length >> 16);
    out_buf[2] = (uint8_t)(hdr->length >> 8);
    out_buf[3] = (uint8_t)(hdr->length);
    out_buf[4] = (uint8_t)(hdr->message_seq >> 8);
    out_buf[5] = (uint8_t)(hdr->message_seq);
    out_buf[6] = (uint8_t)(hdr->fragment_offset >> 16);
    out_buf[7] = (uint8_t)(hdr->fragment_offset >> 8);
    out_buf[8] = (uint8_t)(hdr->fragment_offset);
    out_buf[9] = (uint8_t)(hdr->fragment_length >> 16);
    out_buf[10] = (uint8_t)(hdr->fragment_length >> 8);
    out_buf[11] = (uint8_t)(hdr->fragment_length);
    if (fragment_len) memcpy(out_buf + ND_HANDSHAKE_HDR_LEN, fragment, fragment_len);

    *out_len = total;
    return ND_OK;
}
