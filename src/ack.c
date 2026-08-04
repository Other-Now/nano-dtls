/* See nanodtls/ack.h. */
#include "nanodtls/ack.h"

static void put_u64(uint8_t *out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)(v >> (8 * (7 - i)));
}

static uint64_t get_u64(const uint8_t *in) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | in[i];
    return v;
}

nd_status nd_ack_serialize(const nd_ack *ack, uint8_t *out_buf, size_t out_buf_cap, size_t *out_len) {
    if (!ack || !out_buf || !out_len) return ND_ERR_BAD_ARG;
    if (ack->count > ND_ACK_MAX_RECORDS) return ND_ERR_BAD_ARG;

    size_t list_len = ack->count * 16u;
    if (2 + list_len > out_buf_cap) return ND_ERR_BAD_LENGTH;

    out_buf[0] = (uint8_t)(list_len >> 8);
    out_buf[1] = (uint8_t)list_len;
    size_t pos = 2;
    for (size_t i = 0; i < ack->count; ++i) {
        put_u64(out_buf + pos, ack->records[i].epoch);
        put_u64(out_buf + pos + 8, ack->records[i].sequence_number);
        pos += 16;
    }
    *out_len = pos;
    return ND_OK;
}

nd_status nd_ack_parse(const uint8_t *buf, size_t buf_len, nd_ack *out_ack) {
    if (!buf || !out_ack) return ND_ERR_BAD_ARG;
    if (buf_len < 2) return ND_ERR_TRUNCATED;

    uint16_t list_len = (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
    if ((size_t)list_len + 2 != buf_len) return ND_ERR_BAD_LENGTH;
    if (list_len % 16u != 0) return ND_ERR_BAD_LENGTH;

    size_t count = list_len / 16u;
    if (count > ND_ACK_MAX_RECORDS) return ND_ERR_UNSUPPORTED;

    size_t pos = 2;
    for (size_t i = 0; i < count; ++i) {
        out_ack->records[i].epoch = get_u64(buf + pos);
        out_ack->records[i].sequence_number = get_u64(buf + pos + 8);
        pos += 16;
    }
    out_ack->count = count;
    return ND_OK;
}
