#include "nanodtls/record.h"

#include <string.h>

nd_status nd_plaintext_parse(const uint8_t *buf, size_t buf_len, nd_plaintext_hdr *out_hdr,
                              const uint8_t **out_fragment, size_t *out_fragment_len) {
    if (!buf || !out_hdr || !out_fragment || !out_fragment_len) return ND_ERR_BAD_ARG;
    if (buf_len < ND_PLAINTEXT_HDR_LEN) return ND_ERR_TRUNCATED;

    out_hdr->type = buf[0];
    out_hdr->legacy_version = (uint16_t)((buf[1] << 8) | buf[2]);
    out_hdr->epoch = (uint16_t)((buf[3] << 8) | buf[4]);
    out_hdr->sequence_number = ((uint64_t)buf[5] << 40) | ((uint64_t)buf[6] << 32) |
                               ((uint64_t)buf[7] << 24) | ((uint64_t)buf[8] << 16) |
                               ((uint64_t)buf[9] << 8) | (uint64_t)buf[10];
    out_hdr->length = (uint16_t)((buf[11] << 8) | buf[12]);

    if ((size_t)out_hdr->length > buf_len - ND_PLAINTEXT_HDR_LEN) return ND_ERR_BAD_LENGTH;

    *out_fragment = buf + ND_PLAINTEXT_HDR_LEN;
    *out_fragment_len = out_hdr->length;
    return ND_OK;
}

nd_status nd_plaintext_serialize(const nd_plaintext_hdr *hdr, const uint8_t *fragment,
                                  size_t fragment_len, uint8_t *out_buf, size_t out_buf_cap,
                                  size_t *out_len) {
    if (!hdr || !out_buf || !out_len) return ND_ERR_BAD_ARG;
    if (fragment_len > 0 && !fragment) return ND_ERR_BAD_ARG;
    if (hdr->sequence_number > 0xFFFFFFFFFFFFull) return ND_ERR_BAD_ARG; /* not 48-bit */
    if (fragment_len > 0xFFFFu) return ND_ERR_BAD_ARG;                   /* length is a uint16 */

    size_t total = ND_PLAINTEXT_HDR_LEN + fragment_len;
    if (out_buf_cap < total) return ND_ERR_BAD_LENGTH;

    out_buf[0] = hdr->type;
    out_buf[1] = (uint8_t)(hdr->legacy_version >> 8);
    out_buf[2] = (uint8_t)(hdr->legacy_version);
    out_buf[3] = (uint8_t)(hdr->epoch >> 8);
    out_buf[4] = (uint8_t)(hdr->epoch);
    out_buf[5] = (uint8_t)(hdr->sequence_number >> 40);
    out_buf[6] = (uint8_t)(hdr->sequence_number >> 32);
    out_buf[7] = (uint8_t)(hdr->sequence_number >> 24);
    out_buf[8] = (uint8_t)(hdr->sequence_number >> 16);
    out_buf[9] = (uint8_t)(hdr->sequence_number >> 8);
    out_buf[10] = (uint8_t)(hdr->sequence_number);
    out_buf[11] = (uint8_t)(fragment_len >> 8);
    out_buf[12] = (uint8_t)(fragment_len);
    if (fragment_len) memcpy(out_buf + ND_PLAINTEXT_HDR_LEN, fragment, fragment_len);

    *out_len = total;
    return ND_OK;
}

nd_status nd_unified_parse(const uint8_t *buf, size_t buf_len, size_t cid_len,
                            nd_unified_hdr *out_hdr, const uint8_t **out_payload,
                            size_t *out_payload_len) {
    if (!buf || !out_hdr || !out_payload || !out_payload_len) return ND_ERR_BAD_ARG;
    if (buf_len < 1) return ND_ERR_TRUNCATED;

    uint8_t b0 = buf[0];
    if ((b0 & ND_UNIFIED_FIXED_BITS_MASK) != ND_UNIFIED_FIXED_BITS_VAL) return ND_ERR_NOT_UNIFIED;

    int cid_present = (b0 & ND_UNIFIED_CID_BIT) != 0;
    int seq16 = (b0 & ND_UNIFIED_SEQLEN_BIT) != 0;
    int len_present = (b0 & ND_UNIFIED_LEN_BIT) != 0;
    uint8_t epoch_low2 = (uint8_t)(b0 & ND_UNIFIED_EPOCH_MASK);

    if (cid_present && cid_len == 0) return ND_ERR_BAD_ARG; /* CID length must be known out-of-band */

    size_t need = 1u + (cid_present ? cid_len : 0u) + (seq16 ? 2u : 1u) + (len_present ? 2u : 0u);
    if (buf_len < need) return ND_ERR_TRUNCATED;

    size_t off = 1;
    const uint8_t *cid = NULL;
    if (cid_present) {
        cid = buf + off;
        off += cid_len;
    }

    uint16_t seq;
    if (seq16) {
        seq = (uint16_t)((buf[off] << 8) | buf[off + 1]);
        off += 2;
    } else {
        seq = buf[off];
        off += 1;
    }

    uint16_t length;
    if (len_present) {
        length = (uint16_t)((buf[off] << 8) | buf[off + 1]);
        off += 2;
        if ((size_t)length > buf_len - off) return ND_ERR_BAD_LENGTH;
    } else {
        length = (uint16_t)(buf_len - off); /* payload runs to the end of the datagram */
    }

    out_hdr->cid_present = cid_present;
    out_hdr->seq_len_is_16bit = seq16;
    out_hdr->length_present = len_present;
    out_hdr->epoch_low2 = epoch_low2;
    out_hdr->cid = cid;
    out_hdr->cid_len = cid_present ? cid_len : 0;
    out_hdr->sequence_number = seq;
    out_hdr->length = length;

    *out_payload = buf + off;
    *out_payload_len = length;
    return ND_OK;
}

nd_status nd_unified_serialize(const nd_unified_hdr *hdr, const uint8_t *payload,
                                size_t payload_len, uint8_t *out_buf, size_t out_buf_cap,
                                size_t *out_len) {
    if (!hdr || !out_buf || !out_len) return ND_ERR_BAD_ARG;
    if (payload_len > 0 && !payload) return ND_ERR_BAD_ARG;
    if (hdr->cid_present && (!hdr->cid || hdr->cid_len == 0)) return ND_ERR_BAD_ARG;
    if (!hdr->seq_len_is_16bit && hdr->sequence_number > 0xFFu) return ND_ERR_BAD_ARG;
    if (hdr->length_present && payload_len > 0xFFFFu) return ND_ERR_BAD_ARG;

    size_t total = 1u + (hdr->cid_present ? hdr->cid_len : 0u) +
                   (hdr->seq_len_is_16bit ? 2u : 1u) + (hdr->length_present ? 2u : 0u) +
                   payload_len;
    if (out_buf_cap < total) return ND_ERR_BAD_LENGTH;

    size_t off = 0;
    out_buf[off++] = (uint8_t)(ND_UNIFIED_FIXED_BITS_VAL |
                                (hdr->cid_present ? ND_UNIFIED_CID_BIT : 0u) |
                                (hdr->seq_len_is_16bit ? ND_UNIFIED_SEQLEN_BIT : 0u) |
                                (hdr->length_present ? ND_UNIFIED_LEN_BIT : 0u) |
                                (hdr->epoch_low2 & ND_UNIFIED_EPOCH_MASK));

    if (hdr->cid_present) {
        memcpy(out_buf + off, hdr->cid, hdr->cid_len);
        off += hdr->cid_len;
    }

    if (hdr->seq_len_is_16bit) {
        out_buf[off++] = (uint8_t)(hdr->sequence_number >> 8);
        out_buf[off++] = (uint8_t)(hdr->sequence_number);
    } else {
        out_buf[off++] = (uint8_t)(hdr->sequence_number);
    }

    if (hdr->length_present) {
        out_buf[off++] = (uint8_t)(payload_len >> 8);
        out_buf[off++] = (uint8_t)(payload_len);
    }

    if (payload_len) memcpy(out_buf + off, payload, payload_len);
    off += payload_len;

    *out_len = off;
    return ND_OK;
}

uint16_t nd_reconstruct_epoch(uint16_t highest_known_epoch, uint8_t wire_low2) {
    int32_t low2 = wire_low2 & 0x3;
    int32_t base = highest_known_epoch & ~0x3;
    int32_t best = -1;
    int32_t best_dist = 0x7fffffff;

    for (int32_t w = -1; w <= 1; ++w) {
        int32_t candidate = base + w * 4 + low2;
        if (candidate < 0 || candidate > 0xFFFF) continue;
        int32_t dist = candidate - (int32_t)highest_known_epoch;
        if (dist < 0) dist = -dist;
        if (dist < best_dist) {
            best_dist = dist;
            best = candidate;
        }
    }
    return (uint16_t)best;
}

uint64_t nd_reconstruct_sequence_number(uint64_t highest_known_sequence, uint16_t wire_value, int wire_bits) {
    uint64_t win = (uint64_t)1 << wire_bits;
    uint64_t mask = win - 1;
    uint64_t base = highest_known_sequence & ~mask;
    uint64_t truncated = (uint64_t)wire_value & mask;
    /* window w=0 (candidate = base+truncated) is always a valid fallback,
     * used as the starting "best" before comparing the w=-1/w=+1 windows
     * below. */
    uint64_t best = base + truncated;
    uint64_t best_dist = (best > highest_known_sequence) ? (best - highest_known_sequence)
                                                           : (highest_known_sequence - best);

    for (int w = -1; w <= 1; w += 2) {
        int64_t candidate = (int64_t)base + (int64_t)w * (int64_t)win + (int64_t)truncated;
        if (candidate < 0 || candidate > 0xFFFFFFFFFFFFLL) continue; /* 48-bit ceiling, RFC 9147 sec 4 */
        uint64_t ucandidate = (uint64_t)candidate;
        uint64_t dist = (ucandidate > highest_known_sequence) ? (ucandidate - highest_known_sequence)
                                                                : (highest_known_sequence - ucandidate);
        if (dist < best_dist) {
            best_dist = dist;
            best = ucandidate;
        }
    }
    return best;
}
