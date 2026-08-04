/* See nanodtls/reassembly.h. */
#include "nanodtls/reassembly.h"

#include <string.h>

void nd_reassembly_init(nd_reassembly *r) {
    r->total_len = 0;
    r->total_len_known = 0;
    r->msg_type = 0;
    r->message_seq = 0;
    r->in_progress = 0;
    memset(r->received, 0, sizeof(r->received));
}

nd_status nd_reassembly_add_fragment(nd_reassembly *r, const nd_handshake_hdr *hdr, const uint8_t *fragment) {
    if (!r || !hdr || !fragment) return ND_ERR_BAD_ARG;
    if (hdr->length > ND_REASSEMBLY_MAX_LEN) return ND_ERR_BAD_LENGTH;
    if (hdr->fragment_offset + hdr->fragment_length > hdr->length) return ND_ERR_BAD_LENGTH;

    if (!r->in_progress) {
        r->msg_type = hdr->msg_type;
        r->message_seq = hdr->message_seq;
        r->total_len = hdr->length;
        r->total_len_known = 1;
        r->in_progress = 1;
        memset(r->received, 0, r->total_len);
    } else if (hdr->msg_type != r->msg_type || hdr->message_seq != r->message_seq) {
        return ND_ERR_UNSUPPORTED;
    } else if (hdr->length != r->total_len) {
        return ND_ERR_BAD_LENGTH; /* a genuine retransmission must report the same total length */
    }

    if (hdr->fragment_length) {
        memcpy(r->buf + hdr->fragment_offset, fragment, hdr->fragment_length);
        memset(r->received + hdr->fragment_offset, 1, hdr->fragment_length);
    }
    return ND_OK;
}

int nd_reassembly_is_complete(const nd_reassembly *r) {
    if (!r->in_progress || !r->total_len_known) return 0;
    for (size_t i = 0; i < r->total_len; ++i) {
        if (!r->received[i]) return 0;
    }
    return 1;
}
