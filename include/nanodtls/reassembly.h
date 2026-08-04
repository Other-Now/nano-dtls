#ifndef NANODTLS_REASSEMBLY_H
#define NANODTLS_REASSEMBLY_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/handshake.h"
#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * Out-of-order handshake message reassembly (RFC 9147 section 5.5): one
 * logical Handshake message (identified by message_seq) can arrive split
 * across multiple DTLS records as same-message_seq fragments with
 * different fragment_offset/fragment_length, in any order, with
 * duplicates/retransmissions possible. Tracks which byte ranges of the
 * message have been received with a byte-granularity bitmap (simpler to
 * verify correct than an interval-merging scheme, and this is
 * handshake-only bookkeeping -- never on the Stage 6 hot path -- so the
 * extra memory is a non-issue).
 * --------------------------------------------------------------------- */

#define ND_REASSEMBLY_MAX_LEN 4096u

typedef struct nd_reassembly {
    uint8_t buf[ND_REASSEMBLY_MAX_LEN];
    uint8_t received[ND_REASSEMBLY_MAX_LEN]; /* received[i] != 0 <=> byte i has been written */
    size_t total_len;
    int total_len_known;
    uint8_t msg_type;
    uint16_t message_seq;
    int in_progress;
} nd_reassembly;

void nd_reassembly_init(nd_reassembly *r);

/* Feeds one fragment. hdr->length is the full logical message's length;
 * hdr->fragment_offset/fragment_length locate this fragment within it;
 * fragment points at fragment_length bytes. Starts tracking a new message
 * on the first call (or after nd_reassembly_init); a later fragment whose
 * msg_type/message_seq don't match the one in progress is rejected with
 * ND_ERR_UNSUPPORTED (this minimal build reassembles one message at a
 * time -- a real flight's messages arrive with distinct message_seq
 * values and, in this build's fixed message sequence, aren't reassembled
 * concurrently). Returns ND_ERR_BAD_LENGTH if hdr->length exceeds
 * ND_REASSEMBLY_MAX_LEN or the fragment's range overruns it. */
nd_status nd_reassembly_add_fragment(nd_reassembly *r, const nd_handshake_hdr *hdr, const uint8_t *fragment);

int nd_reassembly_is_complete(const nd_reassembly *r);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_REASSEMBLY_H */
