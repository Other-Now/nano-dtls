#ifndef NANODTLS_HANDSHAKE_H
#define NANODTLS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HandshakeType (RFC 8446 section 4, as reused by RFC 9147). */
typedef enum nd_handshake_type {
    ND_HS_CLIENT_HELLO = 1,
    ND_HS_SERVER_HELLO = 2,
    ND_HS_NEW_SESSION_TICKET = 4,
    ND_HS_END_OF_EARLY_DATA = 5,
    ND_HS_ENCRYPTED_EXTENSIONS = 8,
    ND_HS_CERTIFICATE = 11,
    ND_HS_CERTIFICATE_REQUEST = 13,
    ND_HS_CERTIFICATE_VERIFY = 15,
    ND_HS_FINISHED = 20,
    ND_HS_KEY_UPDATE = 24,
    ND_HS_MESSAGE_HASH = 254,
} nd_handshake_type;

/* ---------------------------------------------------------------------
 * The DTLS Handshake header (RFC 9147 section 5.2, unchanged from DTLS 1.2 /
 * RFC 6347): the same 4-byte msg_type+length prefix TLS uses, plus three
 * DTLS-only fields for reliability -- message_seq (so retransmitted flights
 * can be matched up and duplicates dropped) and fragment_offset/
 * fragment_length (so one logical handshake message can be split across
 * multiple records to fit the path MTU):
 *
 *   struct {
 *       HandshakeType msg_type;
 *       uint24 length;             -- length of the *whole* logical message
 *       uint16 message_seq;
 *       uint24 fragment_offset;
 *       uint24 fragment_length;    -- length of fragment carried here
 *       opaque fragment[fragment_length];
 *   } Handshake;
 *
 * Parsing is zero-copy, exactly like the record layer: nd_handshake_parse()
 * only returns a pointer into the caller's buffer. Reassembling a message
 * whose fragment_length < length (a message that arrived split across
 * multiple records) is Stage 4 work (out-of-order flight reassembly); this
 * header only frames a single wire-level fragment.
 * --------------------------------------------------------------------- */

#define ND_HANDSHAKE_HDR_LEN 12u

typedef struct nd_handshake_hdr {
    uint8_t msg_type;          /* nd_handshake_type */
    uint32_t length;           /* 24-bit: length of the whole logical message */
    uint16_t message_seq;
    uint32_t fragment_offset;  /* 24-bit */
    uint32_t fragment_length;  /* 24-bit: length of the fragment following this header */
} nd_handshake_hdr;

/* Parses a Handshake header out of buf[0..buf_len). On success, *out_hdr
 * holds the decoded fields and *out_fragment/*out_fragment_len point at the
 * fragment bytes inside buf (no copy). */
nd_status nd_handshake_parse(const uint8_t *buf, size_t buf_len, nd_handshake_hdr *out_hdr,
                              const uint8_t **out_fragment, size_t *out_fragment_len);

/* Serializes a Handshake header + fragment into out_buf. hdr->fragment_length
 * must equal fragment_len (the header is the single source of truth for
 * every wire field; this just catches an inconsistent caller rather than
 * silently overwriting one from the other). */
nd_status nd_handshake_serialize(const nd_handshake_hdr *hdr, const uint8_t *fragment,
                                  size_t fragment_len, uint8_t *out_buf, size_t out_buf_cap,
                                  size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_HANDSHAKE_H */
