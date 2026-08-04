#ifndef NANODTLS_ACK_H
#define NANODTLS_ACK_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * ACK message (RFC 9147 section 7): DTLS 1.3's reliability signal, sent as
 * content_type ND_CT_ACK (26) -- as a DTLSPlaintext record at epoch 0
 * (acking a ClientHello/HelloRetryRequest) or as a protected record at
 * later epochs.
 *
 *   struct {
 *       RecordNumber record_numbers<0..2^16-1>;
 *   } ACK;
 *
 *   struct {
 *       uint64 epoch;
 *       uint64 sequence_number;
 *   } RecordNumber;
 *
 * Note RecordNumber carries the full *reconstructed* 64-bit epoch and
 * sequence number, not the truncated bits a unified header puts on the
 * wire (see nd_reconstruct_epoch/nd_reconstruct_sequence_number).
 * --------------------------------------------------------------------- */

#define ND_ACK_MAX_RECORDS 32u /* generous for this build's short handshake flights */

typedef struct nd_record_number {
    uint64_t epoch;
    uint64_t sequence_number;
} nd_record_number;

typedef struct nd_ack {
    nd_record_number records[ND_ACK_MAX_RECORDS];
    size_t count;
} nd_ack;

nd_status nd_ack_serialize(const nd_ack *ack, uint8_t *out_buf, size_t out_buf_cap, size_t *out_len);
/* Returns ND_ERR_UNSUPPORTED if the wire list has more than
 * ND_ACK_MAX_RECORDS entries. */
nd_status nd_ack_parse(const uint8_t *buf, size_t buf_len, nd_ack *out_ack);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_ACK_H */
