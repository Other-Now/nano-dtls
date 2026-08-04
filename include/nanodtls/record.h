#ifndef NANODTLS_RECORD_H
#define NANODTLS_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * DTLSPlaintext: the fixed 13-byte record header (RFC 9147 section 4,
 * unchanged from DTLS 1.2 / RFC 6347) used for records sent before the
 * connection is encrypted -- the first ClientHello, HelloRetryRequest, and
 * any DTLSPlaintext ACKs.
 *
 *   struct {
 *       ContentType type;
 *       ProtocolVersion legacy_record_version;
 *       uint16 epoch;
 *       uint48 sequence_number;
 *       uint16 length;
 *       opaque fragment[length];
 *   } DTLSPlaintext;
 *
 * Parsing is zero-copy: nd_plaintext_parse() never allocates or copies the
 * fragment, it only returns a pointer into the caller's buffer.
 * --------------------------------------------------------------------- */

#define ND_PLAINTEXT_HDR_LEN 13u

typedef struct nd_plaintext_hdr {
    uint8_t type;           /* nd_content_type */
    uint16_t legacy_version; /* nd_legacy_version; informational only, RFC 9147 section 4 */
    uint16_t epoch;
    uint64_t sequence_number; /* 48-bit; the top 16 bits are always zero */
    uint16_t length;          /* length of the fragment that follows the header */
} nd_plaintext_hdr;

/* Parses a DTLSPlaintext header out of buf[0..buf_len). On success, *out_hdr
 * holds the decoded fields, and *out_fragment/*out_fragment_len point at the
 * fragment bytes inside buf (no copy). Returns ND_ERR_TRUNCATED if buf_len is
 * smaller than the 13-byte header, ND_ERR_BAD_LENGTH if the header's length
 * field overruns buf_len. */
nd_status nd_plaintext_parse(const uint8_t *buf, size_t buf_len, nd_plaintext_hdr *out_hdr,
                              const uint8_t **out_fragment, size_t *out_fragment_len);

/* Serializes a DTLSPlaintext header + fragment into out_buf. hdr->length is
 * ignored; the wire length field is always set from fragment_len. Returns
 * ND_ERR_BAD_LENGTH if out_buf_cap is too small, ND_ERR_BAD_ARG if
 * hdr->sequence_number doesn't fit in 48 bits. */
nd_status nd_plaintext_serialize(const nd_plaintext_hdr *hdr, const uint8_t *fragment,
                                  size_t fragment_len, uint8_t *out_buf, size_t out_buf_cap,
                                  size_t *out_len);

/* ---------------------------------------------------------------------
 * DTLSCiphertext unified header (RFC 9147 section 4, Figure 4) -- the compact
 * bitfield header used for every encrypted record after epoch 0:
 *
 *   0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+
 *  |0|0|1|C|S|L|E E|
 *  +-+-+-+-+-+-+-+-+
 *  | Connection ID |  variable length, present only if C == 1; the length
 *  | (if any)      |  itself is negotiated out-of-band, so the caller
 *  +-+-+-+-+-+-+-+-+  supplies it (cid_len)
 *  | 8 or 16 bit   |  16-bit if S == 1, else 8-bit
 *  |Sequence Number|
 *  +-+-+-+-+-+-+-+-+
 *  | 16 bit        |  present only if L == 1; otherwise the payload runs
 *  | Length (opt)  |  to the end of the datagram
 *  +-+-+-+-+-+-+-+-+
 *  | Encrypted payload ... |
 *
 * Only the low 2 bits of the epoch travel on the wire (E E); the full epoch
 * is reconstructed against the highest epoch seen so far with
 * nd_reconstruct_epoch(), the same "closest candidate to a known reference"
 * technique used to reconstruct wrapped sequence counters elsewhere.
 * --------------------------------------------------------------------- */

#define ND_UNIFIED_FIXED_BITS_MASK 0xE0u
#define ND_UNIFIED_FIXED_BITS_VAL 0x20u
#define ND_UNIFIED_CID_BIT 0x10u
#define ND_UNIFIED_SEQLEN_BIT 0x08u
#define ND_UNIFIED_LEN_BIT 0x04u
#define ND_UNIFIED_EPOCH_MASK 0x03u

typedef struct nd_unified_hdr {
    int cid_present;         /* C bit */
    int seq_len_is_16bit;    /* S bit: 0 -> 8-bit sequence number, 1 -> 16-bit */
    int length_present;      /* L bit */
    uint8_t epoch_low2;      /* E E: low 2 bits of the epoch, as seen on the wire */
    const uint8_t *cid;      /* points into the parsed buffer if cid_present, else NULL */
    size_t cid_len;
    uint16_t sequence_number; /* widened to 16 bits regardless of wire width */
    uint16_t length;          /* payload length, whether explicit or datagram-implied */
} nd_unified_hdr;

/* Parses a unified header out of buf[0..buf_len). cid_len is the
 * out-of-band-negotiated connection-ID length for this connection (0 if none
 * was negotiated) -- the wire format has no self-describing CID length.
 * Returns ND_ERR_NOT_UNIFIED if the fixed top bits don't match, otherwise the
 * same truncated/bad-length semantics as nd_plaintext_parse(). */
nd_status nd_unified_parse(const uint8_t *buf, size_t buf_len, size_t cid_len,
                            nd_unified_hdr *out_hdr, const uint8_t **out_payload,
                            size_t *out_payload_len);

/* Serializes a unified header + payload into out_buf. */
nd_status nd_unified_serialize(const nd_unified_hdr *hdr, const uint8_t *payload,
                                size_t payload_len, uint8_t *out_buf, size_t out_buf_cap,
                                size_t *out_len);

/* Reconstructs the full 16-bit epoch from its low 2 wire bits, choosing the
 * candidate closest to highest_known_epoch (ties broken toward the lower
 * value). Mirrors the epoch/sequence-number reconstruction described in
 * RFC 9147 section 4.2.2. */
uint16_t nd_reconstruct_epoch(uint16_t highest_known_epoch, uint8_t wire_low2);

/* Same "closest candidate to a known reference" technique, applied to the
 * sequence number: the wire only carries the low 8 or 16 bits (wire_bits)
 * of the true 48-bit sequence_number (RFC 9147 section 4.2.2), so the full
 * value is reconstructed against the highest sequence number seen so far
 * for the current epoch. wire_bits must be 8 or 16. */
uint64_t nd_reconstruct_sequence_number(uint64_t highest_known_sequence, uint16_t wire_value, int wire_bits);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_RECORD_H */
