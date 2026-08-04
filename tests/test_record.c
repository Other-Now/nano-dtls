/* Round-trip, hand-verified-bytes, and malformed-input tests for the
 * zero-copy DTLSPlaintext and unified-header record parsers (Stage 1). */
#include "nanodtls/record.h"
#include "test_util.h"

static void test_plaintext_roundtrip(void) {
    nd_plaintext_hdr hdr = {
        .type = ND_CT_HANDSHAKE,
        .legacy_version = ND_VERSION_DTLS1_2,
        .epoch = 1,
        .sequence_number = 0x0102030405ull, /* fits in 48 bits */
        .length = 0,                        /* ignored by serialize */
    };
    const uint8_t fragment[] = {0xde, 0xad, 0xbe, 0xef, 0x00};
    uint8_t buf[64];
    size_t written = 0;

    CHECK(nd_plaintext_serialize(&hdr, fragment, sizeof(fragment), buf, sizeof(buf), &written) ==
          ND_OK);
    CHECK(written == ND_PLAINTEXT_HDR_LEN + sizeof(fragment));

    nd_plaintext_hdr parsed;
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    CHECK(nd_plaintext_parse(buf, written, &parsed, &frag, &frag_len) == ND_OK);
    CHECK(parsed.type == ND_CT_HANDSHAKE);
    CHECK(parsed.legacy_version == ND_VERSION_DTLS1_2);
    CHECK(parsed.epoch == 1);
    CHECK(parsed.sequence_number == 0x0102030405ull);
    CHECK(frag_len == sizeof(fragment));
    CHECK(frag == buf + ND_PLAINTEXT_HDR_LEN); /* zero-copy: points inside buf */
    for (size_t i = 0; i < frag_len; ++i) CHECK(frag[i] == fragment[i]);
}

static void test_plaintext_known_bytes(void) {
    /* Hand-built per RFC 9147 section 4: type, legacy_version, epoch,
     * 48-bit sequence_number, length, then the fragment. */
    uint8_t buf[] = {
        22,          /* type = handshake */
        0xfe, 0xfd,  /* legacy_version = DTLS 1.2 */
        0x00, 0x03,  /* epoch = 3 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, /* sequence_number = 42 */
        0x00, 0x02,  /* length = 2 */
        0xAA, 0xBB,  /* fragment */
    };
    nd_plaintext_hdr hdr;
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    CHECK(nd_plaintext_parse(buf, sizeof(buf), &hdr, &frag, &frag_len) == ND_OK);
    CHECK(hdr.type == ND_CT_HANDSHAKE);
    CHECK(hdr.legacy_version == ND_VERSION_DTLS1_2);
    CHECK(hdr.epoch == 3);
    CHECK(hdr.sequence_number == 42);
    CHECK(hdr.length == 2);
    CHECK(frag_len == 2 && frag[0] == 0xAA && frag[1] == 0xBB);
}

static void test_plaintext_malformed(void) {
    uint8_t short_buf[ND_PLAINTEXT_HDR_LEN - 1] = {0};
    nd_plaintext_hdr hdr;
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    CHECK(nd_plaintext_parse(short_buf, sizeof(short_buf), &hdr, &frag, &frag_len) ==
          ND_ERR_TRUNCATED);

    /* Header claims a 100-byte fragment but the buffer only has 13 bytes total. */
    uint8_t bad_len_buf[ND_PLAINTEXT_HDR_LEN] = {
        22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x64,
    };
    CHECK(nd_plaintext_parse(bad_len_buf, sizeof(bad_len_buf), &hdr, &frag, &frag_len) ==
          ND_ERR_BAD_LENGTH);

    CHECK(nd_plaintext_parse(NULL, 13, &hdr, &frag, &frag_len) == ND_ERR_BAD_ARG);
}

static void test_unified_roundtrip_no_cid(void) {
    nd_unified_hdr hdr = {
        .cid_present = 0,
        .seq_len_is_16bit = 1,
        .length_present = 1,
        .epoch_low2 = 2,
        .cid = NULL,
        .cid_len = 0,
        .sequence_number = 0x1234,
        .length = 0, /* derived from payload_len on serialize */
    };
    const uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t buf[64];
    size_t written = 0;
    CHECK(nd_unified_serialize(&hdr, payload, sizeof(payload), buf, sizeof(buf), &written) ==
          ND_OK);
    CHECK(written == 1 + 2 + 2 + sizeof(payload)); /* first byte + seq16 + len16 + payload */

    nd_unified_hdr parsed;
    const uint8_t *out_payload = NULL;
    size_t out_payload_len = 0;
    CHECK(nd_unified_parse(buf, written, /*cid_len=*/0, &parsed, &out_payload,
                            &out_payload_len) == ND_OK);
    CHECK(parsed.cid_present == 0);
    CHECK(parsed.seq_len_is_16bit == 1);
    CHECK(parsed.length_present == 1);
    CHECK(parsed.epoch_low2 == 2);
    CHECK(parsed.sequence_number == 0x1234);
    CHECK(out_payload_len == sizeof(payload));
    CHECK(out_payload == buf + 5); /* 1 (first byte) + 2 (seq16) + 2 (len16) */
    for (size_t i = 0; i < out_payload_len; ++i) CHECK(out_payload[i] == payload[i]);
}

static void test_unified_roundtrip_with_cid_no_explicit_len(void) {
    const uint8_t cid[] = {0xCA, 0xFE};
    nd_unified_hdr hdr = {
        .cid_present = 1,
        .seq_len_is_16bit = 0,
        .length_present = 0, /* payload runs to end of datagram */
        .epoch_low2 = 3,
        .cid = cid,
        .cid_len = sizeof(cid),
        .sequence_number = 0x7F,
        .length = 0,
    };
    const uint8_t payload[] = {0x11, 0x22, 0x33};
    uint8_t buf[64];
    size_t written = 0;
    CHECK(nd_unified_serialize(&hdr, payload, sizeof(payload), buf, sizeof(buf), &written) ==
          ND_OK);
    CHECK(written == 1 + sizeof(cid) + 1 + sizeof(payload)); /* no explicit length field */

    nd_unified_hdr parsed;
    const uint8_t *out_payload = NULL;
    size_t out_payload_len = 0;
    /* Simulate a UDP datagram: the whole buffer IS the record, so the
     * implicit length must equal the datagram's remaining bytes. */
    CHECK(nd_unified_parse(buf, written, sizeof(cid), &parsed, &out_payload, &out_payload_len) ==
          ND_OK);
    CHECK(parsed.cid_present == 1);
    CHECK(parsed.cid_len == sizeof(cid));
    CHECK(parsed.cid[0] == cid[0] && parsed.cid[1] == cid[1]);
    CHECK(parsed.seq_len_is_16bit == 0);
    CHECK(parsed.sequence_number == 0x7F);
    CHECK(out_payload_len == sizeof(payload));
    for (size_t i = 0; i < out_payload_len; ++i) CHECK(out_payload[i] == payload[i]);
}

static void test_unified_known_bits(void) {
    /* First byte = 0b0010_1101 = 0x2D: fixed 001, C=0, S=1, L=1, EE=01. */
    uint8_t buf[] = {0x2D, 0x00, 0x05, 0x00, 0x01, 0x99};
    nd_unified_hdr hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    CHECK(nd_unified_parse(buf, sizeof(buf), 0, &hdr, &payload, &payload_len) == ND_OK);
    CHECK(hdr.cid_present == 0);
    CHECK(hdr.seq_len_is_16bit == 1);
    CHECK(hdr.length_present == 1);
    CHECK(hdr.epoch_low2 == 1);
    CHECK(hdr.sequence_number == 0x0005);
    CHECK(payload_len == 1);
    CHECK(payload[0] == 0x99);
}

static void test_unified_malformed(void) {
    nd_unified_hdr hdr;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    /* A DTLSPlaintext content-type byte (handshake = 22 = 0x16) does not
     * match the unified-header fixed-bits pattern. */
    uint8_t plaintext_first_byte[] = {0x16, 0, 0, 0};
    CHECK(nd_unified_parse(plaintext_first_byte, sizeof(plaintext_first_byte), 0, &hdr, &payload,
                            &payload_len) == ND_ERR_NOT_UNIFIED);

    /* L=1 declared but only one byte total -- truncated before the length field. */
    uint8_t truncated[] = {0x24};
    CHECK(nd_unified_parse(truncated, sizeof(truncated), 0, &hdr, &payload, &payload_len) ==
          ND_ERR_TRUNCATED);

    /* L=1, 8-bit seq: header itself (first byte + seq + 2-byte length) is
     * fully present, but the declared length (100) says payload follows
     * that isn't actually in the buffer. */
    uint8_t bad_len[] = {0x24, 0x00, 0x00, 0x64};
    CHECK(nd_unified_parse(bad_len, sizeof(bad_len), 0, &hdr, &payload, &payload_len) ==
          ND_ERR_BAD_LENGTH);

    /* C=1 but caller didn't supply the negotiated CID length. */
    uint8_t cid_bit_set[] = {0x30, 0x00, 0x00};
    CHECK(nd_unified_parse(cid_bit_set, sizeof(cid_bit_set), /*cid_len=*/0, &hdr, &payload,
                            &payload_len) == ND_ERR_BAD_ARG);
}

static void test_epoch_reconstruction(void) {
    CHECK(nd_reconstruct_epoch(0, 0) == 0);
    CHECK(nd_reconstruct_epoch(3, 3) == 3);
    CHECK(nd_reconstruct_epoch(3, 0) == 4);   /* rekey just happened: epoch rolled 3 -> 4 */
    CHECK(nd_reconstruct_epoch(4, 3) == 3);   /* a late record from the previous epoch */
    CHECK(nd_reconstruct_epoch(65535, 0) == 65532);
    CHECK(nd_reconstruct_epoch(1, 2) == 2);
}

static void test_sequence_number_reconstruction(void) {
    /* 8-bit wire width: window is 256. */
    CHECK(nd_reconstruct_sequence_number(0, 0, 8) == 0);
    CHECK(nd_reconstruct_sequence_number(5, 6, 8) == 6);           /* next in sequence */
    CHECK(nd_reconstruct_sequence_number(250, 3, 8) == 259);       /* wrapped past 256 */
    CHECK(nd_reconstruct_sequence_number(259, 250, 8) == 250);     /* a late/reordered record, no wrap */
    CHECK(nd_reconstruct_sequence_number(1000, 255, 8) == 1023);   /* closest candidate below 1000+256 */

    /* 16-bit wire width: window is 65536. */
    CHECK(nd_reconstruct_sequence_number(0, 0, 16) == 0);
    CHECK(nd_reconstruct_sequence_number(70000, 0, 16) == 65536);  /* closest multiple-of-65536 base */
    CHECK(nd_reconstruct_sequence_number(65535, 0, 16) == 65536);  /* rolled over by one */

    /* Large values near the 48-bit ceiling still resolve without wrapping
     * past it (the wraparound candidate is rejected by the range check). */
    uint64_t near_ceiling = 0xFFFFFFFFFFFFULL - 5;
    CHECK(nd_reconstruct_sequence_number(near_ceiling, (uint16_t)(near_ceiling & 0xFFFFu), 16) == near_ceiling);
}

int main(void) {
    test_plaintext_roundtrip();
    test_plaintext_known_bytes();
    test_plaintext_malformed();
    test_unified_roundtrip_no_cid();
    test_unified_roundtrip_with_cid_no_explicit_len();
    test_unified_known_bits();
    test_unified_malformed();
    test_epoch_reconstruction();
    test_sequence_number_reconstruction();
    return nd_test_summary("test_record");
}
