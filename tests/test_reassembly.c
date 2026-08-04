/* Out-of-order handshake message fragment reassembly (RFC 9147 section
 * 5.5). */
#include "nanodtls/reassembly.h"

#include "test_util.h"

static nd_handshake_hdr mk_hdr(uint8_t msg_type, uint16_t message_seq, uint32_t length, uint32_t offset,
                                uint32_t frag_len) {
    nd_handshake_hdr hdr;
    hdr.msg_type = msg_type;
    hdr.message_seq = message_seq;
    hdr.length = length;
    hdr.fragment_offset = offset;
    hdr.fragment_length = frag_len;
    return hdr;
}

static void test_single_fragment_whole_message(void) {
    nd_reassembly r;
    nd_reassembly_init(&r);
    const uint8_t msg[] = "whole-message-no-fragmentation";
    nd_handshake_hdr hdr = mk_hdr(11 /* Certificate */, 2, sizeof(msg) - 1, 0, sizeof(msg) - 1);

    CHECK(nd_reassembly_add_fragment(&r, &hdr, msg) == ND_OK);
    CHECK(nd_reassembly_is_complete(&r) == 1);
    CHECK(nd_bytes_eq(r.buf, msg, sizeof(msg) - 1));
}

static void test_in_order_fragments(void) {
    nd_reassembly r;
    nd_reassembly_init(&r);
    const uint8_t part1[] = "first-half-";
    const uint8_t part2[] = "second-half";
    uint32_t total = (uint32_t)(sizeof(part1) - 1 + sizeof(part2) - 1);

    nd_handshake_hdr h1 = mk_hdr(11, 0, total, 0, (uint32_t)(sizeof(part1) - 1));
    CHECK(nd_reassembly_add_fragment(&r, &h1, part1) == ND_OK);
    CHECK(nd_reassembly_is_complete(&r) == 0);

    nd_handshake_hdr h2 = mk_hdr(11, 0, total, (uint32_t)(sizeof(part1) - 1), (uint32_t)(sizeof(part2) - 1));
    CHECK(nd_reassembly_add_fragment(&r, &h2, part2) == ND_OK);
    CHECK(nd_reassembly_is_complete(&r) == 1);

    CHECK(nd_bytes_eq(r.buf, part1, sizeof(part1) - 1));
    CHECK(nd_bytes_eq(r.buf + sizeof(part1) - 1, part2, sizeof(part2) - 1));
}

static void test_out_of_order_fragments(void) {
    nd_reassembly r;
    nd_reassembly_init(&r);
    const uint8_t part1[] = "AAAA";
    const uint8_t part2[] = "BBBB";
    const uint8_t part3[] = "CCCC";
    uint32_t total = 12;

    nd_handshake_hdr h3 = mk_hdr(11, 5, total, 8, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h3, part3) == ND_OK);
    CHECK(nd_reassembly_is_complete(&r) == 0);

    nd_handshake_hdr h1 = mk_hdr(11, 5, total, 0, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h1, part1) == ND_OK);
    CHECK(nd_reassembly_is_complete(&r) == 0);

    nd_handshake_hdr h2 = mk_hdr(11, 5, total, 4, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h2, part2) == ND_OK);
    CHECK(nd_reassembly_is_complete(&r) == 1);

    CHECK(nd_bytes_eq(r.buf, (const uint8_t *)"AAAABBBBCCCC", 12));
}

static void test_duplicate_fragment_is_harmless(void) {
    nd_reassembly r;
    nd_reassembly_init(&r);
    const uint8_t part[] = "XYZ!";
    nd_handshake_hdr h = mk_hdr(11, 0, 4, 0, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h, part) == ND_OK);
    CHECK(nd_reassembly_add_fragment(&r, &h, part) == ND_OK); /* retransmission of the same fragment */
    CHECK(nd_reassembly_is_complete(&r) == 1);
    CHECK(nd_bytes_eq(r.buf, part, 4));
}

static void test_mismatched_message_rejected(void) {
    nd_reassembly r;
    nd_reassembly_init(&r);
    const uint8_t part[] = "AAAA";
    nd_handshake_hdr h1 = mk_hdr(11, 0, 8, 0, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h1, part) == ND_OK);

    nd_handshake_hdr h2 = mk_hdr(15 /* different msg_type: CertificateVerify */, 0, 8, 4, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h2, part) == ND_ERR_UNSUPPORTED);

    nd_handshake_hdr h3 = mk_hdr(11, 1 /* different message_seq */, 8, 4, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h3, part) == ND_ERR_UNSUPPORTED);
}

static void test_bad_length_rejected(void) {
    nd_reassembly r;
    nd_reassembly_init(&r);
    const uint8_t part[] = "AAAA";
    /* fragment_offset + fragment_length overruns the declared total length */
    nd_handshake_hdr h = mk_hdr(11, 0, 4, 2, 4);
    CHECK(nd_reassembly_add_fragment(&r, &h, part) == ND_ERR_BAD_LENGTH);

    nd_handshake_hdr too_big = mk_hdr(11, 0, ND_REASSEMBLY_MAX_LEN + 1, 0, 4);
    CHECK(nd_reassembly_add_fragment(&r, &too_big, part) == ND_ERR_BAD_LENGTH);
}

int main(void) {
    test_single_fragment_whole_message();
    test_in_order_fragments();
    test_out_of_order_fragments();
    test_duplicate_fragment_is_harmless();
    test_mismatched_message_rejected();
    test_bad_length_rejected();
    return nd_test_summary("test_reassembly");
}
