/* Round-trip, hand-verified-bytes, and malformed-input tests for the DTLS
 * Handshake header (RFC 9147 section 5.2). */
#include "nanodtls/handshake.h"
#include "test_util.h"

static void test_roundtrip_unfragmented(void) {
    nd_handshake_hdr hdr = {
        .msg_type = ND_HS_CLIENT_HELLO,
        .length = 5,
        .message_seq = 0,
        .fragment_offset = 0,
        .fragment_length = 5,
    };
    const uint8_t fragment[] = {1, 2, 3, 4, 5};
    uint8_t buf[64];
    size_t written = 0;

    CHECK(nd_handshake_serialize(&hdr, fragment, sizeof(fragment), buf, sizeof(buf), &written) ==
          ND_OK);
    CHECK(written == ND_HANDSHAKE_HDR_LEN + sizeof(fragment));

    nd_handshake_hdr parsed;
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    CHECK(nd_handshake_parse(buf, written, &parsed, &frag, &frag_len) == ND_OK);
    CHECK(parsed.msg_type == ND_HS_CLIENT_HELLO);
    CHECK(parsed.length == 5);
    CHECK(parsed.message_seq == 0);
    CHECK(parsed.fragment_offset == 0);
    CHECK(parsed.fragment_length == 5);
    CHECK(frag_len == sizeof(fragment));
    CHECK(frag == buf + ND_HANDSHAKE_HDR_LEN);
    for (size_t i = 0; i < frag_len; ++i) CHECK(frag[i] == fragment[i]);
}

static void test_roundtrip_fragment_of_a_larger_message(void) {
    /* A message_seq=3 ServerHello, logically 300 bytes, of which this wire
     * fragment carries bytes [100,150) -- fragment_offset=100,
     * fragment_length=50, but length=300 (the whole message). */
    nd_handshake_hdr hdr = {
        .msg_type = ND_HS_SERVER_HELLO,
        .length = 300,
        .message_seq = 3,
        .fragment_offset = 100,
        .fragment_length = 50,
    };
    uint8_t fragment[50];
    for (size_t i = 0; i < sizeof(fragment); ++i) fragment[i] = (uint8_t)i;
    uint8_t buf[128];
    size_t written = 0;
    CHECK(nd_handshake_serialize(&hdr, fragment, sizeof(fragment), buf, sizeof(buf), &written) ==
          ND_OK);

    nd_handshake_hdr parsed;
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    CHECK(nd_handshake_parse(buf, written, &parsed, &frag, &frag_len) == ND_OK);
    CHECK(parsed.msg_type == ND_HS_SERVER_HELLO);
    CHECK(parsed.length == 300);
    CHECK(parsed.message_seq == 3);
    CHECK(parsed.fragment_offset == 100);
    CHECK(parsed.fragment_length == 50);
    CHECK(frag_len == 50);
}

static void test_known_bytes(void) {
    /* Hand-built per RFC 9147 section 5.2: msg_type, 24-bit length,
     * 16-bit message_seq, 24-bit fragment_offset, 24-bit fragment_length,
     * then the fragment. */
    uint8_t buf[] = {
        2,          /* msg_type = server_hello */
        0x00, 0x00, 0x02, /* length = 2 */
        0x00, 0x07,       /* message_seq = 7 */
        0x00, 0x00, 0x00, /* fragment_offset = 0 */
        0x00, 0x00, 0x02, /* fragment_length = 2 */
        0xAA, 0xBB,       /* fragment */
    };
    nd_handshake_hdr hdr;
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    CHECK(nd_handshake_parse(buf, sizeof(buf), &hdr, &frag, &frag_len) == ND_OK);
    CHECK(hdr.msg_type == ND_HS_SERVER_HELLO);
    CHECK(hdr.length == 2);
    CHECK(hdr.message_seq == 7);
    CHECK(hdr.fragment_offset == 0);
    CHECK(hdr.fragment_length == 2);
    CHECK(frag_len == 2 && frag[0] == 0xAA && frag[1] == 0xBB);
}

static void test_malformed(void) {
    uint8_t short_buf[ND_HANDSHAKE_HDR_LEN - 1] = {0};
    nd_handshake_hdr hdr;
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    CHECK(nd_handshake_parse(short_buf, sizeof(short_buf), &hdr, &frag, &frag_len) ==
          ND_ERR_TRUNCATED);

    /* fragment_length claims 100 bytes but the buffer only has the 12-byte header. */
    uint8_t bad_len_buf[ND_HANDSHAKE_HDR_LEN] = {
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x64,
    };
    CHECK(nd_handshake_parse(bad_len_buf, sizeof(bad_len_buf), &hdr, &frag, &frag_len) ==
          ND_ERR_BAD_LENGTH);

    CHECK(nd_handshake_parse(NULL, 12, &hdr, &frag, &frag_len) == ND_ERR_BAD_ARG);

    /* serialize must reject a header whose fragment_length disagrees with
     * the fragment buffer actually supplied. */
    nd_handshake_hdr mismatched = {
        .msg_type = ND_HS_FINISHED, .length = 5, .fragment_length = 5,
    };
    uint8_t fragment[3] = {0};
    uint8_t out[32];
    size_t out_len = 0;
    CHECK(nd_handshake_serialize(&mismatched, fragment, 3, out, sizeof(out), &out_len) ==
          ND_ERR_BAD_ARG);
}

int main(void) {
    test_roundtrip_unfragmented();
    test_roundtrip_fragment_of_a_larger_message();
    test_known_bytes();
    test_malformed();
    return nd_test_summary("test_handshake");
}
