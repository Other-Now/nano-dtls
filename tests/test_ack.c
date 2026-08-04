/* ACK message (RFC 9147 section 7): a flat list of {epoch, sequence_number}
 * RecordNumber pairs. */
#include "nanodtls/ack.h"

#include "test_util.h"

static void test_roundtrip_multiple_records(void) {
    nd_ack ack;
    ack.count = 3;
    ack.records[0].epoch = 0;
    ack.records[0].sequence_number = 0;
    ack.records[1].epoch = 2;
    ack.records[1].sequence_number = 1;
    ack.records[2].epoch = 2;
    ack.records[2].sequence_number = 0xFFFFFFFFFFULL;

    uint8_t buf[128];
    size_t len;
    CHECK(nd_ack_serialize(&ack, buf, sizeof(buf), &len) == ND_OK);
    CHECK(len == 2 + 3 * 16);

    nd_ack parsed;
    CHECK(nd_ack_parse(buf, len, &parsed) == ND_OK);
    CHECK(parsed.count == 3);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(parsed.records[i].epoch == ack.records[i].epoch);
        CHECK(parsed.records[i].sequence_number == ack.records[i].sequence_number);
    }
}

static void test_empty_ack(void) {
    nd_ack ack;
    ack.count = 0;
    uint8_t buf[8];
    size_t len;
    CHECK(nd_ack_serialize(&ack, buf, sizeof(buf), &len) == ND_OK);
    CHECK(len == 2);
    CHECK(buf[0] == 0 && buf[1] == 0);

    nd_ack parsed;
    CHECK(nd_ack_parse(buf, len, &parsed) == ND_OK);
    CHECK(parsed.count == 0);
}

static void test_known_bytes(void) {
    /* One RecordNumber {epoch=2, sequence_number=5}: list_len=16, then
     * epoch as 8 big-endian bytes, then sequence_number as 8 big-endian
     * bytes. */
    uint8_t buf[18] = {0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 5};
    nd_ack parsed;
    CHECK(nd_ack_parse(buf, sizeof(buf), &parsed) == ND_OK);
    CHECK(parsed.count == 1);
    CHECK(parsed.records[0].epoch == 2);
    CHECK(parsed.records[0].sequence_number == 5);
}

static void test_malformed(void) {
    nd_ack parsed;
    uint8_t truncated[1] = {0};
    CHECK(nd_ack_parse(truncated, sizeof(truncated), &parsed) == ND_ERR_TRUNCATED);

    uint8_t bad_len[4] = {0x00, 0x05, 0, 0}; /* list_len=5, not a multiple of 16 */
    CHECK(nd_ack_parse(bad_len, sizeof(bad_len), &parsed) == ND_ERR_BAD_LENGTH);

    uint8_t overrun[4] = {0x00, 0x10, 0, 0}; /* claims 16 bytes but buffer is shorter */
    CHECK(nd_ack_parse(overrun, sizeof(overrun), &parsed) == ND_ERR_BAD_LENGTH);
}

static void test_serialize_rejects_too_many_records(void) {
    nd_ack ack;
    ack.count = ND_ACK_MAX_RECORDS + 1;
    uint8_t buf[4096];
    size_t len;
    CHECK(nd_ack_serialize(&ack, buf, sizeof(buf), &len) == ND_ERR_BAD_ARG);
}

int main(void) {
    test_roundtrip_multiple_records();
    test_empty_ack();
    test_known_bytes();
    test_malformed();
    test_serialize_rejects_too_many_records();
    return nd_test_summary("test_ack");
}
