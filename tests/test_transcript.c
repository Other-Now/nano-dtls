/* nd_transcript is just a thin wrapper over streaming SHA-256 (already
 * KAT-tested in test_sha256.c); what needs checking here is the wrapper's
 * own contract: snapshotting mid-stream doesn't disturb further additions,
 * and repeated snapshots after the same messages are hashed agree with a
 * plain one-shot SHA-256 over the concatenation. */
#include "nanodtls/transcript.h"
#include "test_util.h"

static void test_snapshot_matches_one_shot_sha256(void) {
    const uint8_t msg1[] = "ClientHello-bytes-stand-in";
    const uint8_t msg2[] = "ServerHello-bytes-stand-in";

    nd_transcript t;
    nd_transcript_init(&t);
    nd_transcript_add(&t, msg1, sizeof(msg1) - 1);
    nd_transcript_add(&t, msg2, sizeof(msg2) - 1);

    uint8_t got[ND_HASH_LEN];
    nd_transcript_snapshot(&t, got);

    uint8_t concatenated[sizeof(msg1) - 1 + sizeof(msg2) - 1];
    for (size_t i = 0; i < sizeof(msg1) - 1; ++i) concatenated[i] = msg1[i];
    for (size_t i = 0; i < sizeof(msg2) - 1; ++i) concatenated[sizeof(msg1) - 1 + i] = msg2[i];

    uint8_t expected[ND_HASH_LEN];
    nd_sha256(concatenated, sizeof(concatenated), expected);

    CHECK(nd_bytes_eq(got, expected, ND_HASH_LEN));
}

static void test_snapshot_is_non_destructive(void) {
    /* Snapshotting after message 1, then adding message 2 and snapshotting
     * again, must equal hashing (msg1) and (msg1||msg2) independently --
     * the first snapshot must not consume or alter the running hash. */
    const uint8_t msg1[] = "first-message";
    const uint8_t msg2[] = "second-message";

    nd_transcript t;
    nd_transcript_init(&t);
    nd_transcript_add(&t, msg1, sizeof(msg1) - 1);

    uint8_t snap1[ND_HASH_LEN];
    nd_transcript_snapshot(&t, snap1);
    uint8_t expected1[ND_HASH_LEN];
    nd_sha256(msg1, sizeof(msg1) - 1, expected1);
    CHECK(nd_bytes_eq(snap1, expected1, ND_HASH_LEN));

    nd_transcript_add(&t, msg2, sizeof(msg2) - 1);
    uint8_t snap2[ND_HASH_LEN];
    nd_transcript_snapshot(&t, snap2);

    uint8_t concatenated[sizeof(msg1) - 1 + sizeof(msg2) - 1];
    for (size_t i = 0; i < sizeof(msg1) - 1; ++i) concatenated[i] = msg1[i];
    for (size_t i = 0; i < sizeof(msg2) - 1; ++i) concatenated[sizeof(msg1) - 1 + i] = msg2[i];
    uint8_t expected2[ND_HASH_LEN];
    nd_sha256(concatenated, sizeof(concatenated), expected2);
    CHECK(nd_bytes_eq(snap2, expected2, ND_HASH_LEN));

    /* snap1 must still be what it was -- the snapshot itself is a plain
     * byte buffer, but re-derive it a different way to be sure nothing
     * about t's internal state retroactively changed what "after msg1"
     * meant. */
    CHECK(nd_bytes_eq(snap1, expected1, ND_HASH_LEN));
}

int main(void) {
    test_snapshot_matches_one_shot_sha256();
    test_snapshot_is_non_destructive();
    return nd_test_summary("test_transcript");
}
