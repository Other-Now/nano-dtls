/* Anti-replay sliding window (RFC 9147 section 4.3): same shape as the
 * gap/duplicate detection this project's PLAN.md points to from prior
 * market-data work (Binance depth-sync U/u/pu gap checks, NSE
 * sequence-continuity), applied here to DTLS record sequence numbers. */
#include "nanodtls/replay.h"

#include "test_util.h"

static void test_monotonic_sequence_all_fresh(void) {
    nd_replay_window w;
    nd_replay_window_init(&w);
    for (uint64_t seq = 0; seq < 200; ++seq) {
        CHECK(nd_replay_window_check(&w, seq) == 1);
        nd_replay_window_accept(&w, seq);
        CHECK(nd_replay_window_check(&w, seq) == 0); /* immediately a duplicate once accepted */
    }
}

static void test_duplicate_rejected(void) {
    nd_replay_window w;
    nd_replay_window_init(&w);
    nd_replay_window_accept(&w, 10);
    CHECK(nd_replay_window_check(&w, 10) == 0);
    nd_replay_window_accept(&w, 11);
    CHECK(nd_replay_window_check(&w, 10) == 0);
}

static void test_reordered_within_window_accepted_once(void) {
    nd_replay_window w;
    nd_replay_window_init(&w);
    nd_replay_window_accept(&w, 100);
    /* records 90..99 arrive late, out of order -- each fresh exactly once */
    for (uint64_t seq = 99; seq >= 90; --seq) {
        CHECK(nd_replay_window_check(&w, seq) == 1);
        nd_replay_window_accept(&w, seq);
        CHECK(nd_replay_window_check(&w, seq) == 0);
    }
}

static void test_too_old_rejected(void) {
    nd_replay_window w;
    nd_replay_window_init(&w);
    nd_replay_window_accept(&w, 1000);
    CHECK(nd_replay_window_check(&w, 1000 - 64) == 0); /* exactly at the edge: outside the 64-window */
    CHECK(nd_replay_window_check(&w, 1000 - 63) == 1); /* just inside */
}

static void test_window_slides_forward(void) {
    nd_replay_window w;
    nd_replay_window_init(&w);
    nd_replay_window_accept(&w, 5);
    nd_replay_window_accept(&w, 3); /* reordered, within window */
    CHECK(nd_replay_window_check(&w, 3) == 0);

    nd_replay_window_accept(&w, 5 + 64); /* slides the window far forward */
    CHECK(nd_replay_window_check(&w, 3) == 0);  /* now outside the window: treated as not-fresh either way */
    CHECK(nd_replay_window_check(&w, 5) == 0);  /* also now outside the window */
    CHECK(nd_replay_window_check(&w, 5 + 64) == 0); /* the new high-water mark itself, already accepted */
    CHECK(nd_replay_window_check(&w, 5 + 63) == 1); /* just inside the slid window, never seen */
}

static void test_first_record_at_nonzero_sequence(void) {
    /* A connection's first-ever accepted record need not be sequence 0
     * (Stage 4 doesn't mandate starting from 0 for every epoch); the
     * window must still behave sanely. */
    nd_replay_window w;
    nd_replay_window_init(&w);
    CHECK(nd_replay_window_check(&w, 500) == 1);
    nd_replay_window_accept(&w, 500);
    CHECK(nd_replay_window_check(&w, 500) == 0);
    CHECK(nd_replay_window_check(&w, 501) == 1);
}

int main(void) {
    test_monotonic_sequence_all_fresh();
    test_duplicate_rejected();
    test_reordered_within_window_accepted_once();
    test_too_old_rejected();
    test_window_slides_forward();
    test_first_record_at_nonzero_sequence();
    return nd_test_summary("test_replay");
}
