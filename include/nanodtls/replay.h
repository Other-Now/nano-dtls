#ifndef NANODTLS_REPLAY_H
#define NANODTLS_REPLAY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * Anti-replay sliding window (RFC 9147 section 4.3), one per epoch: a
 * 64-record bitmap trailing the highest sequence number accepted so far.
 * Same "gap/duplicate detection over a reordered stream" shape as
 * Binance depth-sync gap detection or NSE sequence-continuity checks (see
 * PLAN.md) -- here applied to DTLS record sequence numbers instead of
 * market-data update IDs.
 *
 * Two-phase by design: nd_replay_window_check() is a cheap pre-filter
 * callers should run BEFORE spending an AEAD decrypt on a record (RFC 9147
 * section 4.3 recommends exactly this, to avoid wasting work on an obvious
 * replay); nd_replay_window_accept() must only be called AFTER that
 * record's AEAD tag has verified. Marking a sequence number "seen" before
 * authenticating it would let an attacker learn something about window
 * state from unauthenticated traffic alone.
 * --------------------------------------------------------------------- */

typedef struct nd_replay_window {
    uint64_t highest_seen;
    uint64_t bitmap;   /* bit i set <=> sequence (highest_seen - i) has been accepted, i in [0,63] */
    int has_received_any;
} nd_replay_window;

void nd_replay_window_init(nd_replay_window *w);

/* Returns 1 if seq is not a replay and not too old to track (fresh: either
 * a new high-water mark, or within the 64-record trailing window and not
 * yet marked seen); 0 if it's a duplicate or falls outside the window. */
int nd_replay_window_check(const nd_replay_window *w, uint64_t seq);

/* Marks seq as seen, advancing highest_seen and shifting the bitmap if seq
 * is a new high-water mark. */
void nd_replay_window_accept(nd_replay_window *w, uint64_t seq);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_REPLAY_H */
