/* See nanodtls/replay.h. */
#include "nanodtls/replay.h"

void nd_replay_window_init(nd_replay_window *w) {
    w->highest_seen = 0;
    w->bitmap = 0;
    w->has_received_any = 0;
}

int nd_replay_window_check(const nd_replay_window *w, uint64_t seq) {
    if (!w->has_received_any) return 1;
    if (seq > w->highest_seen) return 1;
    uint64_t diff = w->highest_seen - seq;
    if (diff >= 64) return 0;
    return ((w->bitmap >> diff) & 1u) == 0;
}

void nd_replay_window_accept(nd_replay_window *w, uint64_t seq) {
    if (!w->has_received_any) {
        w->highest_seen = seq;
        w->bitmap = 1;
        w->has_received_any = 1;
        return;
    }
    if (seq > w->highest_seen) {
        uint64_t shift = seq - w->highest_seen;
        w->bitmap = (shift >= 64) ? 0 : (w->bitmap << shift);
        w->bitmap |= 1u;
        w->highest_seen = seq;
    } else {
        uint64_t diff = w->highest_seen - seq;
        if (diff < 64) w->bitmap |= ((uint64_t)1 << diff);
    }
}
