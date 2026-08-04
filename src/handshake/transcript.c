#include "nanodtls/transcript.h"

void nd_transcript_init(nd_transcript *t) { nd_sha256_init(&t->ctx); }

void nd_transcript_add(nd_transcript *t, const uint8_t *msg, size_t msg_len) {
    nd_sha256_update(&t->ctx, msg, msg_len);
}

void nd_transcript_snapshot(const nd_transcript *t, uint8_t out_hash[ND_HASH_LEN]) {
    nd_sha256_ctx copy = t->ctx; /* nd_sha256_ctx is a plain struct: a shallow copy is a
                                  * real independent snapshot, no aliasing with t->ctx */
    nd_sha256_final(&copy, out_hash);
}
