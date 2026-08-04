#ifndef ND_FUZZ_UTIL_H
#define ND_FUZZ_UTIL_H
/* Shared driver for every fuzz/fuzz_*.c harness in this repo.
 *
 * Each harness exports the standard `LLVMFuzzerTestOneInput(data, size)`
 * entry point libFuzzer/AFL++ expect, so it's ready to run under a real
 * fuzzer (`clang -fsanitize=fuzzer,address fuzz_record.c ... `) -- but
 * neither is installed in the environment this repo was built in, and
 * "the entry point exists" isn't the same claim as "this was fuzzed".
 * ND_FUZZ_MAIN below compiles to a real, standalone, deterministic stress
 * driver instead: a small xorshift64 PRNG generates a large volume of
 * pseudo-random inputs and feeds every one through
 * LLVMFuzzerTestOneInput, actually exercising the parser now, in this
 * repo's own CI, rather than leaving that only for whoever eventually has
 * libFuzzer available. See PLAN.md/README "Honest scope" for this
 * distinction stated plainly. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t nd_fuzz_rng_state = 0x9E3779B97F4A7C15ULL;

static uint64_t nd_fuzz_xorshift64(void) {
    nd_fuzz_rng_state ^= nd_fuzz_rng_state << 13;
    nd_fuzz_rng_state ^= nd_fuzz_rng_state >> 7;
    nd_fuzz_rng_state ^= nd_fuzz_rng_state << 17;
    return nd_fuzz_rng_state;
}

/* Defines main() for a standalone stress run: `argv[1]` (optional) overrides
 * the iteration count (default 500000), `argv[2]` (optional) overrides the
 * PRNG seed for reproducing a specific run. Every parser this repo fuzzes
 * takes a fixed-size-or-smaller buffer, so a 1024-byte scratch buffer with
 * a random length each iteration covers every code path's length checks
 * (truncated, exact, and oversized-relative-to-declared-lengths inputs all
 * occur naturally as the PRNG explores the space). */
#define ND_FUZZ_MAIN(label)                                                                                     \
    int main(int argc, char **argv) {                                                                           \
        long iterations = 500000;                                                                               \
        if (argc > 1) iterations = atol(argv[1]);                                                               \
        if (argc > 2) nd_fuzz_rng_state = (uint64_t)strtoull(argv[2], NULL, 0);                                 \
        uint8_t buf[1024];                                                                                      \
        for (long i = 0; i < iterations; ++i) {                                                                 \
            size_t len = (size_t)(nd_fuzz_xorshift64() % sizeof(buf));                                          \
            for (size_t j = 0; j < len; ++j) buf[j] = (uint8_t)(nd_fuzz_xorshift64() & 0xffu);                  \
            LLVMFuzzerTestOneInput(buf, len);                                                                    \
        }                                                                                                        \
        printf("%s: %ld pseudo-random inputs fed, no crash/hang/sanitizer trip\n", label, iterations);          \
        return 0;                                                                                                \
    }

#endif /* ND_FUZZ_UTIL_H */
