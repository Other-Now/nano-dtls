#ifndef ND_TEST_UTIL_H
#define ND_TEST_UTIL_H
/* Minimal header-only test harness -- keeps the project dependency-free. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static int nd_test_checks = 0;
static int nd_test_failures = 0;

static void nd_test_check(int cond, const char *expr, const char *file, int line) {
    nd_test_checks++;
    if (!cond) {
        nd_test_failures++;
        fprintf(stderr, "FAIL %s:%d  %s\n", file, line, expr);
    }
}

#define CHECK(cond) nd_test_check((cond), #cond, __FILE__, __LINE__)

static int nd_test_summary(const char *suite) {
    printf("[%s] %d checks, %d failures\n", suite, nd_test_checks, nd_test_failures);
    return nd_test_failures == 0 ? 0 : 1;
}

/* Decodes a hex string (spaces/colons/newlines ignored) into bytes, so KAT
 * vectors can be pasted close to verbatim from an RFC rather than
 * hand-reformatted into C hex-literal arrays -- fewer transcription
 * mistakes, and easy to eyeball-diff against the source text. Returns the
 * number of bytes decoded. */
static size_t nd_hex_decode(const char *hex, uint8_t *out, size_t out_cap) {
    size_t n = 0;
    int hi = -1;
    for (const char *p = hex; *p; ++p) {
        char c = *p;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_cap) break;
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    return n;
}

static int nd_bytes_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; ++i)
        if (a[i] != b[i]) return 0;
    return 1;
}

#endif /* ND_TEST_UTIL_H */
