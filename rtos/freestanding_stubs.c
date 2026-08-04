/* memcpy/memset/strlen for a genuinely libc-free build (-ffreestanding
 * -nostdlib): this repo's crypto (src/crypto/ *.c) is portable C11 that
 * happens to use these three <string.h> functions, and a freestanding
 * environment per the C standard only guarantees <stddef.h>/<stdint.h>-
 * style headers, not <string.h>. Providing real implementations (rather
 * than linking newlib or similar) is the point of this stretch goal: prove
 * the crypto has no hidden OS/libc dependency, not just that *a* libc can
 * satisfy it. Built with -fno-builtin so GCC doesn't recognize these by
 * name and substitute its own intrinsic expansion (which would defeat the
 * "these are the only implementations" claim). */
#include <stddef.h>
#include <stdint.h>

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (size_t i = 0; i < n; ++i) d[i] = (uint8_t)c;
    return dst;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}
