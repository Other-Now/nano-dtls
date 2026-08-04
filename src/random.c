/* See nanodtls/random.h. */
#include "nanodtls/random.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

nd_status nd_random_bytes(uint8_t *out, size_t len) {
    if (!out) return ND_ERR_BAD_ARG;
    if (len == 0) return ND_OK;
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? ND_OK : ND_ERR_BAD_ARG; /* 0 == STATUS_SUCCESS */
}

#else
#include <stdio.h>

nd_status nd_random_bytes(uint8_t *out, size_t len) {
    if (!out) return ND_ERR_BAD_ARG;
    if (len == 0) return ND_OK;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return ND_ERR_BAD_ARG;
    size_t got = fread(out, 1, len, f);
    fclose(f);
    return (got == len) ? ND_OK : ND_ERR_BAD_ARG;
}

#endif
