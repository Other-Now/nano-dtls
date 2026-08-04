/* Poly1305 per RFC 8439 section 2.5, using the widely-used radix-2^26,
 * five-limb representation of the 130-bit accumulator and modulus
 * p = 2^130 - 5. Every product stays inside a uint64_t (no __int128, no
 * platform-specific wide-multiply intrinsic), so this is portable to MSVC
 * as well as GCC/Clang -- which is the whole reason to use this radix
 * instead of straight 64-bit-limb schoolbook arithmetic. */
#include "nanodtls/poly1305.h"

#include <string.h>

#define MASK26 0x3ffffffu

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static void clamp_r(uint8_t r[16]) {
    r[3] &= 15;  r[7] &= 15;  r[11] &= 15; r[15] &= 15;
    r[4] &= 252; r[8] &= 252; r[12] &= 252;
}

/* Splits a 17-byte little-endian buffer (16 message/key bytes plus the
 * appended high bit used for message blocks, 0 for the r key) into five
 * 26-bit limbs: limb i covers wire bits [26i, 26i+26). */
static void bytes_to_limbs(const uint8_t buf[17], uint32_t t[5]) {
    t[0] = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
           (((uint32_t)buf[3] & 0x03) << 24);
    t[1] = ((uint32_t)buf[3] >> 2) | ((uint32_t)buf[4] << 6) | ((uint32_t)buf[5] << 14) |
           (((uint32_t)buf[6] & 0x0f) << 22);
    t[2] = ((uint32_t)buf[6] >> 4) | ((uint32_t)buf[7] << 4) | ((uint32_t)buf[8] << 12) |
           (((uint32_t)buf[9] & 0x3f) << 20);
    t[3] = ((uint32_t)buf[9] >> 6) | ((uint32_t)buf[10] << 2) | ((uint32_t)buf[11] << 10) |
           ((uint32_t)buf[12] << 18);
    t[4] = (uint32_t)buf[13] | ((uint32_t)buf[14] << 8) | ((uint32_t)buf[15] << 16) |
           ((uint32_t)buf[16] << 24);
}

/* h = (h * r) mod p, folding the top half of the product back in with the
 * identity 2^130 = 5 (mod p) via the precomputed s[i] = r[i+1] * 5. */
static void poly1305_mulmod(uint32_t h[5], const uint32_t r[5], const uint32_t s[4]) {
    uint64_t d0 = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * s[3] + (uint64_t)h[2] * s[2] +
                  (uint64_t)h[3] * s[1] + (uint64_t)h[4] * s[0];
    uint64_t d1 = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * s[3] +
                  (uint64_t)h[3] * s[2] + (uint64_t)h[4] * s[1];
    uint64_t d2 = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] +
                  (uint64_t)h[3] * s[3] + (uint64_t)h[4] * s[2];
    uint64_t d3 = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] +
                  (uint64_t)h[3] * r[0] + (uint64_t)h[4] * s[3];
    uint64_t d4 = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + (uint64_t)h[2] * r[2] +
                  (uint64_t)h[3] * r[1] + (uint64_t)h[4] * r[0];

    uint64_t carry;
    carry = d0 >> 26; h[0] = (uint32_t)(d0 & MASK26); d1 += carry;
    carry = d1 >> 26; h[1] = (uint32_t)(d1 & MASK26); d2 += carry;
    carry = d2 >> 26; h[2] = (uint32_t)(d2 & MASK26); d3 += carry;
    carry = d3 >> 26; h[3] = (uint32_t)(d3 & MASK26); d4 += carry;
    carry = d4 >> 26; h[4] = (uint32_t)(d4 & MASK26);
    h[0] += (uint32_t)(carry * 5);
    carry = h[0] >> 26; h[0] &= MASK26; h[1] += (uint32_t)carry;
}

static void process_full_block(nd_poly1305_ctx *ctx, const uint8_t block[16]) {
    uint8_t block17[17];
    memcpy(block17, block, 16);
    block17[16] = 0x01;
    uint32_t t[5];
    bytes_to_limbs(block17, t);
    for (int i = 0; i < 5; ++i) ctx->h[i] += t[i];
    poly1305_mulmod(ctx->h, ctx->r, ctx->s);
}

void nd_poly1305_init(nd_poly1305_ctx *ctx, const uint8_t key[ND_POLY1305_KEY_LEN]) {
    uint8_t r_bytes[16];
    memcpy(r_bytes, key, 16);
    clamp_r(r_bytes);

    uint8_t r17[17];
    memcpy(r17, r_bytes, 16);
    r17[16] = 0;
    bytes_to_limbs(r17, ctx->r);
    ctx->s[0] = ctx->r[1] * 5;
    ctx->s[1] = ctx->r[2] * 5;
    ctx->s[2] = ctx->r[3] * 5;
    ctx->s[3] = ctx->r[4] * 5;

    memset(ctx->h, 0, sizeof(ctx->h));
    memcpy(ctx->pad, key + 16, 16);
    ctx->buf_len = 0;
}

void nd_poly1305_update(nd_poly1305_ctx *ctx, const uint8_t *data, size_t len) {
    if (len == 0) return;

    if (ctx->buf_len) {
        size_t take = 16 - ctx->buf_len;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == 16) {
            process_full_block(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }

    while (len >= 16) {
        process_full_block(ctx, data);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

void nd_poly1305_final(nd_poly1305_ctx *ctx, uint8_t out_tag[ND_POLY1305_TAG_LEN]) {
    if (ctx->buf_len > 0) {
        uint8_t block17[17];
        memset(block17, 0, sizeof(block17));
        memcpy(block17, ctx->buf, ctx->buf_len);
        block17[ctx->buf_len] = 0x01;
        uint32_t t[5];
        bytes_to_limbs(block17, t);
        for (int i = 0; i < 5; ++i) ctx->h[i] += t[i];
        poly1305_mulmod(ctx->h, ctx->r, ctx->s);
    }

    uint32_t h[5];
    memcpy(h, ctx->h, sizeof(h));

    /* One more full carry pass so every limb is canonically < 2^26 before
     * the exact (non-modular) comparison against p below. */
    uint32_t c;
    c = h[1] >> 26; h[1] &= MASK26; h[2] += c;
    c = h[2] >> 26; h[2] &= MASK26; h[3] += c;
    c = h[3] >> 26; h[3] &= MASK26; h[4] += c;
    c = h[4] >> 26; h[4] &= MASK26; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= MASK26; h[1] += c;
    c = h[1] >> 26; h[1] &= MASK26; h[2] += c;

    /* h is now < 2^130 and canonical; subtract p = 2^130-5 once if h >= p
     * (plain borrow subtraction -- simple to verify by inspection; a
     * constant-time selection is Stage 6 work, tracked in PLAN.md). */
    int64_t b0 = (int64_t)h[0] - 0x3fffffb;
    int64_t borrow = b0 < 0;
    if (borrow) b0 += 0x4000000;
    int64_t b1 = (int64_t)h[1] - 0x3ffffff - borrow;
    borrow = b1 < 0; if (borrow) b1 += 0x4000000;
    int64_t b2 = (int64_t)h[2] - 0x3ffffff - borrow;
    borrow = b2 < 0; if (borrow) b2 += 0x4000000;
    int64_t b3 = (int64_t)h[3] - 0x3ffffff - borrow;
    borrow = b3 < 0; if (borrow) b3 += 0x4000000;
    int64_t b4 = (int64_t)h[4] - 0x3ffffff - borrow;
    borrow = b4 < 0;

    uint32_t r0, r1, r2, r3, r4;
    if (!borrow) {
        r0 = (uint32_t)b0; r1 = (uint32_t)b1; r2 = (uint32_t)b2; r3 = (uint32_t)b3;
        r4 = (uint32_t)b4;
    } else {
        r0 = h[0]; r1 = h[1]; r2 = h[2]; r3 = h[3]; r4 = h[4];
    }

    /* Pack the low 128 bits of the 5x26-bit value into 4x32-bit words --
     * any bits at position >= 128 (there can be at most 2, since the value
     * is < 2^130) fall off the top of w3 and are dropped, which is exactly
     * the "mod 2^128" the spec calls for once s is added below. */
    uint32_t w0 = r0 | (r1 << 26);
    uint32_t w1 = (r1 >> 6) | (r2 << 20);
    uint32_t w2 = (r2 >> 12) | (r3 << 14);
    uint32_t w3 = (r3 >> 18) | (r4 << 8);

    uint32_t pad0 = load_le32(ctx->pad), pad1 = load_le32(ctx->pad + 4);
    uint32_t pad2 = load_le32(ctx->pad + 8), pad3 = load_le32(ctx->pad + 12);
    uint64_t f;
    f = (uint64_t)w0 + pad0; w0 = (uint32_t)f;
    f = (uint64_t)w1 + pad1 + (f >> 32); w1 = (uint32_t)f;
    f = (uint64_t)w2 + pad2 + (f >> 32); w2 = (uint32_t)f;
    f = (uint64_t)w3 + pad3 + (f >> 32); w3 = (uint32_t)f; /* carry out of w3 dropped: mod 2^128 */

    store_le32(out_tag, w0);
    store_le32(out_tag + 4, w1);
    store_le32(out_tag + 8, w2);
    store_le32(out_tag + 12, w3);
}

void nd_poly1305_mac(const uint8_t key[ND_POLY1305_KEY_LEN], const uint8_t *msg, size_t msg_len,
                      uint8_t out_tag[ND_POLY1305_TAG_LEN]) {
    nd_poly1305_ctx ctx;
    nd_poly1305_init(&ctx, key);
    nd_poly1305_update(&ctx, msg, msg_len);
    nd_poly1305_final(&ctx, out_tag);
}
