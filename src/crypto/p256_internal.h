#ifndef NANODTLS_P256_INTERNAL_H
#define NANODTLS_P256_INTERNAL_H
/* Shared P-256 bignum/curve arithmetic, private to src/crypto/ -- NOT part
 * of the public nanodtls/p256.h API. Used by both p256.c (ECDSA verify,
 * part of the shipped nanodtls library -- see nanodtls/p256.h for why it
 * makes no constant-time claim: it only ever handles public keys/public
 * signatures) and tools/p256_sign_demo.c (ECDSA sign, used ONLY by the
 * demo/interop-test server role in tools/ -- never linked into the
 * nanodtls library itself). Header-only (`static inline` in every
 * translation unit that includes it) rather than a shared .c file, to keep
 * this a private implementation detail with no separate build target.
 *
 * See src/crypto/p256.c's original file comment for the full rationale
 * behind the representation choices that are NOT the point-coordinate
 * system (radix-2^32 8-limb bn256 instead of __int128, binary-long-division
 * modular reduction instead of the NIST fast-reduction formula).
 *
 * Points are Jacobian (X, Y, Z), representing affine (X/Z^2, Y/Z^3) --
 * NOT the affine representation an earlier version of this file used.
 * That earlier version needed a full modular inversion (mod_inv: a
 * 256-iteration modular exponentiation) inside every single point_double
 * and point_add call, because affine addition/doubling's slope computation
 * divides by a field element. A 256-bit scalar multiplication calls
 * point_double/point_add up to ~512 times, so that was ~512 inversions per
 * scalar multiplication -- measured (bench/bench_handshake.c) at roughly
 * 0.5-1 second per ECDSA sign/verify, entirely dominated by mod_inv calls
 * that Jacobian coordinates make unnecessary until the very end. Jacobian
 * point_double (dbl-2001-b) and point_add (add-1998-cmo) -- standard
 * formulas, https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html,
 * fetched rather than derived from memory -- use only field
 * multiply/add/sub, no inversion at all; nd_p256_ecdsa_verify converts
 * back to affine with exactly one mod_inv call, after all the point
 * arithmetic is done. */
#include <stdint.h>

typedef uint32_t bn256[8];

typedef struct {
    bn256 x, y, z; /* Jacobian: affine = (x * z^-2, y * z^-3); infinity is tracked by the
                     * explicit flag below, not by any particular z value. */
    int infinity;
} ec_point;

static const bn256 P256_P = {0xffffffffu, 0xffffffffu, 0xffffffffu, 0x00000000u,
                              0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu};
static const bn256 P256_A = {0xfffffffcu, 0xffffffffu, 0xffffffffu, 0x00000000u,
                              0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu};
static const bn256 P256_B = {0x27d2604bu, 0x3bce3c3eu, 0xcc53b0f6u, 0x651d06b0u,
                              0x769886bcu, 0xb3ebbd55u, 0xaa3a93e7u, 0x5ac635d8u};
static const bn256 P256_N = {0xfc632551u, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
                              0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu};
static const bn256 P256_GX = {0xd898c296u, 0xf4a13945u, 0x2deb33a0u, 0x77037d81u,
                               0x63a440f2u, 0xf8bce6e5u, 0xe12c4247u, 0x6b17d1f2u};
static const bn256 P256_GY = {0x37bf51f5u, 0xcbb64068u, 0x6b315eceu, 0x2bce3357u,
                               0x7c0f9e16u, 0x8ee7eb4au, 0xfe1a7f9bu, 0x4fe342e2u};

static inline void bn_copy(bn256 o, const bn256 a) {
    for (int i = 0; i < 8; ++i) o[i] = a[i];
}

static inline void bn_zero(bn256 o) {
    for (int i = 0; i < 8; ++i) o[i] = 0;
}

static inline int bn_is_zero(const bn256 a) {
    for (int i = 0; i < 8; ++i)
        if (a[i]) return 0;
    return 1;
}

static inline int bn_cmp(const bn256 a, const bn256 b) {
    for (int i = 7; i >= 0; --i) {
        if (a[i] != b[i]) return (a[i] < b[i]) ? -1 : 1;
    }
    return 0;
}

static inline int bn_test_bit(const bn256 a, int i) { return (int)((a[i / 32] >> (i % 32)) & 1u); }

static inline uint32_t bn_add_raw(bn256 o, const bn256 a, const bn256 b) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t s = (uint64_t)a[i] + (uint64_t)b[i] + carry;
        o[i] = (uint32_t)s;
        carry = s >> 32;
    }
    return (uint32_t)carry;
}

static inline uint32_t bn_sub_raw(bn256 o, const bn256 a, const bn256 b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t diff = (uint64_t)a[i] - (uint64_t)b[i] - borrow;
        o[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    return (uint32_t)borrow;
}

static inline void bn_from_bytes_be(bn256 o, const uint8_t in[32]) {
    for (int i = 0; i < 8; ++i) {
        int off = (7 - i) * 4;
        o[i] = ((uint32_t)in[off] << 24) | ((uint32_t)in[off + 1] << 16) | ((uint32_t)in[off + 2] << 8) |
               (uint32_t)in[off + 3];
    }
}

static inline void bn_to_bytes_be(uint8_t out[32], const bn256 a) {
    for (int i = 0; i < 8; ++i) {
        int off = (7 - i) * 4;
        out[off] = (uint8_t)(a[i] >> 24);
        out[off + 1] = (uint8_t)(a[i] >> 16);
        out[off + 2] = (uint8_t)(a[i] >> 8);
        out[off + 3] = (uint8_t)a[i];
    }
}

static inline void bn_mul_wide(uint32_t o[16], const bn256 a, const bn256 b) {
    for (int i = 0; i < 16; ++i) o[i] = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t t = (uint64_t)a[i] * (uint64_t)b[j] + o[i + j] + carry;
            o[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        int k = i + 8;
        while (carry) {
            uint64_t t = (uint64_t)o[k] + carry;
            o[k] = (uint32_t)t;
            carry = t >> 32;
            ++k;
        }
    }
}

static inline int rem9_ge_m(const uint32_t rem[9], const bn256 m) {
    if (rem[8] != 0) return 1;
    for (int i = 7; i >= 0; --i) {
        if (rem[i] > m[i]) return 1;
        if (rem[i] < m[i]) return 0;
    }
    return 1; /* equal */
}

static inline void mod_reduce_wide(bn256 o, const uint32_t wide[16], const bn256 m) {
    uint32_t rem[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
    for (int bit = 511; bit >= 0; --bit) {
        uint32_t carry = 0;
        for (int i = 0; i < 9; ++i) {
            uint32_t next_carry = rem[i] >> 31;
            rem[i] = (rem[i] << 1) | carry;
            carry = next_carry;
        }
        int limb_idx = bit / 32, bit_idx = bit % 32;
        rem[0] |= (wide[limb_idx] >> bit_idx) & 1u;

        if (rem9_ge_m(rem, m)) {
            uint64_t borrow = 0;
            for (int i = 0; i < 8; ++i) {
                uint64_t diff = (uint64_t)rem[i] - (uint64_t)m[i] - borrow;
                rem[i] = (uint32_t)diff;
                borrow = (diff >> 63) & 1u;
            }
            rem[8] = (uint32_t)((uint64_t)rem[8] - borrow);
        }
    }
    for (int i = 0; i < 8; ++i) o[i] = rem[i];
}

static inline void mod_add(bn256 o, const bn256 a, const bn256 b, const bn256 m) {
    bn256 sum;
    uint32_t carry = bn_add_raw(sum, a, b);
    if (carry || bn_cmp(sum, m) >= 0) {
        bn_sub_raw(o, sum, m);
    } else {
        bn_copy(o, sum);
    }
}

static inline void mod_sub(bn256 o, const bn256 a, const bn256 b, const bn256 m) {
    bn256 diff;
    uint32_t borrow = bn_sub_raw(diff, a, b);
    if (borrow) {
        bn_add_raw(o, diff, m);
    } else {
        bn_copy(o, diff);
    }
}

static inline void mod_mul(bn256 o, const bn256 a, const bn256 b, const bn256 m) {
    uint32_t wide[16];
    bn_mul_wide(wide, a, b);
    mod_reduce_wide(o, wide, m);
}

static inline void mod_pow(bn256 o, const bn256 base, const bn256 exp, const bn256 m) {
    bn256 result = {1, 0, 0, 0, 0, 0, 0, 0};
    bn256 b;
    bn_copy(b, base);
    for (int i = 0; i < 256; ++i) {
        if (bn_test_bit(exp, i)) mod_mul(result, result, b, m);
        mod_mul(b, b, b, m);
    }
    bn_copy(o, result);
}

/* p and n are both prime, so a^-1 = a^(modulus-2) mod modulus (Fermat). */
static inline void mod_inv(bn256 o, const bn256 a, const bn256 m) {
    bn256 two = {2, 0, 0, 0, 0, 0, 0, 0};
    bn256 exp;
    bn_sub_raw(exp, m, two);
    mod_pow(o, a, exp, m);
}

static inline void mod_reduce_once(bn256 a, const bn256 m) {
    while (bn_cmp(a, m) >= 0) {
        bn256 tmp;
        bn_sub_raw(tmp, a, m);
        bn_copy(a, tmp);
    }
}

/* dbl-2001-b (a=-3): delta=Z1^2, gamma=Y1^2, beta=X1*gamma,
 * alpha=3*(X1-delta)*(X1+delta), X3=alpha^2-8*beta,
 * Z3=(Y1+Z1)^2-gamma-delta, Y3=alpha*(4*beta-X3)-8*gamma^2. */
static inline void point_double(ec_point *r, const ec_point *p) {
    if (p->infinity || bn_is_zero(p->y)) {
        r->infinity = 1;
        return;
    }
    bn256 delta, gamma, beta, x1_minus_delta, x1_plus_delta, alpha_base, alpha;
    mod_mul(delta, p->z, p->z, P256_P);
    mod_mul(gamma, p->y, p->y, P256_P);
    mod_mul(beta, p->x, gamma, P256_P);
    mod_sub(x1_minus_delta, p->x, delta, P256_P);
    mod_add(x1_plus_delta, p->x, delta, P256_P);
    mod_mul(alpha_base, x1_minus_delta, x1_plus_delta, P256_P);
    mod_add(alpha, alpha_base, alpha_base, P256_P);
    mod_add(alpha, alpha, alpha_base, P256_P); /* alpha = 3*alpha_base */

    bn256 alpha_sq, two_beta, four_beta, eight_beta, x3;
    mod_mul(alpha_sq, alpha, alpha, P256_P);
    mod_add(two_beta, beta, beta, P256_P);
    mod_add(four_beta, two_beta, two_beta, P256_P);
    mod_add(eight_beta, four_beta, four_beta, P256_P);
    mod_sub(x3, alpha_sq, eight_beta, P256_P);

    bn256 y1_plus_z1, y1z1_sq, z3_tmp, z3;
    mod_add(y1_plus_z1, p->y, p->z, P256_P);
    mod_mul(y1z1_sq, y1_plus_z1, y1_plus_z1, P256_P);
    mod_sub(z3_tmp, y1z1_sq, gamma, P256_P);
    mod_sub(z3, z3_tmp, delta, P256_P);

    bn256 four_beta_minus_x3, alpha_times, gamma_sq, two_gamma_sq, four_gamma_sq, eight_gamma_sq, y3;
    mod_sub(four_beta_minus_x3, four_beta, x3, P256_P);
    mod_mul(alpha_times, alpha, four_beta_minus_x3, P256_P);
    mod_mul(gamma_sq, gamma, gamma, P256_P);
    mod_add(two_gamma_sq, gamma_sq, gamma_sq, P256_P);
    mod_add(four_gamma_sq, two_gamma_sq, two_gamma_sq, P256_P);
    mod_add(eight_gamma_sq, four_gamma_sq, four_gamma_sq, P256_P);
    mod_sub(y3, alpha_times, eight_gamma_sq, P256_P);

    bn_copy(r->x, x3);
    bn_copy(r->y, y3);
    bn_copy(r->z, z3);
    r->infinity = 0;
}

/* add-1998-cmo (general Jacobian + Jacobian, no assumption either operand
 * is affine): U1=X1*Z2^2, U2=X2*Z1^2, S1=Y1*Z2^3, S2=Y2*Z1^3, H=U2-U1,
 * r=S2-S1, X3=r^2-H^3-2*U1*H^2, Y3=r*(U1*H^2-X3)-S1*H^3, Z3=Z1*Z2*H. H==0
 * means U1==U2 (same x): either the same point (r==0 too -- double
 * instead) or P and -P (r!=0 -- result is infinity). */
static inline void point_add(ec_point *r, const ec_point *p, const ec_point *q) {
    if (p->infinity) {
        *r = *q;
        return;
    }
    if (q->infinity) {
        *r = *p;
        return;
    }

    bn256 z1z1, z2z2, u1, u2, z1z1z1, z2z2z2, s1, s2, h, rr;
    mod_mul(z1z1, p->z, p->z, P256_P);
    mod_mul(z2z2, q->z, q->z, P256_P);
    mod_mul(u1, p->x, z2z2, P256_P);
    mod_mul(u2, q->x, z1z1, P256_P);
    mod_mul(z1z1z1, z1z1, p->z, P256_P);
    mod_mul(z2z2z2, z2z2, q->z, P256_P);
    mod_mul(s1, p->y, z2z2z2, P256_P);
    mod_mul(s2, q->y, z1z1z1, P256_P);
    mod_sub(h, u2, u1, P256_P);
    mod_sub(rr, s2, s1, P256_P);

    if (bn_is_zero(h)) {
        if (bn_is_zero(rr)) {
            point_double(r, p);
        } else {
            r->infinity = 1;
        }
        return;
    }

    bn256 h2, h3, u1h2, two_u1h2, rr2, tmp, x3;
    mod_mul(h2, h, h, P256_P);
    mod_mul(h3, h2, h, P256_P);
    mod_mul(u1h2, u1, h2, P256_P);
    mod_add(two_u1h2, u1h2, u1h2, P256_P);
    mod_mul(rr2, rr, rr, P256_P);
    mod_sub(tmp, rr2, h3, P256_P);
    mod_sub(x3, tmp, two_u1h2, P256_P);

    bn256 u1h2_minus_x3, s1h3, y3;
    mod_sub(u1h2_minus_x3, u1h2, x3, P256_P);
    mod_mul(tmp, rr, u1h2_minus_x3, P256_P);
    mod_mul(s1h3, s1, h3, P256_P);
    mod_sub(y3, tmp, s1h3, P256_P);

    bn256 z1z2, z3;
    mod_mul(z1z2, p->z, q->z, P256_P);
    mod_mul(z3, z1z2, h, P256_P);

    bn_copy(r->x, x3);
    bn_copy(r->y, y3);
    bn_copy(r->z, z3);
    r->infinity = 0;
}

static inline void point_scalar_mult(ec_point *r, const bn256 k, const ec_point *p) {
    ec_point result;
    result.infinity = 1;
    ec_point addend = *p;
    for (int i = 0; i < 256; ++i) {
        if (bn_test_bit(k, i)) {
            ec_point tmp;
            point_add(&tmp, &result, &addend);
            result = tmp;
        }
        ec_point dbl;
        point_double(&dbl, &addend);
        addend = dbl;
    }
    *r = result;
}

/* Sets a Jacobian point from affine (x, y): Z=1. */
static inline void point_from_affine(ec_point *out, const bn256 x, const bn256 y) {
    bn_copy(out->x, x);
    bn_copy(out->y, y);
    bn256 one = {1, 0, 0, 0, 0, 0, 0, 0};
    bn_copy(out->z, one);
    out->infinity = 0;
}

/* Converts Jacobian back to affine: the ONE mod_inv call needed per
 * verify/sign, deferred to here instead of once per point_double/point_add
 * (see the file comment above). */
static inline void point_to_affine(bn256 out_x, bn256 out_y, const ec_point *p) {
    bn256 z_inv, z_inv2, z_inv3;
    mod_inv(z_inv, p->z, P256_P);
    mod_mul(z_inv2, z_inv, z_inv, P256_P);
    mod_mul(z_inv3, z_inv2, z_inv, P256_P);
    mod_mul(out_x, p->x, z_inv2, P256_P);
    mod_mul(out_y, p->y, z_inv3, P256_P);
}

#endif /* NANODTLS_P256_INTERNAL_H */
