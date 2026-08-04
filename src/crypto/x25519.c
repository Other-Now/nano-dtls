/* X25519 (RFC 7748 section 5): Curve25519 scalar multiplication via the
 * constant-time Montgomery ladder, over the field GF(2^255-19).
 *
 * Field elements are represented in the well-known portable radix-2^16,
 * 16-limb form (each limb an int64_t), the same style TweetNaCl popularized
 * specifically because it needs nothing wider than a 64-bit accumulator --
 * no __int128, no platform-specific wide multiply, so this builds
 * identically on MSVC and GCC/Clang (the same reason Poly1305 in this repo
 * uses a portable limb radix instead of __int128). The reduction constant
 * 38 appears because 2^256 = 2*2^255 = 2*19 = 38 (mod 2^255-19); this is
 * the field-arithmetic analogue of Poly1305's "identity 2^130 = 5" trick. */
#include "nanodtls/x25519.h"

#include <string.h>

typedef int64_t fe[16];

static void fe_0(fe o) {
    for (int i = 0; i < 16; ++i) o[i] = 0;
}

static void fe_1(fe o) {
    o[0] = 1;
    for (int i = 1; i < 16; ++i) o[i] = 0;
}

static void fe_copy(fe o, const fe a) {
    for (int i = 0; i < 16; ++i) o[i] = a[i];
}

static void fe_add(fe o, const fe a, const fe b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void fe_sub(fe o, const fe a, const fe b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

/* Constant-time conditional swap: swaps a and b iff swap_flag is 1 (0 or 1
 * only). Used by the Montgomery ladder, where "swap" depends on secret
 * scalar bits -- a data-dependent branch here would leak them. */
static void fe_cswap(int swap_flag, fe a, fe b) {
    int64_t mask = -(int64_t)swap_flag; /* 0 -> 0x0..0, 1 -> 0xf..f */
    for (int i = 0; i < 16; ++i) {
        int64_t dummy = mask & (a[i] ^ b[i]);
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
}

/* Propagates each limb's overflow/underflow into the next, folding what
 * carries out of limb 15 back into limb 0 (times 38, per the identity
 * above). Biasing each limb by +2^16 before shifting makes the carry
 * computation well-defined even when a limb is negative (as it can be
 * right after fe_sub), without relying on implementation-defined behavior
 * of right-shifting a negative integer. */
static void fe_carry(fe o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (int64_t)1 << 16;
        int64_t raw_carry = o[i] >> 16;
        int64_t carry = raw_carry - 1;
        o[i] -= raw_carry << 16;
        if (i < 15) {
            o[i + 1] += carry;
        } else {
            o[0] += 38 * carry;
        }
    }
}

static void fe_mul(fe o, const fe a, const fe b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    for (int i = 16; i < 31; ++i) t[i - 16] += 38 * t[i];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    fe_carry(o);
    fe_carry(o);
}

static void fe_sq(fe o, const fe a) { fe_mul(o, a, a); }

/* Modular inverse via Fermat's little theorem: a^(p-2) mod p, p = 2^255-19.
 * Fixed square-and-multiply chain for the exponent p-2 = 2^255-21 -- skips
 * the multiply at bit positions 2 and 4, where p-2's binary expansion has a
 * 0 bit (this exact chain is the well-known portable-Curve25519 approach). */
static void fe_inv(fe o, const fe a) {
    fe c;
    fe_copy(c, a);
    for (int i = 253; i >= 0; --i) {
        fe_sq(c, c);
        if (i != 2 && i != 4) fe_mul(c, c, a);
    }
    fe_copy(o, c);
}

static void fe_unpack(fe o, const uint8_t n[32]) {
    for (int i = 0; i < 16; ++i) o[i] = (int64_t)n[2 * i] | ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff; /* RFC 7748 section 5: X25519 decodeUCoordinate masks bit 255 */
}

/* Fully reduces n mod p and packs it into 32 little-endian bytes. p, in this
 * radix, is limb0=0xffed, limbs1..14=0xffff, limb15=0x7fff (2^255-19 written
 * out in 16-bit limbs). Trial-subtracts p (twice, matching the reference
 * implementation this style is drawn from) using explicit borrow tracking
 * rather than a shift-of-negative-numbers trick, for portability. */
static void fe_pack(uint8_t o[32], const fe n) {
    fe t;
    fe_copy(t, n);
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);

    for (int pass = 0; pass < 2; ++pass) {
        int64_t m[16];
        int64_t borrow = 0;
        for (int i = 0; i < 16; ++i) {
            int64_t p_limb = (i == 0) ? 0xffed : (i == 15 ? 0x7fff : 0xffff);
            int64_t d = t[i] - p_limb - borrow;
            borrow = (d < 0) ? 1 : 0;
            if (borrow) d += 0x10000;
            m[i] = d;
        }
        if (borrow == 0) {
            for (int i = 0; i < 16; ++i) t[i] = m[i];
        }
    }

    for (int i = 0; i < 16; ++i) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
    }
}

nd_status nd_x25519_scalarmult(const uint8_t scalar[ND_X25519_LEN],
                                const uint8_t u_in[ND_X25519_LEN],
                                uint8_t u_out[ND_X25519_LEN]) {
    if (!scalar || !u_in || !u_out) return ND_ERR_BAD_ARG;

    uint8_t k[32];
    memcpy(k, scalar, 32);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    const fe a24 = {121665, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    fe x1, x2, z2, x3, z3;
    fe_unpack(x1, u_in);
    fe_copy(x3, x1);
    fe_1(x2);
    fe_0(z2);
    fe_1(z3);

    int swap = 0;
    for (int t = 254; t >= 0; --t) {
        int kt = (k[t >> 3] >> (t & 7)) & 1;
        swap ^= kt;
        fe_cswap(swap, x2, x3);
        fe_cswap(swap, z2, z3);
        swap = kt;

        fe A, AA, B, BB, E, C, D, DA, CB, sum, diff, sq_diff, a24E, aa_plus_a24e;
        fe_add(A, x2, z2);
        fe_sq(AA, A);
        fe_sub(B, x2, z2);
        fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);

        fe_add(sum, DA, CB);
        fe_sq(x3, sum); /* x3 = (DA+CB)^2 */

        fe_sub(diff, DA, CB);
        fe_sq(sq_diff, diff);
        fe_mul(z3, x1, sq_diff); /* z3 = x1*(DA-CB)^2 */

        fe_mul(x2, AA, BB); /* x2 = AA*BB */

        fe_mul(a24E, E, a24);
        fe_add(aa_plus_a24e, AA, a24E);
        fe_mul(z2, E, aa_plus_a24e); /* z2 = E*(AA + a24*E) */
    }
    fe_cswap(swap, x2, x3);
    fe_cswap(swap, z2, z3);

    fe z2_inv, result;
    fe_inv(z2_inv, z2);
    fe_mul(result, x2, z2_inv);
    fe_pack(u_out, result);
    return ND_OK;
}

nd_status nd_x25519_base(const uint8_t scalar[ND_X25519_LEN], uint8_t u_out[ND_X25519_LEN]) {
    uint8_t base[ND_X25519_LEN] = {9, 0};
    return nd_x25519_scalarmult(scalar, base, u_out);
}
