/* ECDSA-P256-SHA256 verification (FIPS 186-4 section 6.4, SEC1 section
 * 4.1.4). See nanodtls/p256.h for why this deliberately isn't
 * constant-time (public keys, public signatures only -- nothing here
 * handles a secret) and see src/crypto/p256_internal.h for the shared
 * bignum/curve arithmetic (representation choices, modular-reduction
 * strategy, domain parameter provenance) this and tools/p256_sign_demo.c
 * both build on. */
#include "nanodtls/p256.h"

#include "p256_internal.h"

nd_status nd_p256_point_is_valid(const uint8_t qx[ND_P256_COORD_LEN], const uint8_t qy[ND_P256_COORD_LEN]) {
    if (!qx || !qy) return ND_ERR_BAD_ARG;
    bn256 x, y;
    bn_from_bytes_be(x, qx);
    bn_from_bytes_be(y, qy);
    if (bn_cmp(x, P256_P) >= 0 || bn_cmp(y, P256_P) >= 0) return ND_ERR_BAD_ARG;

    bn256 lhs, x2, x3, ax, rhs;
    mod_mul(lhs, y, y, P256_P);
    mod_mul(x2, x, x, P256_P);
    mod_mul(x3, x2, x, P256_P);
    mod_mul(ax, P256_A, x, P256_P);
    mod_add(rhs, x3, ax, P256_P);
    mod_add(rhs, rhs, P256_B, P256_P);
    return (bn_cmp(lhs, rhs) == 0) ? ND_OK : ND_ERR_BAD_ARG;
}

nd_status nd_p256_ecdsa_verify(const uint8_t qx[ND_P256_COORD_LEN], const uint8_t qy[ND_P256_COORD_LEN],
                                const uint8_t hash[32], const uint8_t r_bytes[ND_P256_SCALAR_LEN],
                                const uint8_t s_bytes[ND_P256_SCALAR_LEN]) {
    if (!qx || !qy || !hash || !r_bytes || !s_bytes) return ND_ERR_BAD_ARG;
    if (nd_p256_point_is_valid(qx, qy) != ND_OK) return ND_ERR_AUTH_FAILED;

    bn256 rr, s;
    bn_from_bytes_be(rr, r_bytes);
    bn_from_bytes_be(s, s_bytes);
    if (bn_is_zero(rr) || bn_cmp(rr, P256_N) >= 0) return ND_ERR_AUTH_FAILED;
    if (bn_is_zero(s) || bn_cmp(s, P256_N) >= 0) return ND_ERR_AUTH_FAILED;

    bn256 e;
    bn_from_bytes_be(e, hash);
    mod_reduce_once(e, P256_N);

    bn256 w, u1, u2;
    mod_inv(w, s, P256_N);
    mod_mul(u1, e, w, P256_N);
    mod_mul(u2, rr, w, P256_N);

    ec_point g, q, p1, p2, r_point;
    point_from_affine(&g, P256_GX, P256_GY);
    bn256 qx_bn, qy_bn;
    bn_from_bytes_be(qx_bn, qx);
    bn_from_bytes_be(qy_bn, qy);
    point_from_affine(&q, qx_bn, qy_bn);

    point_scalar_mult(&p1, u1, &g);
    point_scalar_mult(&p2, u2, &q);
    point_add(&r_point, &p1, &p2);
    if (r_point.infinity) return ND_ERR_AUTH_FAILED;

    bn256 v, r_affine_y;
    point_to_affine(v, r_affine_y, &r_point);
    mod_reduce_once(v, P256_N);

    return (bn_cmp(v, rr) == 0) ? ND_OK : ND_ERR_AUTH_FAILED;
}
