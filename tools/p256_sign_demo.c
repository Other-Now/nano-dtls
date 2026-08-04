/* See p256_sign_demo.h. Standard ECDSA sign (SEC1 section 4.1.3), built on
 * the same bignum/curve arithmetic src/crypto/p256.c (verify) uses --
 * shared via src/crypto/p256_internal.h so there is exactly one
 * implementation of that arithmetic in this repo, not two to keep in sync. */
#include "p256_sign_demo.h"

#include "nanodtls/random.h"
#include "../src/crypto/p256_internal.h"

nd_status nd_demo_p256_ecdsa_sign(const uint8_t privkey_d[32], const uint8_t hash[32], uint8_t out_r[32],
                                   uint8_t out_s[32]) {
    if (!privkey_d || !hash || !out_r || !out_s) return ND_ERR_BAD_ARG;

    bn256 d, e;
    bn_from_bytes_be(d, privkey_d);
    bn_from_bytes_be(e, hash);
    mod_reduce_once(e, P256_N);

    ec_point g;
    point_from_affine(&g, P256_GX, P256_GY);

    for (int attempt = 0; attempt < 64; ++attempt) {
        uint8_t k_bytes[32];
        if (nd_random_bytes(k_bytes, sizeof(k_bytes)) != ND_OK) return ND_ERR_BAD_ARG;
        bn256 k;
        bn_from_bytes_be(k, k_bytes);
        if (bn_is_zero(k) || bn_cmp(k, P256_N) >= 0) continue;

        ec_point r_point;
        point_scalar_mult(&r_point, k, &g);
        bn256 r, r_affine_y;
        point_to_affine(r, r_affine_y, &r_point);
        mod_reduce_once(r, P256_N);
        if (bn_is_zero(r)) continue;

        bn256 k_inv, rd, e_plus_rd, s;
        mod_inv(k_inv, k, P256_N);
        mod_mul(rd, r, d, P256_N);
        mod_add(e_plus_rd, e, rd, P256_N);
        mod_mul(s, k_inv, e_plus_rd, P256_N);
        if (bn_is_zero(s)) continue;

        bn_to_bytes_be(out_r, r);
        bn_to_bytes_be(out_s, s);
        return ND_OK;
    }
    return ND_ERR_BAD_ARG; /* astronomically unlikely: 64 draws all rejected */
}
