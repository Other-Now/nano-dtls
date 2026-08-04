#include "nanodtls/hkdf.h"

#include <string.h>

#include "nanodtls/hmac_sha256.h"

/* Generous but fixed bounds -- every TLS 1.3/DTLS 1.3 label ("c hs traffic",
 * "s ap traffic", "sn", ...) and every context (a SHA-256 transcript hash,
 * 32 bytes) fits with room to spare. Kept small and fixed rather than
 * RFC 5869/8446's 255-byte ceilings so the combine buffer stays a small,
 * zero-alloc stack array. */
#define ND_HKDF_INFO_MAX 200u
#define ND_HKDF_LABEL_MAX 64u
#define ND_HKDF_CONTEXT_MAX 64u

nd_status nd_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                           size_t ikm_len, uint8_t out_prk[ND_HASH_LEN]) {
    if ((ikm_len > 0 && !ikm) || !out_prk) return ND_ERR_BAD_ARG;

    const uint8_t zero_salt[ND_HASH_LEN] = {0};
    const uint8_t *use_salt = salt;
    size_t use_salt_len = salt_len;
    if (!salt || salt_len == 0) {
        use_salt = zero_salt;
        use_salt_len = ND_HASH_LEN;
    }
    nd_hmac_sha256(use_salt, use_salt_len, ikm, ikm_len, out_prk);
    return ND_OK;
}

nd_status nd_hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len,
                          uint8_t *out, size_t out_len) {
    if (!prk || (info_len > 0 && !info) || (out_len > 0 && !out)) return ND_ERR_BAD_ARG;
    if (out_len > 255u * ND_HASH_LEN) return ND_ERR_BAD_ARG; /* RFC 5869 hard limit */
    if (info_len > ND_HKDF_INFO_MAX) return ND_ERR_BAD_ARG;

    /* T(0) (RFC 5869 section 2.3) is the empty string: t_len starts at 0,
     * so the first iteration's memcpy of t below copies zero bytes (a
     * well-defined no-op regardless of t's contents) -- cppcheck flags
     * this as reading an uninitialized variable, but zero-init removes any
     * ambiguity for that or any other static/dynamic analysis tool rather
     * than relying on "memcpy(_, _, 0) never actually reads its source"
     * being obvious to every reader and every checker. */
    uint8_t t[ND_HASH_LEN] = {0};
    size_t t_len = 0;
    size_t generated = 0;
    uint8_t counter = 1;

    while (generated < out_len) {
        uint8_t combine[ND_HASH_LEN + ND_HKDF_INFO_MAX + 1];
        size_t off = 0;
        memcpy(combine + off, t, t_len);
        off += t_len;
        if (info_len) memcpy(combine + off, info, info_len);
        off += info_len;
        combine[off++] = counter;

        nd_hmac_sha256(prk, prk_len, combine, off, t);
        t_len = ND_HASH_LEN;

        size_t take = out_len - generated;
        if (take > ND_HASH_LEN) take = ND_HASH_LEN;
        memcpy(out + generated, t, take);
        generated += take;
        ++counter;
    }
    return ND_OK;
}

nd_status nd_hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label_prefix,
                                const char *label, const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len) {
    if (!secret || !label_prefix || !label || (context_len > 0 && !context)) {
        return ND_ERR_BAD_ARG;
    }

    size_t prefix_len = strlen(label_prefix);
    size_t label_str_len = strlen(label);
    size_t full_label_len = prefix_len + label_str_len;
    if (full_label_len > ND_HKDF_LABEL_MAX || context_len > ND_HKDF_CONTEXT_MAX) {
        return ND_ERR_BAD_ARG;
    }
    if (out_len > 0xFFFFu) return ND_ERR_BAD_ARG; /* Length is a uint16 on the wire */

    uint8_t hkdf_label[2 + 1 + ND_HKDF_LABEL_MAX + 1 + ND_HKDF_CONTEXT_MAX];
    size_t off = 0;
    hkdf_label[off++] = (uint8_t)(out_len >> 8);
    hkdf_label[off++] = (uint8_t)(out_len);
    hkdf_label[off++] = (uint8_t)full_label_len;
    memcpy(hkdf_label + off, label_prefix, prefix_len);
    off += prefix_len;
    memcpy(hkdf_label + off, label, label_str_len);
    off += label_str_len;
    hkdf_label[off++] = (uint8_t)context_len;
    if (context_len) memcpy(hkdf_label + off, context, context_len);
    off += context_len;

    return nd_hkdf_expand(secret, secret_len, hkdf_label, off, out, out_len);
}

nd_status nd_derive_secret(const uint8_t *secret, size_t secret_len, const char *label_prefix,
                            const char *label, const uint8_t *transcript_hash,
                            size_t transcript_hash_len, uint8_t out[ND_HASH_LEN]) {
    return nd_hkdf_expand_label(secret, secret_len, label_prefix, label, transcript_hash,
                                 transcript_hash_len, out, ND_HASH_LEN);
}
