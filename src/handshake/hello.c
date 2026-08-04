/* ClientHello serialize / ServerHello parse (RFC 9147 section 5.3, RFC 8446
 * sections 4.1.2/4.1.3/4.2.x). See nanodtls/hello.h for the wire layout this
 * follows. The ServerHello parser is verified in tests/test_hello.c against
 * the actual ServerHello bytes from RFC 8448's worked handshake trace --
 * real wire bytes from a real implementation, not just a round-trip against
 * our own serializer. */
#include "nanodtls/hello.h"

#include <string.h>

/* ---- tiny internal byte writer: append, or reserve-a-length-then-patch-it-
 * once-the-body-is-known. Removes an entire class of manual-offset-
 * arithmetic bugs from what would otherwise be a lot of hand-computed TLV
 * lengths below. ---- */
typedef struct writer {
    uint8_t *buf;
    size_t cap;
    size_t len;
    int overflow;
} writer;

static void w_init(writer *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = 0;
}

static void w_bytes(writer *w, const uint8_t *data, size_t n) {
    if (w->overflow || w->len + n > w->cap) {
        w->overflow = 1;
        return;
    }
    if (n) memcpy(w->buf + w->len, data, n);
    w->len += n;
}

static void w_u8(writer *w, uint8_t v) { w_bytes(w, &v, 1); }
static void w_u16(writer *w, uint16_t v) {
    const uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    w_bytes(w, b, 2);
}

static size_t w_reserve_u8_len(writer *w) {
    size_t pos = w->len;
    w_u8(w, 0);
    return pos;
}
static void w_patch_u8_len(writer *w, size_t pos) {
    if (w->overflow) return;
    size_t body = w->len - pos - 1;
    w->buf[pos] = (uint8_t)body; /* caller guarantees body <= 255 */
}
static size_t w_reserve_u16_len(writer *w) {
    size_t pos = w->len;
    w_u16(w, 0);
    return pos;
}
static void w_patch_u16_len(writer *w, size_t pos) {
    if (w->overflow) return;
    size_t body = w->len - pos - 2;
    w->buf[pos] = (uint8_t)(body >> 8);
    w->buf[pos + 1] = (uint8_t)body;
}

nd_status nd_client_hello_serialize(const nd_client_hello_params *params, uint8_t *out_buf,
                                     size_t out_buf_cap, size_t *out_len) {
    if (!params || !out_buf || !out_len) return ND_ERR_BAD_ARG;

    writer w;
    w_init(&w, out_buf, out_buf_cap);

    w_u16(&w, (uint16_t)ND_DTLS_1_2_LEGACY_VERSION);
    w_bytes(&w, params->random, ND_RANDOM_LEN);

    size_t session_id_len_pos = w_reserve_u8_len(&w); /* legacy_session_id: empty */
    w_patch_u8_len(&w, session_id_len_pos);

    size_t cookie_len_pos = w_reserve_u8_len(&w); /* legacy_cookie: empty (DTLS-only field) */
    w_patch_u8_len(&w, cookie_len_pos);

    size_t cs_len_pos = w_reserve_u16_len(&w); /* cipher_suites: just ours */
    w_u16(&w, (uint16_t)ND_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);
    w_patch_u16_len(&w, cs_len_pos);

    size_t comp_len_pos = w_reserve_u8_len(&w); /* legacy_compression_methods: {null} */
    w_u8(&w, 0x00);
    w_patch_u8_len(&w, comp_len_pos);

    size_t ext_list_len_pos = w_reserve_u16_len(&w);

    /* supported_versions (type 43): ClientHello variant is a byte-length-
     * prefixed list of ProtocolVersion; we offer exactly DTLS 1.3. */
    w_u16(&w, 43);
    size_t sv_ext_len_pos = w_reserve_u16_len(&w);
    size_t sv_list_len_pos = w_reserve_u8_len(&w);
    w_u16(&w, (uint16_t)ND_DTLS_1_3_VERSION);
    w_patch_u8_len(&w, sv_list_len_pos);
    w_patch_u16_len(&w, sv_ext_len_pos);

    /* supported_groups (type 10): NamedGroupList, we offer exactly x25519. */
    w_u16(&w, 10);
    size_t sg_ext_len_pos = w_reserve_u16_len(&w);
    size_t sg_list_len_pos = w_reserve_u16_len(&w);
    w_u16(&w, (uint16_t)ND_NAMED_GROUP_X25519);
    w_patch_u16_len(&w, sg_list_len_pos);
    w_patch_u16_len(&w, sg_ext_len_pos);

    /* key_share (type 51): KeyShareClientHello, one KeyShareEntry. */
    w_u16(&w, 51);
    size_t ks_ext_len_pos = w_reserve_u16_len(&w);
    size_t ks_list_len_pos = w_reserve_u16_len(&w);
    w_u16(&w, (uint16_t)ND_NAMED_GROUP_X25519);
    size_t ks_key_len_pos = w_reserve_u16_len(&w);
    w_bytes(&w, params->x25519_public_key, ND_X25519_LEN);
    w_patch_u16_len(&w, ks_key_len_pos);
    w_patch_u16_len(&w, ks_list_len_pos);
    w_patch_u16_len(&w, ks_ext_len_pos);

    /* signature_algorithms (type 13): RFC 8446 requires this extension be
     * present in every ClientHello. nano-dtls can't verify a signature yet
     * (Stage 5), but a real peer expects the list regardless -- offer a
     * conventional, widely-supported set. */
    w_u16(&w, 13);
    size_t sa_ext_len_pos = w_reserve_u16_len(&w);
    size_t sa_list_len_pos = w_reserve_u16_len(&w);
    w_u16(&w, 0x0403); /* ecdsa_secp256r1_sha256 */
    w_u16(&w, 0x0804); /* rsa_pss_rsae_sha256 */
    w_u16(&w, 0x0807); /* ed25519 */
    w_patch_u16_len(&w, sa_list_len_pos);
    w_patch_u16_len(&w, sa_ext_len_pos);

    w_patch_u16_len(&w, ext_list_len_pos);

    if (w.overflow) return ND_ERR_BAD_LENGTH;
    *out_len = w.len;
    return ND_OK;
}

nd_status nd_server_hello_serialize(const nd_server_hello_params *params, uint8_t *out_buf,
                                     size_t out_buf_cap, size_t *out_len) {
    if (!params || !out_buf || !out_len) return ND_ERR_BAD_ARG;

    writer w;
    w_init(&w, out_buf, out_buf_cap);

    w_u16(&w, (uint16_t)ND_DTLS_1_2_LEGACY_VERSION);
    w_bytes(&w, params->random, ND_RANDOM_LEN);

    size_t sid_echo_len_pos = w_reserve_u8_len(&w); /* legacy_session_id_echo: empty */
    w_patch_u8_len(&w, sid_echo_len_pos);

    w_u16(&w, (uint16_t)ND_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);
    w_u8(&w, 0x00); /* legacy_compression_method */

    size_t ext_list_len_pos = w_reserve_u16_len(&w);

    /* supported_versions (type 43): ServerHello variant has no list wrapper
     * -- extension_data is exactly the 2-byte selected_version. */
    w_u16(&w, 43);
    size_t sv_ext_len_pos = w_reserve_u16_len(&w);
    w_u16(&w, (uint16_t)ND_DTLS_1_3_VERSION);
    w_patch_u16_len(&w, sv_ext_len_pos);

    /* key_share (type 51): KeyShareServerHello is a single KeyShareEntry
     * directly -- no list-length wrapper (unlike ClientHello's key_share). */
    w_u16(&w, 51);
    size_t ks_ext_len_pos = w_reserve_u16_len(&w);
    w_u16(&w, (uint16_t)ND_NAMED_GROUP_X25519);
    size_t ks_key_len_pos = w_reserve_u16_len(&w);
    w_bytes(&w, params->x25519_public_key, ND_X25519_LEN);
    w_patch_u16_len(&w, ks_key_len_pos);
    w_patch_u16_len(&w, ks_ext_len_pos);

    w_patch_u16_len(&w, ext_list_len_pos);

    if (w.overflow) return ND_ERR_BAD_LENGTH;
    *out_len = w.len;
    return ND_OK;
}

/* ---- tiny internal byte reader, the mirror of writer above. ---- */
typedef struct reader {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} reader;

static void r_init(reader *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}
static int r_bytes(reader *r, uint8_t *out, size_t n) {
    if (r->pos + n > r->len) return 0;
    if (n) memcpy(out, r->buf + r->pos, n);
    r->pos += n;
    return 1;
}
static int r_u8(reader *r, uint8_t *out) { return r_bytes(r, out, 1); }
static int r_u16(reader *r, uint16_t *out) {
    uint8_t b[2];
    if (!r_bytes(r, b, 2)) return 0;
    *out = (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
    return 1;
}
static int r_skip(reader *r, size_t n) {
    if (r->pos + n > r->len) return 0;
    r->pos += n;
    return 1;
}
/* Points *out at the next n bytes without copying (zero-copy, matching the
 * rest of nano-dtls's parsers) and advances past them. */
static int r_view(reader *r, size_t n, const uint8_t **out) {
    if (r->pos + n > r->len) return 0;
    *out = r->buf + r->pos;
    r->pos += n;
    return 1;
}

/* Scans a ServerHello's already-located extensions block for `want_type`,
 * pointing *out_data/*out_data_len at its extension_data (zero-copy) if
 * found. Returns 0 if not present or the block is malformed. */
static int find_extension(const uint8_t *ext_block, size_t ext_block_len, uint16_t want_type,
                           const uint8_t **out_data, size_t *out_data_len) {
    reader r;
    r_init(&r, ext_block, ext_block_len);
    while (r.pos < r.len) {
        uint16_t ext_type, ext_len;
        if (!r_u16(&r, &ext_type)) return 0;
        if (!r_u16(&r, &ext_len)) return 0;
        const uint8_t *data;
        if (!r_view(&r, ext_len, &data)) return 0;
        if (ext_type == want_type) {
            *out_data = data;
            *out_data_len = ext_len;
            return 1;
        }
    }
    return 0;
}

nd_status nd_server_hello_parse(const uint8_t *buf, size_t buf_len, nd_server_hello *out_hello) {
    if (!buf || !out_hello) return ND_ERR_BAD_ARG;

    reader r;
    r_init(&r, buf, buf_len);

    uint16_t legacy_version;
    if (!r_u16(&r, &legacy_version)) return ND_ERR_TRUNCATED;
    if (!r_bytes(&r, out_hello->random, ND_RANDOM_LEN)) return ND_ERR_TRUNCATED;

    uint8_t session_id_echo_len;
    if (!r_u8(&r, &session_id_echo_len)) return ND_ERR_TRUNCATED;
    if (!r_skip(&r, session_id_echo_len)) return ND_ERR_TRUNCATED;

    if (!r_u16(&r, &out_hello->cipher_suite)) return ND_ERR_TRUNCATED;

    uint8_t legacy_compression_method;
    if (!r_u8(&r, &legacy_compression_method)) return ND_ERR_TRUNCATED;

    uint16_t ext_list_len;
    if (!r_u16(&r, &ext_list_len)) return ND_ERR_TRUNCATED;
    const uint8_t *ext_block;
    if (!r_view(&r, ext_list_len, &ext_block)) return ND_ERR_BAD_LENGTH;

    const uint8_t *sv_data;
    size_t sv_len;
    if (!find_extension(ext_block, ext_list_len, 43 /* supported_versions */, &sv_data, &sv_len)) {
        return ND_ERR_UNSUPPORTED;
    }
    if (sv_len != 2) return ND_ERR_UNSUPPORTED;
    out_hello->selected_version = (uint16_t)(((uint16_t)sv_data[0] << 8) | sv_data[1]);
    if (out_hello->selected_version != ND_DTLS_1_3_VERSION) return ND_ERR_UNSUPPORTED;

    const uint8_t *ks_data;
    size_t ks_len;
    if (!find_extension(ext_block, ext_list_len, 51 /* key_share */, &ks_data, &ks_len)) {
        return ND_ERR_UNSUPPORTED;
    }
    reader ksr;
    r_init(&ksr, ks_data, ks_len);
    uint16_t group;
    uint16_t key_len;
    const uint8_t *key;
    if (!r_u16(&ksr, &group)) return ND_ERR_UNSUPPORTED;
    if (!r_u16(&ksr, &key_len)) return ND_ERR_UNSUPPORTED;
    if (!r_view(&ksr, key_len, &key)) return ND_ERR_UNSUPPORTED;
    if (group != ND_NAMED_GROUP_X25519 || key_len != ND_X25519_LEN) return ND_ERR_UNSUPPORTED;
    memcpy(out_hello->key_share, key, ND_X25519_LEN);

    (void)legacy_version;               /* RFC 9147: MUST be ignored by receivers */
    (void)legacy_compression_method;    /* always null; nothing to act on */
    return ND_OK;
}

nd_status nd_client_hello_parse(const uint8_t *buf, size_t buf_len, nd_client_hello *out_hello) {
    if (!buf || !out_hello) return ND_ERR_BAD_ARG;

    reader r;
    r_init(&r, buf, buf_len);

    uint16_t legacy_version;
    if (!r_u16(&r, &legacy_version)) return ND_ERR_TRUNCATED;
    if (!r_bytes(&r, out_hello->random, ND_RANDOM_LEN)) return ND_ERR_TRUNCATED;

    uint8_t session_id_len;
    if (!r_u8(&r, &session_id_len)) return ND_ERR_TRUNCATED;
    if (!r_skip(&r, session_id_len)) return ND_ERR_TRUNCATED;

    uint8_t cookie_len;
    if (!r_u8(&r, &cookie_len)) return ND_ERR_TRUNCATED; /* DTLS-only field; not validated (no HRR support) */
    if (!r_skip(&r, cookie_len)) return ND_ERR_TRUNCATED;

    uint16_t cs_len;
    if (!r_u16(&r, &cs_len)) return ND_ERR_TRUNCATED;
    const uint8_t *cs_data;
    if (!r_view(&r, cs_len, &cs_data)) return ND_ERR_BAD_LENGTH;
    {
        reader csr;
        r_init(&csr, cs_data, cs_len);
        int found = 0;
        while (csr.pos < csr.len) {
            uint16_t suite;
            if (!r_u16(&csr, &suite)) return ND_ERR_BAD_LENGTH;
            if (suite == (uint16_t)ND_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) found = 1;
        }
        if (!found) return ND_ERR_UNSUPPORTED;
    }

    uint8_t comp_len;
    if (!r_u8(&r, &comp_len)) return ND_ERR_TRUNCATED;
    if (!r_skip(&r, comp_len)) return ND_ERR_TRUNCATED;

    uint16_t ext_list_len;
    if (!r_u16(&r, &ext_list_len)) return ND_ERR_TRUNCATED;
    const uint8_t *ext_block;
    if (!r_view(&r, ext_list_len, &ext_block)) return ND_ERR_BAD_LENGTH;

    const uint8_t *sv_data;
    size_t sv_len;
    if (!find_extension(ext_block, ext_list_len, 43 /* supported_versions */, &sv_data, &sv_len)) {
        return ND_ERR_UNSUPPORTED;
    }
    {
        /* ClientHello's supported_versions is a byte-length-prefixed list of
         * ProtocolVersion (unlike ServerHello's bare 2-byte value). */
        if (sv_len < 1) return ND_ERR_UNSUPPORTED;
        uint8_t list_len = sv_data[0];
        if ((size_t)list_len + 1 != sv_len || (list_len % 2) != 0) return ND_ERR_UNSUPPORTED;
        int found_1_3 = 0;
        for (size_t i = 1; i + 1 < sv_len; i += 2) {
            uint16_t v = (uint16_t)(((uint16_t)sv_data[i] << 8) | sv_data[i + 1]);
            if (v == (uint16_t)ND_DTLS_1_3_VERSION) found_1_3 = 1;
        }
        if (!found_1_3) return ND_ERR_UNSUPPORTED;
    }

    const uint8_t *ks_data;
    size_t ks_len;
    if (!find_extension(ext_block, ext_list_len, 51 /* key_share */, &ks_data, &ks_len)) {
        return ND_ERR_UNSUPPORTED;
    }
    {
        /* ClientHello's key_share is KeyShareClientHello: a u16 list-length
         * prefix followed by KeyShareEntry* (unlike ServerHello's single
         * bare KeyShareEntry). */
        reader ksr;
        r_init(&ksr, ks_data, ks_len);
        uint16_t list_len;
        if (!r_u16(&ksr, &list_len)) return ND_ERR_UNSUPPORTED;
        const uint8_t *list_data;
        if (!r_view(&ksr, list_len, &list_data)) return ND_ERR_UNSUPPORTED;

        reader lr;
        r_init(&lr, list_data, list_len);
        int found = 0;
        while (lr.pos < lr.len) {
            uint16_t group, key_len;
            const uint8_t *key;
            if (!r_u16(&lr, &group)) return ND_ERR_UNSUPPORTED;
            if (!r_u16(&lr, &key_len)) return ND_ERR_UNSUPPORTED;
            if (!r_view(&lr, key_len, &key)) return ND_ERR_UNSUPPORTED;
            if (group == (uint16_t)ND_NAMED_GROUP_X25519 && key_len == ND_X25519_LEN) {
                memcpy(out_hello->x25519_public_key, key, ND_X25519_LEN);
                found = 1;
            }
        }
        if (!found) return ND_ERR_UNSUPPORTED;
    }

    (void)legacy_version; /* RFC 9147: MUST be ignored by receivers */
    return ND_OK;
}
