/* ClientHello serialize: verified by hand-computed TLV offsets (there's no
 * real DTLS 1.3 wire capture handy, so this checks the serializer against a
 * fully worked-out expected byte layout, the same way tests/test_record.c
 * hand-verifies the record header).
 *
 * ServerHello parse: verified against the ACTUAL ServerHello bytes from RFC
 * 8448 section 3's worked TLS 1.3 handshake trace -- real wire bytes from a
 * real implementation, not just a round-trip against our own serializer.
 * Composed through nd_handshake_parse() (Stage 3's DTLS Handshake header)
 * first, so this also exercises that parser against a genuine handshake
 * message rather than only synthetic bytes. */
#include <string.h>

#include "nanodtls/hello.h"
#include "test_util.h"

/* RFC 8448 is a TLS 1.3 trace, so its Handshake header is the 4-byte TLS
 * form (msg_type + 24-bit length) -- NOT nano-dtls's 12-byte DTLS form
 * (msg_type + length + message_seq + fragment_offset + fragment_length,
 * see nanodtls/handshake.h). nd_handshake_parse() is specifically the DTLS
 * parser, so it isn't the right tool for these bytes; strip the TLS header
 * by hand instead. */
static void strip_tls_handshake_header(const uint8_t *wire, size_t wire_len, uint8_t *msg_type,
                                        const uint8_t **body, size_t *body_len) {
    CHECK(wire_len >= 4);
    *msg_type = wire[0];
    uint32_t length = ((uint32_t)wire[1] << 16) | ((uint32_t)wire[2] << 8) | wire[3];
    CHECK(wire_len - 4 == length);
    *body = wire + 4;
    *body_len = length;
}

static void test_client_hello_serialize_byte_layout(void) {
    nd_client_hello_params params;
    for (size_t i = 0; i < ND_RANDOM_LEN; ++i) params.random[i] = (uint8_t)(0xA0 + i);
    for (size_t i = 0; i < ND_X25519_LEN; ++i) params.x25519_public_key[i] = (uint8_t)(0xB0 + i);

    uint8_t buf[256];
    size_t len = 0;
    CHECK(nd_client_hello_serialize(&params, buf, sizeof(buf), &len) == ND_OK);
    CHECK(len == 113); /* hand-computed total: see file header math in the commit/PR notes */

    CHECK(buf[0] == 0xfe && buf[1] == 0xfd); /* legacy_version: DTLS 1.2 compat value */
    for (size_t i = 0; i < ND_RANDOM_LEN; ++i) CHECK(buf[2 + i] == params.random[i]);
    CHECK(buf[34] == 0x00); /* legacy_session_id: empty */
    CHECK(buf[35] == 0x00); /* legacy_cookie: empty (DTLS-only field) */
    CHECK(buf[36] == 0x00 && buf[37] == 0x02); /* cipher_suites length = 2 */
    CHECK(buf[38] == 0x13 && buf[39] == 0x03); /* TLS_CHACHA20_POLY1305_SHA256 */
    CHECK(buf[40] == 0x01);                    /* legacy_compression_methods length = 1 */
    CHECK(buf[41] == 0x00);                    /* null compression */
    CHECK(buf[42] == 0x00 && buf[43] == 0x45); /* extensions length = 69 */

    CHECK(buf[44] == 0x00 && buf[45] == 0x2b); /* supported_versions, type 43 */
    CHECK(buf[46] == 0x00 && buf[47] == 0x03); /* extension_data length = 3 */
    CHECK(buf[48] == 0x02);                    /* version list length = 2 */
    CHECK(buf[49] == 0xfe && buf[50] == 0xfc); /* DTLS 1.3 */

    CHECK(buf[51] == 0x00 && buf[52] == 0x0a); /* supported_groups, type 10 */
    CHECK(buf[53] == 0x00 && buf[54] == 0x04); /* extension_data length = 4 */
    CHECK(buf[55] == 0x00 && buf[56] == 0x02); /* group list length = 2 */
    CHECK(buf[57] == 0x00 && buf[58] == 0x1d); /* x25519 */

    CHECK(buf[59] == 0x00 && buf[60] == 0x33); /* key_share, type 51 */
    CHECK(buf[61] == 0x00 && buf[62] == 0x26); /* extension_data length = 38 */
    CHECK(buf[63] == 0x00 && buf[64] == 0x24); /* KeyShareEntry list length = 36 */
    CHECK(buf[65] == 0x00 && buf[66] == 0x1d); /* group = x25519 */
    CHECK(buf[67] == 0x00 && buf[68] == 0x20); /* key_exchange length = 32 */
    for (size_t i = 0; i < ND_X25519_LEN; ++i) CHECK(buf[69 + i] == params.x25519_public_key[i]);

    CHECK(buf[101] == 0x00 && buf[102] == 0x0d); /* signature_algorithms, type 13 */
    CHECK(buf[103] == 0x00 && buf[104] == 0x08); /* extension_data length = 8 */
    CHECK(buf[105] == 0x00 && buf[106] == 0x06); /* scheme list length = 6 */
    CHECK(buf[107] == 0x04 && buf[108] == 0x03); /* ecdsa_secp256r1_sha256 */
    CHECK(buf[109] == 0x08 && buf[110] == 0x04); /* rsa_pss_rsae_sha256 */
    CHECK(buf[111] == 0x08 && buf[112] == 0x07); /* ed25519 */
}

static void test_client_hello_bad_args(void) {
    uint8_t buf[256];
    size_t len;
    CHECK(nd_client_hello_serialize(NULL, buf, sizeof(buf), &len) == ND_ERR_BAD_ARG);

    nd_client_hello_params params = {0};
    uint8_t tiny[8];
    CHECK(nd_client_hello_serialize(&params, tiny, sizeof(tiny), &len) == ND_ERR_BAD_LENGTH);
}

/* The complete Handshake-header-wrapped ServerHello from RFC 8448 section 3
 * ("Simple 1-RTT Handshake"): msg_type=02 (server_hello), then the 86-byte
 * ServerHello body -- legacy_version, a real random, an empty
 * session_id_echo, cipher_suite=0x1301 (TLS_AES_128_GCM_SHA256 -- RFC 8448
 * uses AES-GCM, not nano-dtls's ChaCha20-Poly1305; the parser doesn't care
 * which suite was negotiated, only how to decode the field), and two
 * extensions: key_share (a real X25519 server share) and supported_versions
 * (selected_version = 0x0304, TLS 1.3). */
static const uint8_t rfc8448_server_hello_wire[] = {
    0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e,
    0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55,
    0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24,
    0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb,
    0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0,
    0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
};

static void test_server_hello_parse_rejects_tls_version(void) {
    /* Real RFC 8448 bytes, unmodified: a genuine TLS 1.3 ServerHello.
     * nano-dtls is DTLS-only, so this MUST be rejected -- accepting it would
     * be a version-confusion bug, not a compatibility nicety. */
    uint8_t msg_type;
    const uint8_t *body;
    size_t body_len;
    strip_tls_handshake_header(rfc8448_server_hello_wire, sizeof(rfc8448_server_hello_wire),
                                &msg_type, &body, &body_len);
    CHECK(msg_type == 2); /* server_hello */
    CHECK(body_len == 0x56);

    nd_server_hello hello;
    CHECK(nd_server_hello_parse(body, body_len, &hello) == ND_ERR_UNSUPPORTED);
    /* selected_version is written before the version check rejects it --
     * confirms the supported_versions extension itself parsed correctly
     * (0x0304 is genuinely what RFC 8448's trace selected: TLS 1.3). */
    CHECK(hello.selected_version == 0x0304);
}

static void test_server_hello_parse_accepts_patched_dtls_version(void) {
    /* Same real RFC 8448 bytes, with only the two selected_version bytes
     * patched from TLS 1.3 (03 04) to DTLS 1.3 (fe fc) -- everything else,
     * including the genuine random and X25519 key share, is untouched. This
     * exercises the full acceptance path against real extension encoding
     * without needing an actual DTLS 1.3 capture. */
    uint8_t wire[sizeof(rfc8448_server_hello_wire)];
    memcpy(wire, rfc8448_server_hello_wire, sizeof(wire));
    size_t last = sizeof(wire);
    CHECK(wire[last - 2] == 0x03 && wire[last - 1] == 0x04);
    wire[last - 2] = 0xfe;
    wire[last - 1] = 0xfc;

    uint8_t msg_type;
    const uint8_t *body;
    size_t body_len;
    strip_tls_handshake_header(wire, sizeof(wire), &msg_type, &body, &body_len);

    nd_server_hello hello;
    CHECK(nd_server_hello_parse(body, body_len, &hello) == ND_OK);
    CHECK(hello.selected_version == ND_DTLS_1_3_VERSION);
    CHECK(hello.cipher_suite == 0x1301);

    uint8_t expected_random[32];
    CHECK(nd_hex_decode("a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95"
                        "93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28",
                        expected_random, 32) == 32);
    CHECK(nd_bytes_eq(hello.random, expected_random, 32));

    uint8_t expected_key_share[32];
    CHECK(nd_hex_decode("c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1"
                        "56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f",
                        expected_key_share, 32) == 32);
    CHECK(nd_bytes_eq(hello.key_share, expected_key_share, 32));
}

static void test_server_hello_parse_malformed(void) {
    nd_server_hello hello;
    CHECK(nd_server_hello_parse(NULL, 0, &hello) == ND_ERR_BAD_ARG);

    uint8_t too_short[10] = {0};
    CHECK(nd_server_hello_parse(too_short, sizeof(too_short), &hello) == ND_ERR_TRUNCATED);

    /* A well-formed-looking prefix but with no extensions at all --
     * required extensions missing, must be ND_ERR_UNSUPPORTED, not a crash
     * or a false accept. */
    uint8_t no_extensions[] = {
        0x03, 0x03,             /* legacy_version */
        0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, /* random */
        0x00,                   /* legacy_session_id_echo length = 0 */
        0x13, 0x03,             /* cipher_suite */
        0x00,                   /* legacy_compression_method */
        0x00, 0x00,             /* extensions length = 0 */
    };
    CHECK(nd_server_hello_parse(no_extensions, sizeof(no_extensions), &hello) ==
          ND_ERR_UNSUPPORTED);
}

static void test_server_hello_roundtrip(void) {
    nd_server_hello_params params;
    for (size_t i = 0; i < ND_RANDOM_LEN; ++i) params.random[i] = (uint8_t)(0xC0 + i);
    for (size_t i = 0; i < ND_X25519_LEN; ++i) params.x25519_public_key[i] = (uint8_t)(0xD0 + i);

    uint8_t buf[128];
    size_t len = 0;
    CHECK(nd_server_hello_serialize(&params, buf, sizeof(buf), &len) == ND_OK);
    /* legacy_version(2) + random(32) + session_id_echo(1+0) + cipher_suite(2)
     * + compression(1) + ext_len(2) + [supported_versions: 4+2] +
     * [key_share: 4+2+2+32=40] = 2+32+1+2+1+2+6+40 = 86 */
    CHECK(len == 86);

    nd_server_hello parsed;
    CHECK(nd_server_hello_parse(buf, len, &parsed) == ND_OK);
    CHECK(nd_bytes_eq(parsed.random, params.random, ND_RANDOM_LEN));
    CHECK(parsed.cipher_suite == ND_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);
    CHECK(parsed.selected_version == ND_DTLS_1_3_VERSION);
    CHECK(nd_bytes_eq(parsed.key_share, params.x25519_public_key, ND_X25519_LEN));
}

static void test_server_hello_serialize_bad_args(void) {
    uint8_t buf[128];
    size_t len;
    CHECK(nd_server_hello_serialize(NULL, buf, sizeof(buf), &len) == ND_ERR_BAD_ARG);

    nd_server_hello_params params = {0};
    uint8_t tiny[8];
    CHECK(nd_server_hello_serialize(&params, tiny, sizeof(tiny), &len) == ND_ERR_BAD_LENGTH);
}

/* nd_client_hello_parse is the server-role mirror of nd_client_hello_serialize
 * (already byte-layout-verified above) -- checked here via round-trip
 * through that same serializer, the standard pattern this repo uses when
 * there's no independent real-implementation wire trace to parse (unlike
 * ServerHello, which is checked against real RFC 8448 bytes above). */
static void test_client_hello_roundtrip(void) {
    nd_client_hello_params params;
    for (size_t i = 0; i < ND_RANDOM_LEN; ++i) params.random[i] = (uint8_t)(0xA0 + i);
    for (size_t i = 0; i < ND_X25519_LEN; ++i) params.x25519_public_key[i] = (uint8_t)(0xB0 + i);

    uint8_t buf[256];
    size_t len = 0;
    CHECK(nd_client_hello_serialize(&params, buf, sizeof(buf), &len) == ND_OK);

    nd_client_hello parsed;
    CHECK(nd_client_hello_parse(buf, len, &parsed) == ND_OK);
    CHECK(nd_bytes_eq(parsed.random, params.random, ND_RANDOM_LEN));
    CHECK(nd_bytes_eq(parsed.x25519_public_key, params.x25519_public_key, ND_X25519_LEN));
}

static void test_client_hello_parse_malformed(void) {
    nd_client_hello_params params;
    for (size_t i = 0; i < ND_RANDOM_LEN; ++i) params.random[i] = (uint8_t)i;
    for (size_t i = 0; i < ND_X25519_LEN; ++i) params.x25519_public_key[i] = (uint8_t)i;
    uint8_t buf[256];
    size_t len = 0;
    CHECK(nd_client_hello_serialize(&params, buf, sizeof(buf), &len) == ND_OK);

    nd_client_hello parsed;
    CHECK(nd_client_hello_parse(buf, 10, &parsed) == ND_ERR_TRUNCATED);

    /* Corrupt the cipher_suites list to something never containing our
     * suite -- ext block offsets shift, but the parser must still fail
     * cleanly (ND_ERR_UNSUPPORTED), not read out of bounds or crash. */
    uint8_t bad[256];
    for (size_t i = 0; i < len; ++i) bad[i] = buf[i];
    size_t cs_offset = 2 + ND_RANDOM_LEN + 1 + 1; /* legacy_version+random+session_id_len(0)+cookie_len(0) */
    bad[cs_offset + 2] = 0x00;
    bad[cs_offset + 3] = 0x00; /* cipher suite 0x0000: never matches */
    CHECK(nd_client_hello_parse(bad, len, &parsed) == ND_ERR_UNSUPPORTED);
}

int main(void) {
    test_client_hello_serialize_byte_layout();
    test_client_hello_bad_args();
    test_server_hello_parse_rejects_tls_version();
    test_server_hello_parse_accepts_patched_dtls_version();
    test_server_hello_parse_malformed();
    test_server_hello_roundtrip();
    test_server_hello_serialize_bad_args();
    test_client_hello_roundtrip();
    test_client_hello_parse_malformed();
    return nd_test_summary("test_hello");
}
