/* EncryptedExtensions / Certificate / CertificateVerify tests.
 *
 * The CertificateVerify vector is, like test_p256.c and test_x509.c, real
 * output from the OpenSSL 3.5.7 installed on this machine rather than
 * hand-built bytes: the exact RFC 8446 section 4.4.3 content (64 bytes of
 * 0x20, "TLS 1.3, server CertificateVerify", a 0x00 separator, and an
 * arbitrary-but-fixed 32-byte stand-in transcript hash) was signed with
 * leaf_key.pem -- the same key behind LEAF_CERT_DER -- and OpenSSL's own
 * `dgst -verify` confirmed it before nano-dtls ever saw it (see
 * scratchpad/gen_p256_kat.py-style generation, this time for
 * CertificateVerify's specific content framing). The transcript hash here
 * isn't from a real handshake -- there is no full handshake yet to draw one
 * from -- but that's irrelevant to what's under test: whether
 * nd_certificate_verify_check reconstructs the exact signed content and
 * calls ECDSA verify correctly. */
#include "nanodtls/messages.h"

#include "nanodtls/x509.h"
#include "test_util.h"
#include "x509_test_certs.h"

static const uint8_t CV_TRANSCRIPT_HASH[] = {
    0xe7, 0x5e, 0x90, 0xe5, 0xc9, 0x48, 0x3e, 0xdf, 0xef, 0x47, 0x43, 0xcf,
    0x54, 0x71, 0x6c, 0x71, 0x77, 0xf3, 0x3a, 0x69, 0x68, 0x6d, 0xa9, 0x79,
    0x2d, 0xa7, 0x6e, 0x8b, 0xa4, 0x9d, 0x65, 0x95,
};

static const uint8_t CV_MSG_WIRE[] = {
    0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x05, 0x61, 0xdb, 0x85,
    0xca, 0x5b, 0x4a, 0xdd, 0xf9, 0x45, 0xec, 0x52, 0x9f, 0x0f, 0xb2, 0x1a,
    0x1f, 0xa2, 0x35, 0xb1, 0x61, 0x17, 0xf6, 0xff, 0x7f, 0x47, 0x3e, 0x6e,
    0x94, 0x43, 0xf0, 0x11, 0x02, 0x21, 0x00, 0xcd, 0x6a, 0xd6, 0x91, 0x12,
    0x19, 0x18, 0x1b, 0xed, 0x0c, 0x4a, 0xda, 0xf7, 0xa7, 0x30, 0xbf, 0x05,
    0xa0, 0x27, 0x8a, 0xaa, 0x79, 0x73, 0xef, 0x0a, 0xe5, 0x98, 0x25, 0x26,
    0xc1, 0x5e, 0xde,
};
#define CV_MSG_WIRE_LEN 75u

static void test_encrypted_extensions_round_trip(void) {
    uint8_t buf[8];
    size_t len;
    CHECK(nd_encrypted_extensions_serialize(buf, sizeof(buf), &len) == ND_OK);
    CHECK(len == 2);
    CHECK(buf[0] == 0 && buf[1] == 0);
    CHECK(nd_encrypted_extensions_parse(buf, len) == ND_OK);
}

static void test_encrypted_extensions_rejects_trailing_garbage(void) {
    uint8_t buf[3] = {0x00, 0x00, 0xAA}; /* empty list claimed, but one extra byte follows */
    CHECK(nd_encrypted_extensions_parse(buf, sizeof(buf)) == ND_ERR_BAD_LENGTH);
}

static void test_certificate_round_trip_single_cert(void) {
    nd_certificate_msg msg;
    msg.cert_count = 1;
    msg.cert_der[0] = LEAF_CERT_DER;
    msg.cert_der_len[0] = LEAF_CERT_DER_LEN;

    uint8_t buf[1024];
    size_t len;
    CHECK(nd_certificate_serialize(&msg, buf, sizeof(buf), &len) == ND_OK);
    /* 1 (context len) + 3 (list len) + 3 (entry len) + cert + 2 (ext len) */
    CHECK(len == 1 + 3 + 3 + LEAF_CERT_DER_LEN + 2);

    nd_certificate_msg parsed;
    CHECK(nd_certificate_parse(buf, len, &parsed) == ND_OK);
    CHECK(parsed.cert_count == 1);
    CHECK(parsed.cert_der_len[0] == LEAF_CERT_DER_LEN);
    CHECK(nd_bytes_eq(parsed.cert_der[0], LEAF_CERT_DER, LEAF_CERT_DER_LEN));
}

static void test_certificate_round_trip_two_certs(void) {
    nd_certificate_msg msg;
    msg.cert_count = 2;
    msg.cert_der[0] = LEAF_CERT_DER;
    msg.cert_der_len[0] = LEAF_CERT_DER_LEN;
    msg.cert_der[1] = ROOT_CERT_DER;
    msg.cert_der_len[1] = ROOT_CERT_DER_LEN;

    uint8_t buf[2048];
    size_t len;
    CHECK(nd_certificate_serialize(&msg, buf, sizeof(buf), &len) == ND_OK);

    nd_certificate_msg parsed;
    CHECK(nd_certificate_parse(buf, len, &parsed) == ND_OK);
    CHECK(parsed.cert_count == 2);
    CHECK(nd_bytes_eq(parsed.cert_der[0], LEAF_CERT_DER, LEAF_CERT_DER_LEN));
    CHECK(nd_bytes_eq(parsed.cert_der[1], ROOT_CERT_DER, ROOT_CERT_DER_LEN));
}

static void test_certificate_verify_content_layout(void) {
    uint8_t transcript_hash[32];
    for (int i = 0; i < 32; ++i) transcript_hash[i] = (uint8_t)i;

    uint8_t content[ND_CERT_VERIFY_CONTENT_MAX];
    size_t content_len;
    CHECK(nd_certificate_verify_content(ND_CERT_VERIFY_CONTEXT_SERVER, transcript_hash, content, sizeof(content),
                                         &content_len) == ND_OK);

    size_t ctx_len = 33; /* strlen("TLS 1.3, server CertificateVerify") */
    CHECK(content_len == 64 + ctx_len + 1 + 32);
    for (int i = 0; i < 64; ++i) CHECK(content[i] == 0x20);
    CHECK(nd_bytes_eq(content + 64, (const uint8_t *)ND_CERT_VERIFY_CONTEXT_SERVER, ctx_len));
    CHECK(content[64 + ctx_len] == 0x00);
    CHECK(nd_bytes_eq(content + 64 + ctx_len + 1, transcript_hash, 32));
}

static void test_certificate_verify_real_signature_verifies(void) {
    nd_certificate_verify_msg msg;
    CHECK(nd_certificate_verify_parse(CV_MSG_WIRE, CV_MSG_WIRE_LEN, &msg) == ND_OK);
    CHECK(msg.algorithm == ND_SIGSCHEME_ECDSA_SECP256R1_SHA256);

    nd_x509_cert leaf;
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);

    CHECK(nd_certificate_verify_check(&msg, ND_CERT_VERIFY_CONTEXT_SERVER, CV_TRANSCRIPT_HASH, leaf.pubkey_qx,
                                       leaf.pubkey_qy) == ND_OK);
}

static void test_certificate_verify_wrong_context_rejected(void) {
    /* Same signature, but checked as if it were a CLIENT CertificateVerify
     * -- the context string differs, so the signed content differs, so
     * verification must fail even though the signature itself is genuine. */
    nd_certificate_verify_msg msg;
    CHECK(nd_certificate_verify_parse(CV_MSG_WIRE, CV_MSG_WIRE_LEN, &msg) == ND_OK);

    nd_x509_cert leaf;
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);

    CHECK(nd_certificate_verify_check(&msg, ND_CERT_VERIFY_CONTEXT_CLIENT, CV_TRANSCRIPT_HASH, leaf.pubkey_qx,
                                       leaf.pubkey_qy) == ND_ERR_AUTH_FAILED);
}

static void test_certificate_verify_wrong_transcript_hash_rejected(void) {
    nd_certificate_verify_msg msg;
    CHECK(nd_certificate_verify_parse(CV_MSG_WIRE, CV_MSG_WIRE_LEN, &msg) == ND_OK);

    nd_x509_cert leaf;
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);

    uint8_t tampered_hash[32];
    for (int i = 0; i < 32; ++i) tampered_hash[i] = CV_TRANSCRIPT_HASH[i];
    tampered_hash[0] ^= 0x01;

    CHECK(nd_certificate_verify_check(&msg, ND_CERT_VERIFY_CONTEXT_SERVER, tampered_hash, leaf.pubkey_qx,
                                       leaf.pubkey_qy) == ND_ERR_AUTH_FAILED);
}

static void test_certificate_verify_wrong_key_rejected(void) {
    nd_certificate_verify_msg msg;
    CHECK(nd_certificate_verify_parse(CV_MSG_WIRE, CV_MSG_WIRE_LEN, &msg) == ND_OK);

    nd_x509_cert root; /* root's key did NOT produce this signature -- leaf's did */
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);

    CHECK(nd_certificate_verify_check(&msg, ND_CERT_VERIFY_CONTEXT_SERVER, CV_TRANSCRIPT_HASH, root.pubkey_qx,
                                       root.pubkey_qy) == ND_ERR_AUTH_FAILED);
}

static void test_certificate_verify_unsupported_algorithm_rejected(void) {
    uint8_t buf[8] = {0x08, 0x07, 0x00, 0x02, 0xAA, 0xBB}; /* ed25519 (0x0807): not implemented */
    nd_certificate_verify_msg msg;
    CHECK(nd_certificate_verify_parse(buf, 6, &msg) == ND_OK);
    CHECK(msg.algorithm == 0x0807);

    nd_x509_cert leaf;
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);
    CHECK(nd_certificate_verify_check(&msg, ND_CERT_VERIFY_CONTEXT_SERVER, CV_TRANSCRIPT_HASH, leaf.pubkey_qx,
                                       leaf.pubkey_qy) == ND_ERR_UNSUPPORTED);
}

int main(void) {
    test_encrypted_extensions_round_trip();
    test_encrypted_extensions_rejects_trailing_garbage();
    test_certificate_round_trip_single_cert();
    test_certificate_round_trip_two_certs();
    test_certificate_verify_content_layout();
    test_certificate_verify_real_signature_verifies();
    test_certificate_verify_wrong_context_rejected();
    test_certificate_verify_wrong_transcript_hash_rejected();
    test_certificate_verify_wrong_key_rejected();
    test_certificate_verify_unsupported_algorithm_rejected();
    return nd_test_summary("test_messages");
}
