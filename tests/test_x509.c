/* X.509 parse + chain verification tests, against a real 2-certificate
 * chain: a self-signed P-256 root CA and a leaf it actually signed, both
 * produced and cross-verified by the OpenSSL 3.5.7 installed on this
 * machine (`openssl verify -CAfile root_cert.pem leaf_cert.pem` said OK
 * before either DER blob was ever handed to nano-dtls -- see
 * scratchpad/gen_x509_kat.py). Real ASN.1, real ECDSA-P256-SHA256
 * signatures, real RFC 5280 structure -- not synthetic bytes. */
#include "nanodtls/x509.h"

#include "test_util.h"

#include "x509_test_certs.h"

/* Both certs' notBefore is 2026-08-04 05:20:52 UTC; root expires 2036-08-01,
 * leaf expires 2028-11-06. AT_TIME sits inside both windows. */
static const uint64_t AT_TIME_VALID = 20270101000000ULL;
static const uint64_t AT_TIME_BEFORE_NOT_BEFORE = 20200101000000ULL;
static const uint64_t AT_TIME_AFTER_LEAF_EXPIRY = 20300101000000ULL;

static void test_parse_root_and_leaf(void) {
    nd_x509_cert root, leaf;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);

    CHECK(root.is_ca == 1);   /* root_cert.pem was issued with basicConstraints CA:TRUE */
    CHECK(leaf.is_ca == 0);   /* leaf_cert.pem was issued with basicConstraints CA:FALSE */

    CHECK(root.not_before == 20260804052052ULL);
    CHECK(root.not_after == 20360801052052ULL);
    CHECK(leaf.not_before == 20260804052052ULL);
    CHECK(leaf.not_after == 20281106052052ULL);

    /* root is self-signed: issuer and subject Name DER must be byte-identical */
    CHECK(root.issuer_der_len == root.subject_der_len);
    CHECK(nd_bytes_eq(root.issuer_der, root.subject_der, root.issuer_der_len));

    /* leaf's issuer must match root's subject -- the chain-linkage check
     * nd_x509_verify_chain performs internally */
    CHECK(leaf.issuer_der_len == root.subject_der_len);
    CHECK(nd_bytes_eq(leaf.issuer_der, root.subject_der, leaf.issuer_der_len));
}

static void test_root_is_self_signed_valid_signature(void) {
    nd_x509_cert root;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);
    CHECK(nd_x509_verify_signature(&root, root.pubkey_qx, root.pubkey_qy) == ND_OK);
}

static void test_leaf_signed_by_root(void) {
    nd_x509_cert root, leaf;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);
    CHECK(nd_x509_verify_signature(&leaf, root.pubkey_qx, root.pubkey_qy) == ND_OK);
}

static void test_leaf_not_self_signed(void) {
    /* Sanity check the verifier actually checks the key: leaf's own public
     * key must NOT validate leaf's own signature (it was signed by root). */
    nd_x509_cert leaf;
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);
    CHECK(nd_x509_verify_signature(&leaf, leaf.pubkey_qx, leaf.pubkey_qy) == ND_ERR_AUTH_FAILED);
}

static void test_full_chain_verify(void) {
    nd_x509_cert root, leaf;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);

    CHECK(nd_x509_verify_chain(&leaf, 1, &root, AT_TIME_VALID) == ND_OK);
}

static void test_chain_rejects_untrusted_root(void) {
    nd_x509_cert root, leaf, not_the_root;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);
    /* leaf "trusted" against itself as a root -- wrong issuer linkage */
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &not_the_root) == ND_OK);

    CHECK(nd_x509_verify_chain(&leaf, 1, &not_the_root, AT_TIME_VALID) == ND_ERR_AUTH_FAILED);
    (void)root;
}

static void test_chain_rejects_non_ca_signer(void) {
    /* Using the leaf (is_ca == 0) as if it were a trust anchor for itself
     * must fail even when self-comparison of issuer/subject would
     * otherwise be silly-matched -- the is_ca gate must independently
     * reject it. Reuse leaf as its own "anchor" candidate: its own subject
     * won't equal its own issuer (leaf's issuer is the root's subject), so
     * this also exercises the linkage check failing first; is_ca is
     * checked regardless of ordering inside nd_x509_verify_chain. */
    nd_x509_cert leaf;
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);
    CHECK(nd_x509_verify_chain(&leaf, 1, &leaf, AT_TIME_VALID) == ND_ERR_AUTH_FAILED);
}

static void test_chain_rejects_outside_validity_window(void) {
    nd_x509_cert root, leaf;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);
    CHECK(nd_x509_parse(LEAF_CERT_DER, LEAF_CERT_DER_LEN, &leaf) == ND_OK);

    CHECK(nd_x509_verify_chain(&leaf, 1, &root, AT_TIME_BEFORE_NOT_BEFORE) == ND_ERR_AUTH_FAILED);
    CHECK(nd_x509_verify_chain(&leaf, 1, &root, AT_TIME_AFTER_LEAF_EXPIRY) == ND_ERR_AUTH_FAILED);
}

static void test_tampered_der_rejected(void) {
    uint8_t tampered[LEAF_CERT_DER_LEN];
    for (size_t i = 0; i < LEAF_CERT_DER_LEN; ++i) tampered[i] = LEAF_CERT_DER[i];
    tampered[100] ^= 0x01; /* flip a byte inside TBSCertificate (well within its span) */

    nd_x509_cert root, leaf;
    CHECK(nd_x509_parse(ROOT_CERT_DER, ROOT_CERT_DER_LEN, &root) == ND_OK);
    nd_status parsed = nd_x509_parse(tampered, LEAF_CERT_DER_LEN, &leaf);
    /* Either the tamper corrupts DER structure (parse fails) or it survives
     * parsing but the signature no longer matches -- both are an honest
     * "don't trust this" outcome, never ND_OK end to end. */
    if (parsed == ND_OK) {
        CHECK(nd_x509_verify_chain(&leaf, 1, &root, AT_TIME_VALID) != ND_OK);
    } else {
        CHECK(parsed != ND_OK);
    }
}

int main(void) {
    test_parse_root_and_leaf();
    test_root_is_self_signed_valid_signature();
    test_leaf_signed_by_root();
    test_leaf_not_self_signed();
    test_full_chain_verify();
    test_chain_rejects_untrusted_root();
    test_chain_rejects_non_ca_signer();
    test_chain_rejects_outside_validity_window();
    test_tampered_der_rejected();
    return nd_test_summary("test_x509");
}
