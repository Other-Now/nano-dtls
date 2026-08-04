/* X.509v3 certificate parsing + chain verification. See nanodtls/x509.h for
 * scope. OID DER content-octet constants below were extracted byte-for-byte
 * from a real OpenSSL-issued certificate (scratchpad/gen_x509_kat.py) at
 * known offsets, not hand-encoded from the dotted OID -- the same
 * "don't hand-transcribe, let a trusted tool produce ground truth"
 * discipline this repo has used since the RFC 8448/7748 KATs. */
#include "nanodtls/x509.h"

#include "nanodtls/asn1.h"
#include "nanodtls/hkdf.h"
#include "nanodtls/sha256.h"

static const uint8_t OID_ECDSA_WITH_SHA256[] = {0x2au, 0x86u, 0x48u, 0xceu, 0x3du, 0x04u, 0x03u, 0x02u};
static const uint8_t OID_EC_PUBLIC_KEY[] = {0x2au, 0x86u, 0x48u, 0xceu, 0x3du, 0x02u, 0x01u};
static const uint8_t OID_PRIME256V1[] = {0x2au, 0x86u, 0x48u, 0xceu, 0x3du, 0x03u, 0x01u, 0x07u};
static const uint8_t OID_BASIC_CONSTRAINTS[] = {0x55u, 0x1du, 0x13u};

static int oid_eq(const nd_asn1_tlv *tlv, const uint8_t *oid, size_t oid_len) {
    if (tlv->tag != ND_ASN1_TAG_OID) return 0;
    if (tlv->value_len != oid_len) return 0;
    for (size_t i = 0; i < oid_len; ++i)
        if (tlv->value[i] != oid[i]) return 0;
    return 1;
}

static int der_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    if (!a || !b || alen != blen) return 0;
    for (size_t i = 0; i < alen; ++i)
        if (a[i] != b[i]) return 0;
    return 1;
}

static int all_digits(const uint8_t *p, int n) {
    for (int i = 0; i < n; ++i)
        if (p[i] < '0' || p[i] > '9') return 0;
    return 1;
}

static int d2(const uint8_t *p) { return (p[0] - '0') * 10 + (p[1] - '0'); }

/* Time (RFC 5280 section 4.1.2.5): UTCTime "YYMMDDHHMMSSZ" (2-digit year,
 * >=50 -> 19YY, <50 -> 20YY) or GeneralizedTime "YYYYMMDDHHMMSSZ". Both are
 * folded into one canonical YYYYMMDDHHMMSS integer for plain numeric
 * comparison against a caller-supplied "now". */
static nd_status parse_time(const nd_asn1_tlv *tlv, uint64_t *out) {
    const uint8_t *p = tlv->value;
    int year, mo, dd, hh, mi, ss;
    if (tlv->tag == ND_ASN1_TAG_UTC_TIME) {
        if (tlv->value_len != 13 || p[12] != 'Z' || !all_digits(p, 12)) return ND_ERR_BAD_LENGTH;
        int yy = d2(p);
        year = (yy >= 50) ? 1900 + yy : 2000 + yy;
        mo = d2(p + 2);
        dd = d2(p + 4);
        hh = d2(p + 6);
        mi = d2(p + 8);
        ss = d2(p + 10);
    } else if (tlv->tag == ND_ASN1_TAG_GENERALIZED_TIME) {
        if (tlv->value_len != 15 || p[14] != 'Z' || !all_digits(p, 14)) return ND_ERR_BAD_LENGTH;
        year = (p[0] - '0') * 1000 + (p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0');
        mo = d2(p + 4);
        dd = d2(p + 6);
        hh = d2(p + 8);
        mi = d2(p + 10);
        ss = d2(p + 12);
    } else {
        return ND_ERR_BAD_ARG;
    }
    *out = (uint64_t)year * 10000000000ULL + (uint64_t)mo * 100000000ULL + (uint64_t)dd * 1000000ULL +
           (uint64_t)hh * 10000ULL + (uint64_t)mi * 100ULL + (uint64_t)ss;
    return ND_OK;
}

/* Scans a parsed Extensions SEQUENCE for basicConstraints and sets
 * out->is_ca if it's present with cA TRUE. Absence, or cA FALSE/omitted
 * (DER "3000" -- an empty BasicConstraints SEQUENCE, cA defaults to
 * FALSE per RFC 5280), both leave is_ca at its default of 0. */
static nd_status scan_extensions(const nd_asn1_tlv *ext_list_octets, nd_x509_cert *out) {
    nd_asn1_tlv exts_seq;
    nd_status st = nd_asn1_parse_tlv(ext_list_octets->value, ext_list_octets->value_len, &exts_seq);
    if (st != ND_OK) return st;
    if (exts_seq.tag != ND_ASN1_TAG_SEQUENCE) return ND_ERR_BAD_ARG;

    nd_asn1_reader er;
    nd_asn1_reader_init(&er, exts_seq.value, exts_seq.value_len);
    while (!nd_asn1_reader_done(&er)) {
        nd_asn1_tlv ext;
        st = nd_asn1_reader_next(&er, &ext);
        if (st != ND_OK) return st;
        if (ext.tag != ND_ASN1_TAG_SEQUENCE) return ND_ERR_BAD_ARG;

        nd_asn1_reader xr;
        nd_asn1_reader_init(&xr, ext.value, ext.value_len);
        nd_asn1_tlv ext_oid;
        st = nd_asn1_reader_next(&xr, &ext_oid);
        if (st != ND_OK) return st;

        if (oid_eq(&ext_oid, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS))) {
            nd_asn1_tlv next_field;
            st = nd_asn1_reader_next(&xr, &next_field);
            if (st != ND_OK) return st;
            if (next_field.tag == 0x01u /* BOOLEAN: optional "critical" */) {
                st = nd_asn1_reader_next(&xr, &next_field);
                if (st != ND_OK) return st;
            }
            if (next_field.tag != ND_ASN1_TAG_OCTET_STRING) return ND_ERR_BAD_ARG;
            nd_asn1_tlv bc_seq;
            st = nd_asn1_parse_tlv(next_field.value, next_field.value_len, &bc_seq);
            if (st != ND_OK) return st;
            if (bc_seq.tag == ND_ASN1_TAG_SEQUENCE && bc_seq.value_len > 0) {
                nd_asn1_reader bcr;
                nd_asn1_reader_init(&bcr, bc_seq.value, bc_seq.value_len);
                nd_asn1_tlv ca_bool;
                st = nd_asn1_reader_next(&bcr, &ca_bool);
                if (st != ND_OK) return st;
                if (ca_bool.tag == 0x01u && ca_bool.value_len == 1 && ca_bool.value[0] != 0x00) out->is_ca = 1;
            }
        }
    }
    return ND_OK;
}

nd_status nd_x509_parse(const uint8_t *der, size_t der_len, nd_x509_cert *out) {
    if (!der || !out) return ND_ERR_BAD_ARG;
    out->is_ca = 0;

    nd_asn1_tlv cert_tlv;
    nd_status st = nd_asn1_parse_tlv(der, der_len, &cert_tlv);
    if (st != ND_OK) return st;
    if (cert_tlv.tag != ND_ASN1_TAG_SEQUENCE) return ND_ERR_BAD_ARG;

    nd_asn1_reader cert_r;
    nd_asn1_reader_init(&cert_r, cert_tlv.value, cert_tlv.value_len);

    const uint8_t *tbs_start = cert_r.buf + cert_r.pos;
    nd_asn1_tlv tbs_tlv;
    st = nd_asn1_reader_next(&cert_r, &tbs_tlv);
    if (st != ND_OK) return st;
    if (tbs_tlv.tag != ND_ASN1_TAG_SEQUENCE) return ND_ERR_BAD_ARG;
    out->tbs_der = tbs_start;
    out->tbs_der_len = tbs_tlv.header_len + tbs_tlv.value_len;

    nd_asn1_tlv sig_alg_tlv;
    st = nd_asn1_reader_next(&cert_r, &sig_alg_tlv);
    if (st != ND_OK) return st;
    {
        nd_asn1_reader sar;
        nd_asn1_reader_init(&sar, sig_alg_tlv.value, sig_alg_tlv.value_len);
        nd_asn1_tlv oid_tlv;
        st = nd_asn1_reader_next(&sar, &oid_tlv);
        if (st != ND_OK) return st;
        if (!oid_eq(&oid_tlv, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256))) return ND_ERR_UNSUPPORTED;
    }

    nd_asn1_tlv sig_val_tlv;
    st = nd_asn1_reader_next(&cert_r, &sig_val_tlv);
    if (st != ND_OK) return st;
    {
        const uint8_t *sig_bytes;
        size_t sig_len;
        st = nd_asn1_read_bitstring_bytes(&sig_val_tlv, &sig_bytes, &sig_len);
        if (st != ND_OK) return st;
        nd_asn1_tlv seq_tlv;
        st = nd_asn1_parse_tlv(sig_bytes, sig_len, &seq_tlv);
        if (st != ND_OK) return st;
        if (seq_tlv.tag != ND_ASN1_TAG_SEQUENCE) return ND_ERR_BAD_ARG;
        nd_asn1_reader sr;
        nd_asn1_reader_init(&sr, seq_tlv.value, seq_tlv.value_len);
        nd_asn1_tlv r_tlv, s_tlv;
        st = nd_asn1_reader_next(&sr, &r_tlv);
        if (st != ND_OK) return st;
        st = nd_asn1_reader_next(&sr, &s_tlv);
        if (st != ND_OK) return st;
        st = nd_asn1_read_uint_fixed(&r_tlv, out->sig_r, ND_P256_SCALAR_LEN);
        if (st != ND_OK) return st;
        st = nd_asn1_read_uint_fixed(&s_tlv, out->sig_s, ND_P256_SCALAR_LEN);
        if (st != ND_OK) return st;
    }

    /* --- inside TBSCertificate --- */
    nd_asn1_reader tbs_r;
    nd_asn1_reader_init(&tbs_r, tbs_tlv.value, tbs_tlv.value_len);

    nd_asn1_tlv field;
    st = nd_asn1_reader_next(&tbs_r, &field);
    if (st != ND_OK) return st;
    if (field.tag == ND_ASN1_TAG_CTX(0)) { /* optional [0] version, EXPLICIT */
        st = nd_asn1_reader_next(&tbs_r, &field);
        if (st != ND_OK) return st;
    }
    if (field.tag != ND_ASN1_TAG_INTEGER) return ND_ERR_BAD_ARG; /* serialNumber: present, opaque, not stored */

    nd_asn1_tlv inner_sig_alg;
    st = nd_asn1_reader_next(&tbs_r, &inner_sig_alg); /* "signature" field: RFC 5280 requires == outer sig alg */
    if (st != ND_OK) return st;

    const uint8_t *issuer_start = tbs_r.buf + tbs_r.pos;
    nd_asn1_tlv issuer_tlv;
    st = nd_asn1_reader_next(&tbs_r, &issuer_tlv);
    if (st != ND_OK) return st;
    out->issuer_der = issuer_start;
    out->issuer_der_len = issuer_tlv.header_len + issuer_tlv.value_len;

    nd_asn1_tlv validity_tlv;
    st = nd_asn1_reader_next(&tbs_r, &validity_tlv);
    if (st != ND_OK) return st;
    {
        nd_asn1_reader vr;
        nd_asn1_reader_init(&vr, validity_tlv.value, validity_tlv.value_len);
        nd_asn1_tlv nb, na;
        st = nd_asn1_reader_next(&vr, &nb);
        if (st != ND_OK) return st;
        st = nd_asn1_reader_next(&vr, &na);
        if (st != ND_OK) return st;
        st = parse_time(&nb, &out->not_before);
        if (st != ND_OK) return st;
        st = parse_time(&na, &out->not_after);
        if (st != ND_OK) return st;
    }

    const uint8_t *subject_start = tbs_r.buf + tbs_r.pos;
    nd_asn1_tlv subject_tlv;
    st = nd_asn1_reader_next(&tbs_r, &subject_tlv);
    if (st != ND_OK) return st;
    out->subject_der = subject_start;
    out->subject_der_len = subject_tlv.header_len + subject_tlv.value_len;

    nd_asn1_tlv spki_tlv;
    st = nd_asn1_reader_next(&tbs_r, &spki_tlv);
    if (st != ND_OK) return st;
    {
        nd_asn1_reader sr;
        nd_asn1_reader_init(&sr, spki_tlv.value, spki_tlv.value_len);
        nd_asn1_tlv alg_tlv;
        st = nd_asn1_reader_next(&sr, &alg_tlv);
        if (st != ND_OK) return st;
        {
            nd_asn1_reader ar;
            nd_asn1_reader_init(&ar, alg_tlv.value, alg_tlv.value_len);
            nd_asn1_tlv alg_oid, curve_oid;
            st = nd_asn1_reader_next(&ar, &alg_oid);
            if (st != ND_OK) return st;
            if (!oid_eq(&alg_oid, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) return ND_ERR_UNSUPPORTED;
            st = nd_asn1_reader_next(&ar, &curve_oid);
            if (st != ND_OK) return st;
            if (!oid_eq(&curve_oid, OID_PRIME256V1, sizeof(OID_PRIME256V1))) return ND_ERR_UNSUPPORTED;
        }
        nd_asn1_tlv key_bits_tlv;
        st = nd_asn1_reader_next(&sr, &key_bits_tlv);
        if (st != ND_OK) return st;
        const uint8_t *key_bytes;
        size_t key_len;
        st = nd_asn1_read_bitstring_bytes(&key_bits_tlv, &key_bytes, &key_len);
        if (st != ND_OK) return st;
        if (key_len != 1 + 2 * ND_P256_COORD_LEN || key_bytes[0] != 0x04) return ND_ERR_UNSUPPORTED;
        for (size_t i = 0; i < ND_P256_COORD_LEN; ++i) out->pubkey_qx[i] = key_bytes[1 + i];
        for (size_t i = 0; i < ND_P256_COORD_LEN; ++i) out->pubkey_qy[i] = key_bytes[1 + ND_P256_COORD_LEN + i];
        if (nd_p256_point_is_valid(out->pubkey_qx, out->pubkey_qy) != ND_OK) return ND_ERR_BAD_ARG;
    }

    while (!nd_asn1_reader_done(&tbs_r)) { /* issuerUniqueID [1] / subjectUniqueID [2] / extensions [3], any optional */
        nd_asn1_tlv opt;
        st = nd_asn1_reader_next(&tbs_r, &opt);
        if (st != ND_OK) return st;
        if (opt.tag == ND_ASN1_TAG_CTX(3)) {
            st = scan_extensions(&opt, out);
            if (st != ND_OK) return st;
        }
    }

    (void)inner_sig_alg;
    return ND_OK;
}

nd_status nd_x509_verify_signature(const nd_x509_cert *cert, const uint8_t issuer_qx[ND_P256_COORD_LEN],
                                    const uint8_t issuer_qy[ND_P256_COORD_LEN]) {
    if (!cert || !issuer_qx || !issuer_qy) return ND_ERR_BAD_ARG;
    uint8_t hash[ND_HASH_LEN];
    nd_sha256(cert->tbs_der, cert->tbs_der_len, hash);
    return nd_p256_ecdsa_verify(issuer_qx, issuer_qy, hash, cert->sig_r, cert->sig_s);
}

nd_status nd_x509_verify_chain(const nd_x509_cert *chain, size_t chain_len, const nd_x509_cert *trust_anchor,
                                uint64_t at_time) {
    if (!chain || chain_len == 0 || !trust_anchor) return ND_ERR_BAD_ARG;

    if (at_time < trust_anchor->not_before || at_time > trust_anchor->not_after) return ND_ERR_AUTH_FAILED;
    for (size_t i = 0; i < chain_len; ++i) {
        if (at_time < chain[i].not_before || at_time > chain[i].not_after) return ND_ERR_AUTH_FAILED;
    }

    for (size_t i = 0; i < chain_len; ++i) {
        const nd_x509_cert *subject_cert = &chain[i];
        const nd_x509_cert *issuer_cert = (i + 1 < chain_len) ? &chain[i + 1] : trust_anchor;
        if (!der_eq(subject_cert->issuer_der, subject_cert->issuer_der_len, issuer_cert->subject_der,
                    issuer_cert->subject_der_len)) {
            return ND_ERR_AUTH_FAILED;
        }
        if (!issuer_cert->is_ca) return ND_ERR_AUTH_FAILED;
        nd_status st = nd_x509_verify_signature(subject_cert, issuer_cert->pubkey_qx, issuer_cert->pubkey_qy);
        if (st != ND_OK) return st;
    }
    return ND_OK;
}
