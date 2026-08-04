/* Fuzzes the DER/ASN.1 TLV reader and the full X.509 certificate parser --
 * the parser most likely to face genuinely adversarial input in practice
 * (a malicious or malformed peer certificate), and the newest/least
 * battle-tested code in this repo. See fuzz_util.h. */
#include "nanodtls/asn1.h"
#include "nanodtls/x509.h"

#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nd_asn1_tlv tlv;
    nd_asn1_parse_tlv(data, size, &tlv);

    nd_asn1_reader r;
    nd_asn1_reader_init(&r, data, size);
    while (!nd_asn1_reader_done(&r)) {
        nd_asn1_tlv child;
        if (nd_asn1_reader_next(&r, &child) != ND_OK) break;
    }

    nd_x509_cert cert;
    nd_x509_parse(data, size, &cert);

    return 0;
}

ND_FUZZ_MAIN("fuzz_x509")
