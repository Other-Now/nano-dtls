/* Fuzzes the record layer: DTLSPlaintext parse, the unified-header parse
 * (both without and with a connection ID), AEAD-protected record
 * unprotect (fixed key/IV, so this stresses the unified-header parse +
 * AEAD-tag-mismatch path against arbitrary bytes, not the crypto itself),
 * and ACK message parse -- every parser here runs directly on
 * network-attacker-controlled bytes before any authentication has
 * happened. See fuzz_util.h for how this actually runs in this repo
 * (standalone stress driver) versus how it would run under a real
 * libFuzzer/AFL++. */
#include <string.h>

#include "nanodtls/ack.h"
#include "nanodtls/protect.h"
#include "nanodtls/record.h"

#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nd_plaintext_hdr phdr;
    const uint8_t *frag;
    size_t frag_len;
    nd_plaintext_parse(data, size, &phdr, &frag, &frag_len);

    nd_unified_hdr uhdr;
    const uint8_t *payload;
    size_t payload_len;
    nd_unified_parse(data, size, 0, &uhdr, &payload, &payload_len);
    nd_unified_parse(data, size, 4, &uhdr, &payload, &payload_len);

    static const uint8_t fixed_key[ND_AEAD_KEY_LEN] = {0};
    static const uint8_t fixed_iv[ND_AEAD_NONCE_LEN] = {0};
    nd_record_unprotection u;
    nd_record_unprotection_init(&u, fixed_key, fixed_iv, 2);
    uint8_t plaintext_out[1024];
    size_t plaintext_len;
    uint8_t content_type;
    nd_record_unprotect(&u, data, size, plaintext_out, sizeof(plaintext_out), &plaintext_len, &content_type);

    nd_ack ack;
    nd_ack_parse(data, size, &ack);

    return 0;
}

ND_FUZZ_MAIN("fuzz_record")
