/* Fuzzes every handshake-message parser directly on arbitrary bytes: the
 * Handshake header itself, ClientHello, ServerHello, EncryptedExtensions,
 * Certificate, CertificateVerify, and fragment reassembly. These run on
 * bytes that are already past the record layer's AEAD authentication in a
 * real connection, but this repo treats them as hostile input anyway (RFC
 * 9147's "don't trust anything just because it decrypted" discipline
 * doesn't really apply here since these are plaintext structural parsers,
 * but bounds-safety on malformed/truncated/oversized-length input matters
 * regardless of what layer feeds them). See fuzz_util.h. */
#include "nanodtls/handshake.h"
#include "nanodtls/hello.h"
#include "nanodtls/messages.h"
#include "nanodtls/reassembly.h"

#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nd_handshake_hdr hdr;
    const uint8_t *fragment;
    size_t fragment_len;
    nd_status st = nd_handshake_parse(data, size, &hdr, &fragment, &fragment_len);
    if (st == ND_OK) {
        nd_reassembly r;
        nd_reassembly_init(&r);
        nd_reassembly_add_fragment(&r, &hdr, fragment);
    }

    nd_client_hello ch;
    nd_client_hello_parse(data, size, &ch);

    nd_server_hello sh;
    nd_server_hello_parse(data, size, &sh);

    nd_encrypted_extensions_parse(data, size);

    nd_certificate_msg cert_msg;
    nd_certificate_parse(data, size, &cert_msg);

    nd_certificate_verify_msg cv_msg;
    nd_certificate_verify_parse(data, size, &cv_msg);

    return 0;
}

ND_FUZZ_MAIN("fuzz_handshake")
