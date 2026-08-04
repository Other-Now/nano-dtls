/* See nanodtls/server.h for scope. */
#include "nanodtls/server.h"

#include <string.h>

#include "nanodtls/asn1.h"
#include "nanodtls/handshake.h"
#include "nanodtls/hello.h"
#include "nanodtls/protect.h"
#include "nanodtls/random.h"
#include "nanodtls/record.h"
#include "nanodtls/sha256.h"
#include "nanodtls/transcript.h"
#include "nanodtls/x25519.h"

#define ND_MAX_MSG 4096u

static nd_status wrap_and_add(nd_transcript *t, uint8_t msg_type, uint16_t message_seq, const uint8_t *body,
                               size_t body_len, uint8_t *out, size_t out_cap, size_t *out_len) {
    nd_handshake_hdr hdr;
    hdr.msg_type = msg_type;
    hdr.length = (uint32_t)body_len;
    hdr.message_seq = message_seq;
    hdr.fragment_offset = 0;
    hdr.fragment_length = (uint32_t)body_len;
    nd_status st = nd_handshake_serialize(&hdr, body, body_len, out, out_cap, out_len);
    if (st != ND_OK) return st;
    nd_transcript_add(t, out, *out_len);
    return ND_OK;
}

/* Wraps, adds to transcript, protects, and sends one handshake message in
 * one call -- every server-to-client message after the key schedule is
 * derived goes through this, so "protect with the right epoch" and "add to
 * transcript" can't drift apart at a call site. */
static nd_status send_protected(nd_udp_socket *sock, nd_transcript *t, nd_record_protection *w, uint8_t msg_type,
                                 uint16_t message_seq, const uint8_t *body, size_t body_len) {
    uint8_t wrapped[ND_MAX_MSG];
    size_t wrapped_len;
    nd_status st = wrap_and_add(t, msg_type, message_seq, body, body_len, wrapped, sizeof(wrapped), &wrapped_len);
    if (st != ND_OK) return st;

    uint8_t record[ND_MAX_MSG];
    size_t record_len;
    st = nd_record_protect(w, ND_CT_HANDSHAKE, wrapped, wrapped_len, record, sizeof(record), &record_len);
    if (st != ND_OK) return st;
    return nd_udp_send(sock, record, record_len);
}

nd_status nd_server_handshake(nd_udp_socket *sock, const nd_server_config *config, int recv_timeout_ms,
                               nd_server_result *out_result) {
    if (!sock || !config || !config->sign_fn || !out_result) return ND_ERR_BAD_ARG;
    if (config->cert_count == 0 || config->cert_count > ND_CERTIFICATE_MSG_MAX_CERTS) return ND_ERR_BAD_ARG;

    nd_transcript transcript;
    nd_transcript_init(&transcript);

    /* ---- ClientHello ---- */
    uint8_t datagram[ND_MAX_MSG];
    size_t datagram_len;
    nd_status st = nd_udp_server_accept_peer(sock, datagram, sizeof(datagram), &datagram_len, recv_timeout_ms);
    if (st != ND_OK) return st;

    nd_plaintext_hdr ph;
    const uint8_t *ch_wrapped;
    size_t ch_wrapped_len;
    st = nd_plaintext_parse(datagram, datagram_len, &ph, &ch_wrapped, &ch_wrapped_len);
    if (st != ND_OK) return st;
    if (ph.type != ND_CT_HANDSHAKE) return ND_ERR_UNSUPPORTED;

    nd_handshake_hdr hh;
    const uint8_t *frag;
    size_t frag_len;
    st = nd_handshake_parse(ch_wrapped, ch_wrapped_len, &hh, &frag, &frag_len);
    if (st != ND_OK) return st;
    if (hh.msg_type != ND_HS_CLIENT_HELLO) return ND_ERR_UNSUPPORTED;
    if (hh.fragment_offset != 0 || hh.fragment_length != hh.length) return ND_ERR_UNSUPPORTED;
    nd_transcript_add(&transcript, ch_wrapped, ch_wrapped_len);

    nd_client_hello ch;
    st = nd_client_hello_parse(frag, frag_len, &ch);
    if (st != ND_OK) return st;

    /* ---- ServerHello ---- */
    uint8_t server_priv[ND_X25519_LEN];
    if (nd_random_bytes(server_priv, ND_X25519_LEN) != ND_OK) return ND_ERR_BAD_ARG;
    nd_server_hello_params sh_params;
    if (nd_random_bytes(sh_params.random, ND_RANDOM_LEN) != ND_OK) return ND_ERR_BAD_ARG;
    if (nd_x25519_base(server_priv, sh_params.x25519_public_key) != ND_OK) return ND_ERR_BAD_ARG;

    uint8_t sh_body[512];
    size_t sh_body_len;
    st = nd_server_hello_serialize(&sh_params, sh_body, sizeof(sh_body), &sh_body_len);
    if (st != ND_OK) return st;

    uint8_t sh_wrapped[512 + ND_HANDSHAKE_HDR_LEN];
    size_t sh_wrapped_len;
    st = wrap_and_add(&transcript, ND_HS_SERVER_HELLO, 0, sh_body, sh_body_len, sh_wrapped, sizeof(sh_wrapped),
                       &sh_wrapped_len);
    if (st != ND_OK) return st;

    nd_plaintext_hdr sh_ph;
    sh_ph.type = ND_CT_HANDSHAKE;
    sh_ph.legacy_version = ND_VERSION_DTLS1_2;
    sh_ph.epoch = 0;
    sh_ph.sequence_number = 0;
    uint8_t out_datagram[ND_MAX_MSG];
    size_t out_datagram_len;
    st = nd_plaintext_serialize(&sh_ph, sh_wrapped, sh_wrapped_len, out_datagram, sizeof(out_datagram),
                                 &out_datagram_len);
    if (st != ND_OK) return st;
    st = nd_udp_send(sock, out_datagram, out_datagram_len);
    if (st != ND_OK) return st;

    uint8_t shared_secret[ND_X25519_LEN];
    st = nd_x25519_scalarmult(server_priv, ch.x25519_public_key, shared_secret);
    if (st != ND_OK) return st;
    {
        int all_zero = 1;
        for (size_t i = 0; i < ND_X25519_LEN; ++i)
            if (shared_secret[i]) all_zero = 0;
        if (all_zero) return ND_ERR_AUTH_FAILED;
    }

    uint8_t hello_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, hello_hash);

    nd_handshake_keys keys;
    st = nd_derive_handshake_keys(ND_HKDF_LABEL_PREFIX_DTLS13, shared_secret, hello_hash, &keys);
    if (st != ND_OK) return st;

    nd_record_protection server_write;
    nd_record_protection_init(&server_write, keys.server_write_key, keys.server_write_iv, /*epoch=*/2);
    nd_record_unprotection client_read;
    nd_record_unprotection_init(&client_read, keys.client_write_key, keys.client_write_iv, /*epoch=*/2);

    /* ---- EncryptedExtensions ---- */
    uint8_t ee_body[2];
    size_t ee_body_len;
    st = nd_encrypted_extensions_serialize(ee_body, sizeof(ee_body), &ee_body_len);
    if (st != ND_OK) return st;
    st = send_protected(sock, &transcript, &server_write, ND_HS_ENCRYPTED_EXTENSIONS, 1, ee_body, ee_body_len);
    if (st != ND_OK) return st;

    /* ---- Certificate ---- */
    nd_certificate_msg cert_msg;
    cert_msg.cert_count = config->cert_count;
    for (size_t i = 0; i < config->cert_count; ++i) {
        cert_msg.cert_der[i] = config->cert_der[i];
        cert_msg.cert_der_len[i] = config->cert_der_len[i];
    }
    uint8_t cert_body[ND_MAX_MSG];
    size_t cert_body_len;
    st = nd_certificate_serialize(&cert_msg, cert_body, sizeof(cert_body), &cert_body_len);
    if (st != ND_OK) return st;
    st = send_protected(sock, &transcript, &server_write, ND_HS_CERTIFICATE, 2, cert_body, cert_body_len);
    if (st != ND_OK) return st;

    /* ---- CertificateVerify ---- */
    uint8_t cert_verify_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, cert_verify_hash); /* Transcript-Hash(CH..Certificate) */

    uint8_t cv_content[ND_CERT_VERIFY_CONTENT_MAX];
    size_t cv_content_len;
    st = nd_certificate_verify_content(ND_CERT_VERIFY_CONTEXT_SERVER, cert_verify_hash, cv_content,
                                        sizeof(cv_content), &cv_content_len);
    if (st != ND_OK) return st;
    uint8_t cv_hash[ND_HASH_LEN];
    nd_sha256(cv_content, cv_content_len, cv_hash);

    uint8_t sig_r[32], sig_s[32];
    st = config->sign_fn(config->sign_ctx, cv_hash, sig_r, sig_s);
    if (st != ND_OK) return st;

    uint8_t sig_der[80];
    size_t sig_der_len;
    st = nd_asn1_write_ecdsa_sig_value(sig_r, sig_s, sig_der, sizeof(sig_der), &sig_der_len);
    if (st != ND_OK) return st;

    uint8_t cv_body[4 + 80];
    cv_body[0] = 0x04;
    cv_body[1] = 0x03; /* ecdsa_secp256r1_sha256 */
    cv_body[2] = (uint8_t)(sig_der_len >> 8);
    cv_body[3] = (uint8_t)sig_der_len;
    memcpy(cv_body + 4, sig_der, sig_der_len);
    st = send_protected(sock, &transcript, &server_write, ND_HS_CERTIFICATE_VERIFY, 3, cv_body, 4 + sig_der_len);
    if (st != ND_OK) return st;

    /* ---- server Finished ---- */
    uint8_t server_finished_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, server_finished_hash); /* Transcript-Hash(CH..CertificateVerify) */

    uint8_t server_verify_data[ND_HASH_LEN];
    st = nd_finished_compute(ND_HKDF_LABEL_PREFIX_DTLS13, keys.server_handshake_traffic_secret,
                              server_finished_hash, server_verify_data);
    if (st != ND_OK) return st;
    st = send_protected(sock, &transcript, &server_write, ND_HS_FINISHED, 4, server_verify_data, ND_HASH_LEN);
    if (st != ND_OK) return st;

    /* ---- client Finished ---- */
    uint8_t client_finished_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, client_finished_hash); /* Transcript-Hash(CH..server Finished) */

    /* A client that retransmitted its ClientHello (nd_client_handshake's
     * bounded retry -- see nanodtls/client.h) can leave extra, by-now-stale
     * copies sitting in this socket's receive queue: UDP doesn't discard
     * unread datagrams just because a later one satisfied
     * nd_udp_server_accept_peer. Those stale ClientHellos are epoch-0
     * DTLSPlaintext records, so they fail nd_record_unprotect's
     * unified-header parse outright; skip anything that doesn't decrypt as
     * the expected message and keep waiting, rather than treating a stray
     * leftover retransmission as fatal -- a real DTLS receiver has to
     * tolerate exactly this. Bounded so a genuinely absent/wrong client
     * Finished still fails instead of looping forever. */
    uint8_t plaintext[ND_MAX_MSG];
    size_t plaintext_len = 0;
    uint8_t content_type = 0;
    st = ND_ERR_TRUNCATED;
    for (int attempt = 0; attempt < 8; ++attempt) {
        size_t in_datagram_len;
        nd_status recv_st = nd_udp_recv(sock, datagram, sizeof(datagram), &in_datagram_len, recv_timeout_ms);
        if (recv_st != ND_OK) {
            st = recv_st;
            break;
        }
        st = nd_record_unprotect(&client_read, datagram, in_datagram_len, plaintext, sizeof(plaintext),
                                  &plaintext_len, &content_type);
        if (st == ND_OK) break; /* a genuinely undecryptable/malformed datagram: try the next one in the queue */
    }
    if (st != ND_OK) return st;
    if (content_type != ND_CT_HANDSHAKE) return ND_ERR_UNSUPPORTED;

    st = nd_handshake_parse(plaintext, plaintext_len, &hh, &frag, &frag_len);
    if (st != ND_OK) return st;
    if (hh.msg_type != ND_HS_FINISHED) return ND_ERR_UNSUPPORTED;
    if (hh.fragment_offset != 0 || hh.fragment_length != hh.length) return ND_ERR_UNSUPPORTED;
    if (frag_len != ND_HASH_LEN) return ND_ERR_BAD_LENGTH;

    st = nd_finished_verify(ND_HKDF_LABEL_PREFIX_DTLS13, keys.client_handshake_traffic_secret, client_finished_hash,
                             frag);
    if (st != ND_OK) return st;

    memcpy(&out_result->keys, &keys, sizeof(keys));
    return ND_OK;
}
