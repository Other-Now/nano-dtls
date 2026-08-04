/* See nanodtls/client.h for scope. */
#include "nanodtls/client.h"

#include <string.h>

#include "nanodtls/handshake.h"
#include "nanodtls/hello.h"
#include "nanodtls/messages.h"
#include "nanodtls/random.h"
#include "nanodtls/record.h"
#include "nanodtls/transcript.h"
#include "nanodtls/x25519.h"

#define ND_MAX_MSG 4096u
#define ND_CLIENT_HELLO_MAX_ATTEMPTS 5

/* Wraps body in a Handshake header, writes the whole thing to out (zero-copy
 * body pointer required to stay valid until the caller's done with it), and
 * adds those exact wrapped bytes to the transcript -- every handshake
 * message this client sends or receives goes through this one path so the
 * "add to transcript in wire order" invariant can't be forgotten at a call
 * site. */
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

/* Blocks for one DTLSPlaintext record (epoch 0, unencrypted -- only used
 * for ClientHello/ServerHello) and returns its Handshake-framed fragment. */
static nd_status recv_plaintext_handshake(nd_udp_socket *sock, int timeout_ms, uint8_t *datagram_buf,
                                           size_t datagram_cap, nd_handshake_hdr *out_hdr,
                                           const uint8_t **out_fragment, size_t *out_fragment_len,
                                           const uint8_t **out_record_start, size_t *out_record_len) {
    size_t datagram_len;
    nd_status st = nd_udp_recv(sock, datagram_buf, datagram_cap, &datagram_len, timeout_ms);
    if (st != ND_OK) return st;

    nd_plaintext_hdr phdr;
    const uint8_t *fragment;
    size_t fragment_len;
    st = nd_plaintext_parse(datagram_buf, datagram_len, &phdr, &fragment, &fragment_len);
    if (st != ND_OK) return st;
    if (phdr.type != ND_CT_HANDSHAKE) return ND_ERR_UNSUPPORTED;

    *out_record_start = fragment;
    *out_record_len = fragment_len;
    return nd_handshake_parse(fragment, fragment_len, out_hdr, out_fragment, out_fragment_len);
}

/* Blocks for one protected (unified-header) record, decrypts it, and
 * returns the Handshake-framed fragment inside. plaintext_buf backs the
 * decrypted bytes (both the record bytes added to the transcript and the
 * fragment returned point into it). */
static nd_status recv_protected_handshake(nd_udp_socket *sock, int timeout_ms, nd_record_unprotection *u,
                                           uint8_t *datagram_buf, size_t datagram_cap, uint8_t *plaintext_buf,
                                           size_t plaintext_cap, size_t *plaintext_len, nd_handshake_hdr *out_hdr,
                                           const uint8_t **out_fragment, size_t *out_fragment_len) {
    size_t datagram_len;
    nd_status st = nd_udp_recv(sock, datagram_buf, datagram_cap, &datagram_len, timeout_ms);
    if (st != ND_OK) return st;

    uint8_t content_type;
    st = nd_record_unprotect(u, datagram_buf, datagram_len, plaintext_buf, plaintext_cap, plaintext_len,
                              &content_type);
    if (st != ND_OK) return st;
    if (content_type != ND_CT_HANDSHAKE) return ND_ERR_UNSUPPORTED;

    return nd_handshake_parse(plaintext_buf, *plaintext_len, out_hdr, out_fragment, out_fragment_len);
}

nd_status nd_client_handshake(nd_udp_socket *sock, const nd_x509_cert *trust_anchor, uint64_t at_time,
                               int recv_timeout_ms, nd_client_result *out_result) {
    if (!sock || !trust_anchor || !out_result) return ND_ERR_BAD_ARG;

    nd_transcript transcript;
    nd_transcript_init(&transcript);

    /* ---- ClientHello ---- */
    nd_client_hello_params ch_params;
    if (nd_random_bytes(ch_params.random, ND_RANDOM_LEN) != ND_OK) return ND_ERR_BAD_ARG;
    uint8_t x25519_priv[ND_X25519_LEN];
    if (nd_random_bytes(x25519_priv, ND_X25519_LEN) != ND_OK) return ND_ERR_BAD_ARG;
    if (nd_x25519_base(x25519_priv, ch_params.x25519_public_key) != ND_OK) return ND_ERR_BAD_ARG;

    uint8_t ch_body[512];
    size_t ch_body_len;
    nd_status st = nd_client_hello_serialize(&ch_params, ch_body, sizeof(ch_body), &ch_body_len);
    if (st != ND_OK) return st;

    uint8_t ch_wrapped[512 + ND_HANDSHAKE_HDR_LEN];
    size_t ch_wrapped_len;
    st = wrap_and_add(&transcript, ND_HS_CLIENT_HELLO, 0, ch_body, ch_body_len, ch_wrapped, sizeof(ch_wrapped),
                       &ch_wrapped_len);
    if (st != ND_OK) return st;

    nd_plaintext_hdr ph;
    ph.type = ND_CT_HANDSHAKE;
    ph.legacy_version = ND_VERSION_DTLS1_2;
    ph.epoch = 0;
    ph.sequence_number = 0;
    uint8_t ch_datagram[ND_MAX_MSG];
    size_t ch_datagram_len;
    st = nd_plaintext_serialize(&ph, ch_wrapped, ch_wrapped_len, ch_datagram, sizeof(ch_datagram), &ch_datagram_len);
    if (st != ND_OK) return st;

    /* ---- ServerHello, with bounded retransmission of ClientHello on
     * timeout (RFC 9147 section 5.7's flight-retransmission idea, in its
     * simplest form: no exponential backoff, no cookie/HelloRetryRequest
     * handling -- just "resend the same flight if nothing came back").
     * This is the one place this build's otherwise-blocking-and-unreliable
     * state machine (see nanodtls/client.h scope note) actually exercises
     * Stage 4 reliability behavior live, rather than only in the standalone
     * unit tests for nd_replay_window/nd_ack/nd_reassembly. */
    uint8_t datagram[ND_MAX_MSG]; /* receive scratch -- distinct from ch_datagram, which a retry resends unmodified */
    /* All of these are only ever read after a successful
     * recv_plaintext_handshake sets them, but the retry loop's
     * every-attempt-failed path isn't provably unreachable to the
     * compiler -- zero-init avoids relying on that provability. */
    nd_handshake_hdr hh = {0};
    const uint8_t *frag = NULL;
    size_t frag_len = 0;
    const uint8_t *sh_wrapped = NULL;
    size_t sh_wrapped_len = 0;
    st = ND_ERR_TRUNCATED;
    for (int attempt = 0; attempt < ND_CLIENT_HELLO_MAX_ATTEMPTS; ++attempt) {
        /* A send can itself fail here -- e.g. a connected UDP socket
         * surfacing a delayed ICMP Port Unreachable from an earlier
         * attempt, if nothing was listening yet -- and that's still just
         * "this attempt didn't work", not fatal: keep retrying rather than
         * giving up on the first transient send error. */
        nd_status send_st = nd_udp_send(sock, ch_datagram, ch_datagram_len);
        if (send_st != ND_OK) {
            st = send_st;
            continue;
        }

        st = recv_plaintext_handshake(sock, recv_timeout_ms, datagram, sizeof(datagram), &hh, &frag, &frag_len,
                                       &sh_wrapped, &sh_wrapped_len);
        if (st == ND_OK) break; /* got a reply -- stop retransmitting */
    }
    if (st != ND_OK) return st; /* exhausted retries with no reply */
    if (hh.msg_type != ND_HS_SERVER_HELLO) return ND_ERR_UNSUPPORTED;
    if (hh.fragment_offset != 0 || hh.fragment_length != hh.length) return ND_ERR_UNSUPPORTED; /* no fragmentation */
    nd_transcript_add(&transcript, sh_wrapped, sh_wrapped_len);

    nd_server_hello sh;
    st = nd_server_hello_parse(frag, frag_len, &sh);
    if (st != ND_OK) return st;
    if (sh.cipher_suite != ND_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) return ND_ERR_UNSUPPORTED;

    uint8_t shared_secret[ND_X25519_LEN];
    st = nd_x25519_scalarmult(x25519_priv, sh.key_share, shared_secret);
    if (st != ND_OK) return st;
    {
        int all_zero = 1;
        for (size_t i = 0; i < ND_X25519_LEN; ++i)
            if (shared_secret[i]) all_zero = 0;
        if (all_zero) return ND_ERR_AUTH_FAILED; /* RFC 7748 sec 6.1: reject a small-order/invalid peer point */
    }

    uint8_t hello_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, hello_hash);

    nd_handshake_keys keys;
    st = nd_derive_handshake_keys(ND_HKDF_LABEL_PREFIX_DTLS13, shared_secret, hello_hash, &keys);
    if (st != ND_OK) return st;

    nd_record_unprotection server_read;
    nd_record_unprotection_init(&server_read, keys.server_write_key, keys.server_write_iv, /*epoch=*/2);
    nd_record_protection client_write;
    nd_record_protection_init(&client_write, keys.client_write_key, keys.client_write_iv, /*epoch=*/2);

    /* ---- EncryptedExtensions ---- */
    uint8_t plaintext[ND_MAX_MSG];
    size_t plaintext_len;
    st = recv_protected_handshake(sock, recv_timeout_ms, &server_read, datagram, sizeof(datagram), plaintext,
                                   sizeof(plaintext), &plaintext_len, &hh, &frag, &frag_len);
    if (st != ND_OK) return st;
    if (hh.msg_type != ND_HS_ENCRYPTED_EXTENSIONS) return ND_ERR_UNSUPPORTED;
    if (hh.fragment_offset != 0 || hh.fragment_length != hh.length) return ND_ERR_UNSUPPORTED;
    st = nd_encrypted_extensions_parse(frag, frag_len);
    if (st != ND_OK) return st;
    nd_transcript_add(&transcript, plaintext, plaintext_len);

    /* ---- Certificate ---- */
    st = recv_protected_handshake(sock, recv_timeout_ms, &server_read, datagram, sizeof(datagram), plaintext,
                                   sizeof(plaintext), &plaintext_len, &hh, &frag, &frag_len);
    if (st != ND_OK) return st;
    if (hh.msg_type != ND_HS_CERTIFICATE) return ND_ERR_UNSUPPORTED;
    if (hh.fragment_offset != 0 || hh.fragment_length != hh.length) return ND_ERR_UNSUPPORTED;

    nd_certificate_msg cert_msg;
    st = nd_certificate_parse(frag, frag_len, &cert_msg);
    if (st != ND_OK) return st;

    nd_x509_cert chain[ND_CERTIFICATE_MSG_MAX_CERTS];
    for (size_t i = 0; i < cert_msg.cert_count; ++i) {
        st = nd_x509_parse(cert_msg.cert_der[i], cert_msg.cert_der_len[i], &chain[i]);
        if (st != ND_OK) return st;
    }
    st = nd_x509_verify_chain(chain, cert_msg.cert_count, trust_anchor, at_time);
    if (st != ND_OK) return st;
    nd_transcript_add(&transcript, plaintext, plaintext_len);

    /* ---- CertificateVerify ---- */
    uint8_t cert_verify_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, cert_verify_hash); /* Transcript-Hash(CH..Certificate), before CV itself */

    st = recv_protected_handshake(sock, recv_timeout_ms, &server_read, datagram, sizeof(datagram), plaintext,
                                   sizeof(plaintext), &plaintext_len, &hh, &frag, &frag_len);
    if (st != ND_OK) return st;
    if (hh.msg_type != ND_HS_CERTIFICATE_VERIFY) return ND_ERR_UNSUPPORTED;
    if (hh.fragment_offset != 0 || hh.fragment_length != hh.length) return ND_ERR_UNSUPPORTED;

    nd_certificate_verify_msg cv_msg;
    st = nd_certificate_verify_parse(frag, frag_len, &cv_msg);
    if (st != ND_OK) return st;
    st = nd_certificate_verify_check(&cv_msg, ND_CERT_VERIFY_CONTEXT_SERVER, cert_verify_hash, chain[0].pubkey_qx,
                                      chain[0].pubkey_qy);
    if (st != ND_OK) return st;
    nd_transcript_add(&transcript, plaintext, plaintext_len);

    /* ---- server Finished ---- */
    uint8_t server_finished_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, server_finished_hash); /* Transcript-Hash(CH..CertificateVerify) */

    st = recv_protected_handshake(sock, recv_timeout_ms, &server_read, datagram, sizeof(datagram), plaintext,
                                   sizeof(plaintext), &plaintext_len, &hh, &frag, &frag_len);
    if (st != ND_OK) return st;
    if (hh.msg_type != ND_HS_FINISHED) return ND_ERR_UNSUPPORTED;
    if (hh.fragment_offset != 0 || hh.fragment_length != hh.length) return ND_ERR_UNSUPPORTED;
    if (frag_len != ND_HASH_LEN) return ND_ERR_BAD_LENGTH;

    st = nd_finished_verify(ND_HKDF_LABEL_PREFIX_DTLS13, keys.server_handshake_traffic_secret, server_finished_hash,
                             frag);
    if (st != ND_OK) return st;
    nd_transcript_add(&transcript, plaintext, plaintext_len);

    /* ---- client Finished ---- */
    uint8_t client_finished_hash[ND_HASH_LEN];
    nd_transcript_snapshot(&transcript, client_finished_hash); /* Transcript-Hash(CH..server Finished) */

    uint8_t client_verify_data[ND_HASH_LEN];
    st = nd_finished_compute(ND_HKDF_LABEL_PREFIX_DTLS13, keys.client_handshake_traffic_secret, client_finished_hash,
                              client_verify_data);
    if (st != ND_OK) return st;

    uint8_t fin_wrapped[ND_HASH_LEN + ND_HANDSHAKE_HDR_LEN];
    size_t fin_wrapped_len;
    st = wrap_and_add(&transcript, ND_HS_FINISHED, 1 /* client's 2nd message: CH=0, Finished=1 */, client_verify_data,
                       ND_HASH_LEN, fin_wrapped, sizeof(fin_wrapped), &fin_wrapped_len);
    if (st != ND_OK) return st;

    uint8_t out_record[ND_MAX_MSG];
    size_t out_record_len;
    st = nd_record_protect(&client_write, ND_CT_HANDSHAKE, fin_wrapped, fin_wrapped_len, out_record,
                            sizeof(out_record), &out_record_len);
    if (st != ND_OK) return st;
    st = nd_udp_send(sock, out_record, out_record_len);
    if (st != ND_OK) return st;

    memcpy(&out_result->keys, &keys, sizeof(keys));
    memcpy(&out_result->server_leaf, &chain[0], sizeof(chain[0]));
    return ND_OK;
}
