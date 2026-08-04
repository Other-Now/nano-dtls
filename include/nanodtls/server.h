#ifndef NANODTLS_SERVER_H
#define NANODTLS_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/key_schedule.h"
#include "nanodtls/messages.h"
#include "nanodtls/types.h"
#include "nanodtls/udp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * The server-role mirror of nanodtls/client.h: ClientHello -> ServerHello
 * -> EncryptedExtensions -> Certificate -> CertificateVerify -> Finished
 * (server's) -> Finished (client's).
 *
 * This server never touches a private key itself. CertificateVerify needs
 * an ECDSA signature over a hash this library computes at handshake time
 * (it depends on the live transcript, so it can't be precomputed) -- sign_fn
 * supplies it, exactly like a real integration would plug in an HSM or
 * keystore. nano-dtls's own crypto (nanodtls/p256.h) is deliberately
 * verify-only; see tools/p256_sign_demo.h for the non-constant-time,
 * explicitly-not-for-production signer this repo's own demo/interop
 * programs pass as sign_fn. Same blocking/no-retransmission/
 * no-fragmentation scope as the client role -- see nanodtls/client.h.
 * --------------------------------------------------------------------- */

typedef nd_status (*nd_sign_fn)(void *ctx, const uint8_t hash[32], uint8_t out_r[32], uint8_t out_s[32]);

typedef struct nd_server_config {
    const uint8_t *cert_der[ND_CERTIFICATE_MSG_MAX_CERTS]; /* the chain to send, leaf first */
    size_t cert_der_len[ND_CERTIFICATE_MSG_MAX_CERTS];
    size_t cert_count;
    nd_sign_fn sign_fn; /* signs SHA-256(CertificateVerify content) with the leaf's private key */
    void *sign_ctx;
} nd_server_config;

typedef struct nd_server_result {
    nd_handshake_keys keys;
} nd_server_result;

/* sock must already be nd_udp_server_bind'd (not yet peer-connected -- this
 * function itself calls nd_udp_server_accept_peer to wait for and bind to
 * the first ClientHello's sender). */
nd_status nd_server_handshake(nd_udp_socket *sock, const nd_server_config *config, int recv_timeout_ms,
                               nd_server_result *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_SERVER_H */
