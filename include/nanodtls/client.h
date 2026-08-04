#ifndef NANODTLS_CLIENT_H
#define NANODTLS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "nanodtls/key_schedule.h"
#include "nanodtls/protect.h"
#include "nanodtls/types.h"
#include "nanodtls/udp.h"
#include "nanodtls/x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------
 * The client-role DTLS 1.3 handshake state machine: ClientHello ->
 * ServerHello -> EncryptedExtensions -> Certificate -> CertificateVerify ->
 * Finished (server's) -> Finished (client's), driving the ordering RFC 8446
 * section 4 / RFC 9147 specify, decrypting each server message with the
 * handshake keys derived after ServerHello, and verifying the server's
 * certificate chain and CertificateVerify signature before trusting
 * anything it sent.
 *
 * Deliberately synchronous and blocking, over an already-connected
 * nd_udp_socket. Stage 4's reliability primitives (nd_replay_window,
 * nd_ack, nd_reassembly) exist and are independently tested, but are not
 * yet wired into every step of this flow -- the one place they are is
 * ClientHello: it's retransmitted (unmodified, same bytes) up to
 * ND_CLIENT_HELLO_MAX_ATTEMPTS times, once per recv_timeout_ms with no
 * reply, before giving up. Every message after that still assumes it
 * arrives once, in order, unfragmented. This is a real state machine doing
 * real network I/O, real decryption, and real certificate verification,
 * with one real (if partial) piece of loss recovery; it is not yet a fully
 * *reliable* one end to end. See PLAN.md Stage 3/4.
 * --------------------------------------------------------------------- */

typedef struct nd_client_result {
    nd_handshake_keys keys; /* handshake-phase traffic secrets/keys (see nanodtls/key_schedule.h) --
                              * nano-dtls stops at Finished, so there is no application-data key
                              * derivation (Master Secret / app traffic secrets) here. */
    nd_x509_cert server_leaf; /* the verified leaf certificate, in case the caller wants its identity */
} nd_client_result;

/* sock must already be nd_udp_client_connect'd to the server. trust_anchor
 * is the CA certificate the server's chain must verify against; at_time is
 * the caller-supplied "now" for the certificate validity-window check (see
 * nanodtls/x509.h -- this repo makes no system-clock assumption).
 * recv_timeout_ms bounds each individual blocking receive (not the whole
 * handshake). Returns ND_ERR_AUTH_FAILED if the server's chain or
 * CertificateVerify or Finished don't check out, ND_ERR_UNSUPPORTED if the
 * server sends something this minimal client doesn't handle (a different
 * cipher suite/group/version, or a handshake message split across more
 * than one record). */
nd_status nd_client_handshake(nd_udp_socket *sock, const nd_x509_cert *trust_anchor, uint64_t at_time,
                               int recv_timeout_ms, nd_client_result *out_result);

#ifdef __cplusplus
}
#endif

#endif /* NANODTLS_CLIENT_H */
