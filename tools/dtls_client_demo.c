/* Real DTLS 1.3 client, over real UDP sockets, driving nd_client_handshake
 * end to end against tools/dtls_server_demo.c (or, in principle, any real
 * DTLS 1.3 peer -- see that file's comment for why OpenSSL isn't one yet in
 * this environment). Loads the same real root CA nd_x509_verify_chain
 * checks the server's certificate against. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "nanodtls/client.h"
#include "nanodtls/udp.h"

static uint8_t *read_whole_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)len);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)len, f);
    fclose(f);
    if (got != (size_t)len) {
        free(buf);
        return NULL;
    }
    *out_len = (size_t)len;
    return buf;
}

/* Real wall-clock "now", folded into nd_x509_cert's canonical
 * YYYYMMDDHHMMSS form -- nanodtls itself makes no system-clock assumption
 * (nd_x509_verify_chain takes at_time as an explicit argument), but a real
 * client normally does want the actual current time for the certificate
 * validity check, so that's what this demo program supplies. */
static uint64_t now_canonical(void) {
    time_t t = time(NULL);
    struct tm tm_utc;
#if defined(_WIN32)
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    uint64_t year = (uint64_t)(tm_utc.tm_year + 1900);
    uint64_t mon = (uint64_t)(tm_utc.tm_mon + 1);
    uint64_t day = (uint64_t)tm_utc.tm_mday;
    uint64_t hour = (uint64_t)tm_utc.tm_hour;
    uint64_t min = (uint64_t)tm_utc.tm_min;
    uint64_t sec = (uint64_t)tm_utc.tm_sec;
    return year * 10000000000ULL + mon * 100000000ULL + day * 1000000ULL + hour * 10000ULL + min * 100ULL + sec;
}

int main(int argc, char **argv) {
    const char *cert_dir = (argc > 1) ? argv[1] : "examples/certs";
    const char *host = (argc > 2) ? argv[2] : "127.0.0.1";
    uint16_t port = (argc > 3) ? (uint16_t)atoi(argv[3]) : 4443;

    char root_path[512];
    snprintf(root_path, sizeof(root_path), "%s/root_cert.der", cert_dir);
    size_t root_len;
    uint8_t *root_der = read_whole_file(root_path, &root_len);
    if (!root_der) {
        fprintf(stderr, "client: failed to load %s\n", root_path);
        return 1;
    }

    nd_x509_cert trust_anchor;
    if (nd_x509_parse(root_der, root_len, &trust_anchor) != ND_OK) {
        fprintf(stderr, "client: failed to parse trust anchor\n");
        free(root_der);
        return 1;
    }

    if (nd_udp_global_init() != ND_OK) {
        fprintf(stderr, "client: nd_udp_global_init failed\n");
        free(root_der);
        return 1;
    }

    nd_udp_socket sock;
    if (nd_udp_client_connect(&sock, host, port) != ND_OK) {
        fprintf(stderr, "client: connect to %s:%u failed\n", host, (unsigned)port);
        free(root_der);
        nd_udp_global_cleanup();
        return 1;
    }
    fprintf(stderr, "client: connected (UDP) to %s:%u\n", host, (unsigned)port);

    nd_client_result result;
    nd_status st = nd_client_handshake(&sock, &trust_anchor, now_canonical(), /*recv_timeout_ms=*/10000, &result);

    nd_udp_close(&sock);
    nd_udp_global_cleanup();
    free(root_der);

    if (st != ND_OK) {
        fprintf(stderr, "client: handshake failed, status=%d\n", (int)st);
        return 1;
    }
    fprintf(stderr, "client: handshake completed successfully\n");
    fprintf(stderr, "client: server leaf cert is_ca=%d, not_before=%llu, not_after=%llu\n", result.server_leaf.is_ca,
            (unsigned long long)result.server_leaf.not_before, (unsigned long long)result.server_leaf.not_after);
    return 0;
}
