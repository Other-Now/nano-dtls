/* X25519 known-answer tests, both quoted directly from RFC 7748:
 * - section 5.2's raw scalarmult test vector.
 * - section 6.1's Diffie-Hellman example (Alice/Bob), which additionally
 *   exercises scalarmult against a non-basepoint input (each side's
 *   scalarmult of the OTHER's public key) and checks the two directions
 *   agree -- a correctness property beyond just matching fixed constants. */
#include "nanodtls/x25519.h"
#include "test_util.h"

static void test_rfc7748_section_5_2(void) {
    uint8_t scalar[32], u_in[32], expected[32];
    CHECK(nd_hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar,
                        sizeof(scalar)) == 32);
    CHECK(nd_hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u_in,
                        sizeof(u_in)) == 32);
    CHECK(nd_hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", expected,
                        sizeof(expected)) == 32);

    uint8_t got[32];
    CHECK(nd_x25519_scalarmult(scalar, u_in, got) == ND_OK);
    CHECK(nd_bytes_eq(got, expected, 32));
}

static void test_rfc7748_section_6_1_diffie_hellman(void) {
    uint8_t alice_priv[32], alice_pub_expected[32];
    uint8_t bob_priv[32], bob_pub_expected[32];
    uint8_t shared_expected[32];

    CHECK(nd_hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                        alice_priv, 32) == 32);
    CHECK(nd_hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                        alice_pub_expected, 32) == 32);
    CHECK(nd_hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                        bob_priv, 32) == 32);
    CHECK(nd_hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                        bob_pub_expected, 32) == 32);
    CHECK(nd_hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                        shared_expected, 32) == 32);

    uint8_t alice_pub[32], bob_pub[32];
    CHECK(nd_x25519_base(alice_priv, alice_pub) == ND_OK);
    CHECK(nd_bytes_eq(alice_pub, alice_pub_expected, 32));

    CHECK(nd_x25519_base(bob_priv, bob_pub) == ND_OK);
    CHECK(nd_bytes_eq(bob_pub, bob_pub_expected, 32));

    uint8_t shared_from_alice[32], shared_from_bob[32];
    CHECK(nd_x25519_scalarmult(alice_priv, bob_pub, shared_from_alice) == ND_OK);
    CHECK(nd_x25519_scalarmult(bob_priv, alice_pub, shared_from_bob) == ND_OK);

    CHECK(nd_bytes_eq(shared_from_alice, shared_expected, 32));
    CHECK(nd_bytes_eq(shared_from_bob, shared_expected, 32));
    CHECK(nd_bytes_eq(shared_from_alice, shared_from_bob, 32)); /* DH commutativity */
}

static void test_bad_args(void) {
    uint8_t buf[32] = {0};
    CHECK(nd_x25519_scalarmult(NULL, buf, buf) == ND_ERR_BAD_ARG);
    CHECK(nd_x25519_scalarmult(buf, NULL, buf) == ND_ERR_BAD_ARG);
    CHECK(nd_x25519_scalarmult(buf, buf, NULL) == ND_ERR_BAD_ARG);
}

int main(void) {
    test_rfc7748_section_5_2();
    test_rfc7748_section_6_1_diffie_hellman();
    test_bad_args();
    return nd_test_summary("test_x25519");
}
