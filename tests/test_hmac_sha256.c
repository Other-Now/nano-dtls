/* HMAC-SHA256 known-answer test: RFC 4231 section 4.2, Test Case 1
 * (key = 20 bytes of 0x0b, data = "Hi There"). */
#include "nanodtls/hmac_sha256.h"
#include "test_util.h"

int main(void) {
    uint8_t key[20];
    for (int i = 0; i < 20; ++i) key[i] = 0x0b;

    uint8_t data[8];
    CHECK(nd_hex_decode("4869205468657265", data, sizeof(data)) == 8); /* "Hi There" */

    uint8_t expected[32];
    CHECK(nd_hex_decode("b0344c61 d8db3853 5ca8afce af0bf12b 881dc200 c9833da7 26e9376c 2e32cff7",
                        expected, sizeof(expected)) == 32);

    uint8_t got[32];
    nd_hmac_sha256(key, sizeof(key), data, sizeof(data), got);
    CHECK(nd_bytes_eq(got, expected, sizeof(expected)));

    return nd_test_summary("test_hmac_sha256");
}
