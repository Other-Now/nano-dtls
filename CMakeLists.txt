cmake_minimum_required(VERSION 3.16)
project(nanodtls LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Core library.
#   Stage 1: zero-copy record layer -- DTLSPlaintext + the DTLS 1.3 unified
#            header (src/record.c).
#   Stage 2: crypto primitives -- SHA-256, HMAC-SHA256, HKDF/key-schedule,
#            and the AEAD_CHACHA20_POLY1305 cipher suite (src/crypto/).
#   Stage 3: X25519 key exchange (src/crypto/x25519.c), the DTLS Handshake
#            message header, ClientHello/ServerHello encoding, transcript
#            hashing, and the handshake key schedule (src/handshake/). The
#            full state machine, EncryptedExtensions/Certificate/
#            CertificateVerify/Finished handling end to end, and a UDP
#            transport are not built yet -- see PLAN.md.
# Later stages add x509/ sources here without changing this shape.
# ---------------------------------------------------------------------------
add_library(nanodtls STATIC
  src/record.c
  src/record_protect.c
  src/random.c
  src/replay.c
  src/ack.c
  src/reassembly.c
  src/crypto/sha256.c
  src/crypto/hmac_sha256.c
  src/crypto/hkdf.c
  src/crypto/chacha20.c
  src/crypto/poly1305.c
  src/crypto/aead_chacha20poly1305.c
  src/crypto/x25519.c
  src/crypto/p256.c
  src/handshake/header.c
  src/handshake/hello.c
  src/handshake/transcript.c
  src/handshake/key_schedule.c
  src/handshake/messages.c
  src/handshake/client.c
  src/handshake/server.c
  src/x509/asn1.c
  src/x509/x509.c
  src/transport/udp.c)
target_include_directories(nanodtls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(WIN32)
  target_link_libraries(nanodtls PUBLIC ws2_32 bcrypt)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
enable_testing()
foreach(t record sha256 hmac_sha256 hkdf chacha20poly1305 x25519 p256 handshake hello transcript key_schedule x509 messages udp protect replay ack reassembly)
  add_executable(test_${t} tests/test_${t}.c)
  target_include_directories(test_${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(test_${t} PRIVATE nanodtls)
  add_test(NAME ${t} COMMAND test_${t})
endforeach()

# test_interop needs tools/p256_sign_demo.c (the demo-only ECDSA signer --
# see tools/p256_sign_demo.h) to play the server role for real, and POSIX
# builds need pthread for the two-threads-over-real-sockets setup this test
# uses (see tests/test_interop.c).
add_executable(test_interop tests/test_interop.c tools/p256_sign_demo.c)
target_include_directories(test_interop PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/tools)
target_link_libraries(test_interop PRIVATE nanodtls)
if(NOT WIN32)
  find_package(Threads REQUIRED)
  target_link_libraries(test_interop PRIVATE Threads::Threads)
endif()
add_test(NAME interop COMMAND test_interop)

# ---------------------------------------------------------------------------
# Benchmarks: ns/parse for both header shapes, ns/op for the AEAD
# ---------------------------------------------------------------------------
add_executable(bench_record bench/bench_record.c)
target_link_libraries(bench_record PRIVATE nanodtls)

add_executable(bench_aead bench/bench_aead.c)
target_link_libraries(bench_aead PRIVATE nanodtls)

add_executable(bench_x25519 bench/bench_x25519.c)
target_link_libraries(bench_x25519 PRIVATE nanodtls)

# ---------------------------------------------------------------------------
# tools/: demo/interop programs, deliberately NOT part of the nanodtls
# library. p256_sign_demo provides the one private-key operation (ECDSA
# sign) this repo's own crypto never performs -- see tools/p256_sign_demo.h
# for exactly why that line is drawn where it is. dtls_server_demo and
# dtls_client_demo run a real two-sided DTLS 1.3 handshake over real UDP
# sockets (see PLAN.md / README "Honest scope" for what this does and
# doesn't prove about OpenSSL interop).
# ---------------------------------------------------------------------------
add_executable(dtls_server_demo tools/dtls_server_demo.c tools/p256_sign_demo.c)
target_link_libraries(dtls_server_demo PRIVATE nanodtls)
target_include_directories(dtls_server_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tools)

add_executable(dtls_client_demo tools/dtls_client_demo.c)
target_link_libraries(dtls_client_demo PRIVATE nanodtls)

# bench_handshake reuses tests/x509_test_certs.h and tools/p256_sign_demo.c
# (see bench/bench_handshake.c) -- same "not part of nanodtls itself" demo
# signer as test_interop and dtls_server_demo.
add_executable(bench_handshake bench/bench_handshake.c tools/p256_sign_demo.c)
target_include_directories(bench_handshake PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/tools)
target_link_libraries(bench_handshake PRIVATE nanodtls)
if(NOT WIN32)
  target_link_libraries(bench_handshake PRIVATE Threads::Threads)
endif()

# ---------------------------------------------------------------------------
# fuzz/: LLVMFuzzerTestOneInput harnesses for every parser that runs on
# attacker-controlled bytes (record layer, handshake messages, ASN.1/X.509).
# Built here as standalone stress-test executables (see fuzz/fuzz_util.h for
# why: no libFuzzer/AFL++ in this environment) -- rebuild with clang
# -fsanitize=fuzzer,address instead of this CMake target to run them under a
# real fuzzer.
# ---------------------------------------------------------------------------
foreach(f record handshake x509)
  add_executable(fuzz_${f} fuzz/fuzz_${f}.c)
  target_include_directories(fuzz_${f} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/fuzz)
  target_link_libraries(fuzz_${f} PRIVATE nanodtls)
endforeach()

# ---------------------------------------------------------------------------
# validation/: a dudect-style constant-time statistical check for the
# primitives that claim constant-time behavior (AEAD_CHACHA20_POLY1305,
# X25519) -- see validation/dudect_check.c.
# ---------------------------------------------------------------------------
add_executable(dudect_check validation/dudect_check.c)
target_link_libraries(dudect_check PRIVATE nanodtls)
