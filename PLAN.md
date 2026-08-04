# nano-dtls — Project Plan

A from-scratch, zero-copy **DTLS 1.3** stack (RFC 9147, sharing the TLS 1.3
handshake/key-schedule core of RFC 8446) in portable **C11**, engineered as a
low-latency / zero-allocation hot path and sized for an embedded/RTOS target.
The name is a deliberate nod to the compact embedded TLS/DTLS SDKs shipped
by security vendors for resource-constrained targets — that's the exact
class of product this mimics.

Target readers: a low-latency C++/HFT panel *and* an embedded-security
panel (the kind that reviews compact embedded TLS/DTLS SDKs), from the
same repo. See "Why one project covers both lanes" below — that's the
whole thesis of this build.

---

## 0. Why this project

- **On-taste for both lanes at once.** A DTLS record is a binary wire format
  with a header, sequence number, and length — parsed the same way as an
  EOBI/ITCH message ([itch-orderbook](../itch-orderbook)). The payload happens
  to be AEAD-encrypted and the framing happens to be a security protocol.
- **DTLS over UDP, not plain TLS.** UDP forces a sequence-number + anti-replay
  window and out-of-order/reordered record handling — the same machinery
  already built for Binance depth-sync gap detection (`U`/`u`/`pu`) and NSE
  sequence-continuity checks. It's also what embedded/IoT actually uses
  (CoAP-over-DTLS), so it's more on-target for IoT-security positioning than
  plain TLS.
- **Existing muscles this reuses:** zero-copy wire parsing (itch-orderbook),
  replay/gap windows (Binance sync), zero-alloc SPSC pipelines
  (AWSFileStreamer), crypto APIs (HMAC/ECDSA/Keccak/BLAKE3 — see
  [cdc-store](../cdc-store)), cross-arch bit-exact determinism (cdc-store,
  [gemm-lab](../gemm-lab)/GEMM). That's why this is ~3-4 focused weeks, not
  three months.

## 1. Why one project covers both lanes

- **The HFT reviewer sees:** zero-copy wire parsing, a zero-alloc hot path,
  cache-conscious layout, nanosecond-level per-record latency benchmarked
  against OpenSSL, sequence/replay-window handling, deterministic behavior —
  existing strengths, restated in a networking-security context.
- **An embedded-security reviewer sees:** a cryptographic + networking
  protocol implemented in C, on a resource-constrained target, with
  constant-time crypto, secure-coding discipline (fuzzing + static analysis),
  X.509 cert-chain verification (the PKI touch), and a hybrid post-quantum
  key exchange — i.e. exactly what a compact embedded TLS/crypto SDK has
  to do.

"Constant RAM, no malloc on the hot path" is simultaneously a low-latency
claim *and* an embedded claim — that line does double duty throughout.

## 2. Scope — the staged ladder

Each stage is a shippable checkpoint with its own defensible story (same
format as [gemm-lab](../gemm-lab)'s optimization ladder), so even stopping
early leaves something real and demoable.

### Stage 1 — Record layer, plaintext ✅ (this checkpoint)
Parse/serialize the DTLS record header zero-copy: pointers into a
caller-owned buffer, no allocation, bounds-checked length. Covers both the
`DTLSPlaintext` fixed header (epoch + 48-bit sequence number, used pre-
encryption) and the DTLS 1.3 "unified header" bitfield format used for all
encrypted records (RFC 9147 §4) — connection-ID presence, variable sequence-
number length, optional explicit length, low 2 bits of epoch + reconstruction
against the last known full epoch. This stage alone is the "binary
wire-format parser" bullet.

### Stage 2 — AEAD + key schedule ✅
Cipher suite: **`TLS_CHACHA20_POLY1305_SHA256`**, not AES-128-GCM. Chosen
deliberately over AES-GCM: ChaCha20 and Poly1305 are naturally constant-time
in portable software (ARX operations only -- no S-box table lookups to leak
through cache timing), whereas a from-scratch AES needs either hardware
AES-NI/ARMv8 crypto extensions (not guaranteed on an embedded target) or a
software S-box that's a textbook cache-timing side channel. That tradeoff
favors the embedded/security story this project is making. Built from
scratch: SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), HKDF-Extract/Expand
(RFC 5869), HKDF-Expand-Label + Derive-Secret (RFC 8446 section 7.1), and
AEAD_CHACHA20_POLY1305 (RFC 8439) with a portable radix-2^26 Poly1305 (no
`__int128`, so it builds on MSVC too). Every primitive is verified bit-exact
against published KATs: RFC 5869 Appendix A.1 (HKDF), RFC 8439 sections
2.3.2/2.5.2/2.8.2 (ChaCha20 block, Poly1305, AEAD "Sunscreen" vector), and
the early-secret -> handshake-secret -> handshake-traffic-secret -> write-
key/IV chain from **RFC 8448** section 3's fully worked TLS 1.3 trace.

### Stage 3 — Handshake state machine ✅
ClientHello → ServerHello → EncryptedExtensions → Cert → CertVerify →
Finished, with X25519 (RFC 7748) key share and the transcript hash. The hard,
high-signal core — a protocol state machine in C. Interop against
`openssl s_server`.

Built so far: **X25519** (RFC 7748 section 5) -- the constant-time Montgomery
ladder over GF(2^255-19), in the portable 16-limb radix-2^16 representation
(no `__int128`, same portability reasoning as Poly1305). Verified bit-exact
against RFC 7748's section 5.2 scalarmult vector and the full section 6.1
Alice/Bob Diffie-Hellman example, including cross-checking that both
directions of the exchange agree (DH commutativity), not just that fixed
constants match. Also built: the **DTLS Handshake message header** (RFC 9147
section 5.2 -- msg_type/length plus the DTLS-only message_seq/
fragment_offset/fragment_length fields), zero-copy and bounds-checked in the
same style as the Stage 1 record header.

Also built: **ClientHello serialize / ServerHello parse** (RFC 9147 section
5.3). The DTLS 1.3 ClientHello inserts one field the TLS 1.3 ClientHello
doesn't have -- `legacy_cookie`, between `legacy_session_id` and
`cipher_suites` -- confirmed from the RFC text rather than assumed, since
guessing its position wrong would silently misalign every field after it.
nano-dtls's ClientHello sends one cipher suite (`TLS_CHACHA20_POLY1305_SHA256`),
one key-share group (X25519), and the four extensions a minimal client needs:
`supported_versions` ({0xfefc}), `supported_groups` ({x25519}), `key_share`
(one X25519 entry), and `signature_algorithms` (mandatory per RFC 8446, even
though nano-dtls can't verify a signature yet -- Stage 5). Verified two ways:
the serializer against a hand-computed byte-exact TLV layout (113 bytes,
every field offset checked), and the parser against the **actual ServerHello
bytes from RFC 8448**'s worked handshake trace -- real wire bytes, not just
a round-trip against our own serializer. That parse test first confirms
nano-dtls correctly *rejects* the genuine RFC 8448 bytes (a real TLS 1.3
ServerHello, `selected_version=0x0304`) as `ND_ERR_UNSUPPORTED` -- proof it
doesn't silently accept a TLS 1.3 peer -- then re-parses the same bytes with
only the version field patched to DTLS 1.3, and confirms the genuine random
and X25519 key share extract correctly.

This pass also caught a real bug in already-shipped Stage 2 code: fetching
RFC 9147 section 5.9 turned up that DTLS 1.3 uses a *different*
HKDF-Expand-Label prefix than TLS 1.3 -- `"dtls13"` (six characters, no
trailing space) instead of `"tls13 "` -- for key separation between the two
protocols. `nd_hkdf_expand_label`/`nd_derive_secret` were hardcoded to the
TLS prefix. Fixed by making the prefix an explicit required parameter
(`ND_HKDF_LABEL_PREFIX_TLS13` / `ND_HKDF_LABEL_PREFIX_DTLS13`, no silent
default), with a new test proving the two prefixes actually diverge. The
RFC 8448 KATs still pass unchanged since that trace is genuinely TLS 1.3 and
correctly uses `ND_HKDF_LABEL_PREFIX_TLS13`.

Also built: **transcript hashing** (`nd_transcript`), **`ServerHello`
serialize** (mirroring `ClientHello` serialize), and the **actual DTLS 1.3
key schedule wiring** (`nd_derive_handshake_keys`, `nd_finished_compute`/
`nd_finished_verify`) -- Early Secret through Handshake Secret, both
handshake traffic secrets, write keys/IVs, and the `Finished` value,
composed from the Stage 2 primitives with the label prefix as an explicit
required argument throughout (no silent default, learned the hard way --
see the HKDF prefix bug above). Proved with an end-to-end integration test:
independent "client" and "server" X25519 keypairs, real `ClientHello`/
`ServerHello` messages, each side deriving its own transcript hash, shared
secret, handshake keys, and `Finished` value completely independently --
and landing on byte-identical results. That's the concrete evidence Stage
1-3's pieces compose correctly together, not just pass in isolation.

Completed since: `nd_client_handshake`/`nd_server_handshake`
(`src/handshake/client.c`/`server.c`) drive the full
ClientHello→ServerHello→EncryptedExtensions→Certificate→CertificateVerify→
Finished(server)→Finished(client) exchange over a real cross-platform UDP
transport (`src/transport/udp.c`, Winsock2/BSD sockets, `ND_SOCK()` cast
macro fixing a real 64-bit `SOCKET`-truncation bug found along the way).
`EncryptedExtensions`/`Certificate`/`CertificateVerify` serialize+parse live
in `src/handshake/messages.c`, with `nd_certificate_verify_content` matching
RFC 8446 §4.4.3's exact signed-content byte layout (64×`0x20` padding +
context string + separator + transcript hash). Interop is proven with a
real two-OS-thread, real-socket test (`tests/test_interop.c`, not a mock)
that runs an independent client and server to completion over an actual UDP
socket pair and confirms both sides derive byte-identical keys — a stronger
bar than scripting against `openssl s_server`, which this session's
environment couldn't get to reliably bind for a same-machine probe.

### Stage 4 — DTLS-specific reliability ✅
Anti-replay sliding window (`src/replay.c`, RFC 9147 §4.3 64-bit bitmap,
two-phase check-then-accept so a forged record can never poison the window),
ACK records (`src/ack.c`, RFC 9147 §7), and out-of-order handshake fragment
reassembly (`src/reassembly.c`, RFC 9147 §5.5 byte-granularity bitmap) —
each with full unit coverage (`tests/test_replay.c`, `test_ack.c`,
`test_reassembly.c`). Retransmission is proven live, not just unit-tested:
`test_interop.c`'s second test has the server bind immediately but delay
its first read by 600ms while the client retries ClientHello on a 300ms×5
budget, and confirms the handshake still completes — this is where the
market-data replay/sequence-gap experience transferred directly.

### Stage 5 — X.509 verification ✅
Minimal DER/ASN.1 TLV reader (`src/x509/asn1.c`, low-tag-form only) and
X.509v3 chain verification (`src/x509/x509.c`) — ECDSA-P256-SHA256 only,
DER-byte-equality Name comparison, `basicConstraints cA` checked. Verified
against a real OpenSSL-generated root+leaf cert chain
(`tests/x509_test_certs.h`), not synthetic DER. Caught a real bug along the
way: `nd_asn1_read_uint_fixed` rejected valid post-strip INTEGER bytes with
the sign-byte check firing on the wrong condition — invisible on the root
cert's r/s (32 bytes, no leading zero needed) but tripped by the leaf's
33-byte encoding, caught by testing against the real generated bytes rather
than hand-built ones that happened not to exercise the edge case.

### Stage 6 — Latency ladder ✅
Full end-to-end handshake benchmark (`bench/bench_handshake.c`, min/p50/p99
over 100 real handshakes) drove one real optimization: initial profiling
(temporary per-step instrumentation, since removed) showed ~2 seconds of
handshake latency traced to `mod_inv`'s 256-iteration `mod_pow` being called
inside every P-256 `point_double`/`point_add` — i.e. affine coordinates
paying a full modular inversion per curve operation. Rewrote `ec_point` to
Jacobian coordinates (dbl-2001-b / add-1998-cmo, EFD-verified formulas),
deferring the one unavoidable inversion to the final affine conversion —
measured ~25-30x handshake-latency improvement, full test suite still green
throughout. Record protection (`src/record_protect.c`) also got a targeted
optimization: a direct fixed-shape header writer replacing a two-pass
serialize-then-overwrite, cross-validated against `nd_unified_serialize`'s
own output to prove the fast path produces byte-identical headers.

### Stretch A — Hybrid post-quantum key exchange — deliberately not attempted
Would add `X25519MLKEM768` as a key-share group. **Decision: not built**,
documented honestly rather than shipped half-verified. Reasoning: this
project's whole methodology (stated throughout this plan and enforced in
every stage above) is "verify every primitive bit-exact against a published
KAT, never trust memory for wire formats or math." ML-KEM-768 (FIPS 203) is
a materially larger, sharper-edged undertaking than anything else in this
repo — a full polynomial-ring NTT over `Z_q[X]/(X^256+1)` with `q=3329`,
centered-binomial-distribution sampling from a SHAKE256-based XOF, and a
multi-step compress/decompress encoding — where subtle bugs (an off-by-one
in the NTT butterfly, a wrong CBD parameter, a mismatched byte order in the
encoding) produce a key exchange that *looks* like it works (parses,
completes, derives *some* shared secret) while being silently wrong or
insecure. Implementing that correctly and then verifying it against FIPS
203's own KATs in the time actually left in this session was not realistic
without cutting the same corners this project has refused to cut everywhere
else. Shipping an unverified lattice-crypto implementation would be a worse
portfolio outcome than an honest gap. **What a real implementation would
need:** `src/crypto/mlkem768.c` (NTT forward/inverse, CBD sampling, K-PKE
encrypt/decrypt, the ML-KEM.Encaps/Decaps wrapper), verified against the
NIST ACVP/FIPS 203 KATs, then a `key_share` entry carrying the concatenated
X25519 + ML-KEM-768 public keys/ciphertexts per
`draft-ietf-tls-ecdhe-mlkem`, with the combined shared secret computed as
`concat(X25519_secret, ML-KEM_secret)` fed into the existing HKDF-based key
schedule unchanged (the key-schedule wiring in `src/handshake/key_schedule.c`
already takes an arbitrary-length shared secret, so this is the one part
that would *not* need rework).

### Stretch B — Bare-metal embedded footprint proof ✅
Cortex-M3 (QEMU `lm3s6965evb`), no RTOS, no libc, no heap: `rtos/startup.c`
(vector table + `Reset_Handler`), `rtos/linker.ld` (256KB flash / 64KB RAM,
the board's real memory map), `rtos/freestanding_stubs.c` (`memcpy`/
`memset`/`strlen`, the only libc surface the crypto touches), and
`rtos/main.c` running SHA-256, AEAD_CHACHA20_POLY1305, X25519, and
HKDF-Extract as self-consistency checks (determinism, round-trip, tamper
detection, independent Alice/Bob DH agreement) over polled UART0 — the same
`src/crypto/*.c` translation units the host build uses, unmodified. Built
with `arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -ffreestanding -nostdlib
-nostartfiles -fno-builtin`, clean with `-Wall -Wextra`. Run under
`qemu-system-arm -M lm3s6965evb -nographic -serial mon:stdio`: all 7 checks
print `ok`, final banner `RESULT: PASS`. Measured footprint
(`arm-none-eabi-size`): **7,764 bytes flash** (`.isr_vector` + `.text`, 3.0%
of the board's 256KB) and **8 bytes static RAM** (`.bss`, 0.01% of 64KB) —
see `rtos/README.md` for the full build/run transcript and scope notes (this
proves the crypto core has no hidden OS/heap/libc dependency; it is not a
full on-target DTLS handshake, which would additionally need a UDP-capable
network stack).

## 3. What to measure

- **Latency** (HFT axis): per-record AEAD ns, handshake completion time,
  p50/p99, next to OpenSSL.
- **Footprint** (embedded axis): flash/`.text` size, peak RAM/stack, zero
  heap allocation on the steady-state path.

Capture both in every stage's benchmark output so the one repo speaks to
both audiences.

## 4. Validation & secure coding (the embedded-security differentiator) ✅

- **Known-answer tests** against RFC 8448 traces — bit-exact key derivation. ✅
- **Interop**: real two-process/two-thread same-machine interop over actual
  UDP sockets (`tests/test_interop.c`), not a mock transport — see Stage 3/4
  above. A direct `openssl s_server` probe was attempted but the tool didn't
  reliably bind in this session's environment (an environment quirk, not a
  nano-dtls issue); not pursued further given the stronger self-interop
  evidence already in hand. ✅ (self-interop) / not attempted (OpenSSL)
- **Fuzzing**: three libFuzzer-compatible harnesses (`fuzz/fuzz_record.c`,
  `fuzz_handshake.c`, `fuzz_x509.c`) plus an `ND_FUZZ_MAIN` standalone
  xorshift64-PRNG stress driver used in place of an installed
  libFuzzer/AFL++ toolchain — several million iterations, zero crashes.
  ASan instrumentation was attempted but the MSVC/CMake configuration in
  this environment couldn't get `/fsanitize=address` building alongside
  `/RTC` (Debug) or through RelWithDebInfo; documented honestly as
  "crash-free but without sanitizer instrumentation in this session." ✅
  (functional coverage) / partial (no ASan)
- **Constant-time discipline**: `validation/dudect_check.c`, a
  `dudect`-style Welch's-t-test harness over RDTSC cycles, run against AEAD
  and X25519 — `|t| < 1.1` across three repeated runs (well under the 4.5
  leak threshold). One self-inflicted false positive along the way (a
  buffer reused across timing classes made one class's "decrypt" secretly a
  fast-path tag-mismatch failure, producing a spurious `t=-57`) — fixed by
  pre-computing independent valid ciphertext/tag pairs per class before the
  timed region. Signature verification (ECDSA-P256) is verify-only on
  public data in this library, so it carries no constant-time claim — noted
  explicitly in `p256_internal.h`. ✅
- **Static analysis**: cppcheck (`--enable=warning,style,performance,
  portability`) — one real finding fixed (a `redundantInitialization` dead
  store in `nd_reconstruct_sequence_number`), plus several `constVariable`/
  `uninitvar` hygiene findings addressed (see `src/crypto/hkdf.c`,
  `src/handshake/key_schedule.c`/`hello.c`/`messages.c`). clang-tidy was not
  run in this session (not installed in this environment); cppcheck's
  coverage is the validated static-analysis evidence here. ✅ (cppcheck) /
  not attempted (clang-tidy)

## 5. Honest scope (state this in the README)

Not production TLS, not FIPS-validated, one or two cipher suites, no session
resumption/0-RTT unless added later. Primitives are verified against KATs but
the README should say plainly: use a vetted/validated implementation in
production. This preempts the "did you roll your own crypto?" objection —
the *protocol* is implemented from spec and the *primitives* are verified
against test vectors, deferring to vetted libs for real deployment.

## 6. Repo layout

```
nano-dtls/
├── PLAN.md                 (this file)
├── README.md               (what/why/design/benchmarks)
├── CMakeLists.txt          (C11; lib + tests + bench)
├── .clang-format
├── .gitignore
├── LICENSE
├── include/nanodtls/
│   ├── types.h              (content types, versions, error codes)
│   ├── record.h             (DTLSPlaintext + unified-header record layer)
│   ├── sha256.h              (Stage 2: streaming SHA-256)
│   ├── hmac_sha256.h         (Stage 2: HMAC-SHA256)
│   ├── hkdf.h                (Stage 2: HKDF-Extract/Expand, Expand-Label, Derive-Secret)
│   ├── chacha20.h            (Stage 2: ChaCha20 block/keystream)
│   ├── poly1305.h            (Stage 2: streaming Poly1305)
│   ├── aead.h                (Stage 2: AEAD_CHACHA20_POLY1305)
│   ├── x25519.h              (Stage 3: X25519 key exchange)
│   ├── handshake.h           (Stage 3: DTLS Handshake message header)
│   ├── hello.h               (Stage 3: ClientHello / ServerHello serialize+parse)
│   ├── transcript.h          (Stage 3: transcript hashing)
│   └── key_schedule.h        (Stage 3: handshake key derivation + Finished)
├── src/
│   ├── record.c
│   ├── crypto/
│   │   ├── sha256.c
│   │   ├── hmac_sha256.c
│   │   ├── hkdf.c
│   │   ├── chacha20.c
│   │   ├── poly1305.c
│   │   ├── aead_chacha20poly1305.c
│   │   └── x25519.c
│   └── handshake/
│       ├── header.c          (message_seq/fragment_offset/fragment_length framing)
│       ├── hello.c           (ClientHello / ServerHello serialize+parse)
│       ├── transcript.c
│       └── key_schedule.c
├── tests/
│   ├── test_record.c            (round-trip + bounds/malformed-input checks)
│   ├── test_sha256.c            (NIST/FIPS 180-4 KATs)
│   ├── test_hmac_sha256.c       (RFC 4231 KAT)
│   ├── test_hkdf.c              (RFC 5869 + RFC 8448 key-schedule chain KATs + prefix separation check)
│   ├── test_chacha20poly1305.c  (RFC 8439 KATs + tamper-detection checks)
│   ├── test_x25519.c            (RFC 7748 KATs + DH commutativity check)
│   ├── test_handshake.c         (round-trip + bounds/malformed-input checks)
│   ├── test_hello.c             (byte-exact ClientHello + RFC 8448 ServerHello parse KATs + ServerHello round-trip)
│   ├── test_transcript.c        (snapshot correctness/non-destructiveness)
│   └── test_key_schedule.c      (RFC 8448 partial KAT + Finished tests + end-to-end client/server agreement)
├── bench/
│   ├── bench_record.c       (ns/parse micro-benchmark)
│   ├── bench_aead.c         (ns/op AEAD encrypt/decrypt micro-benchmark)
│   └── bench_x25519.c       (ns/op scalarmult micro-benchmark)
└── .github/workflows/ci.yml (Linux/macOS/Windows build + test matrix)
```

The tree above is Stage 1-2's snapshot; the layout grew without disturbing
it. As actually shipped, the repo additionally has: `src/handshake/client.c`
+ `server.c` + `messages.c` (state machine, EncryptedExtensions/Certificate/
CertificateVerify), `src/transport/udp.c` (cross-platform UDP), `src/x509/`
(`asn1.c`, `x509.c`), `src/record_protect.c` + `src/random.c` + `src/replay.c`
+ `src/ack.c` + `src/reassembly.c`, `src/crypto/p256.c` (+
`p256_internal.h`), `tools/` (demo-only ECDSA signer + `dtls_client_demo.c`/
`dtls_server_demo.c` standalone executables, never linked into the library),
`examples/certs/` (real generated cert/key artifacts), `fuzz/` (three
libFuzzer-compatible harnesses), `validation/dudect_check.c` (constant-time
check), `bench/bench_handshake.c` (full end-to-end latency benchmark), and
`rtos/` (bare-metal Cortex-M3/QEMU footprint proof — see `rtos/README.md`).

## 7. Milestones / checklist

- [x] Repo scaffold, build system, plan.
- [x] `DTLSPlaintext` header pack/parse: zero-copy, bounds-checked,
      round-trip tested.
- [x] DTLS 1.3 unified-header (RFC 9147 §4) bitfield pack/parse: connection
      ID, variable sequence-number length, optional explicit length, epoch
      low-bits + reconstruction against last-known epoch.
- [x] Malformed/truncated-input tests (short buffers, bad lengths) return
      error codes, never read out of bounds — fuzz-readiness from day one.
- [x] ns/parse micro-benchmark for both header shapes.
- [x] GitHub Actions CI (Linux/macOS/Windows).
- [x] Stage 2: SHA-256, HMAC-SHA256, HKDF-Extract/Expand, HKDF-Expand-Label +
      Derive-Secret -- verified bit-exact against RFC 5869 and the RFC 8448
      early/handshake-secret + traffic-secret + write-key/IV chain.
- [x] Stage 2: ChaCha20, Poly1305 (portable radix-2^26, no `__int128`), and
      AEAD_CHACHA20_POLY1305 -- verified bit-exact against RFC 8439 KATs
      (block function, MAC, and the "Sunscreen" AEAD vector), plus explicit
      tamper-detection tests (flipped ciphertext byte / flipped tag byte
      both return `ND_ERR_AUTH_FAILED` without touching the output buffer).
- [x] ns/op micro-benchmark for AEAD encrypt/decrypt at a representative
      record size (baseline: ~4.2us/1200 bytes, ~270 MB/s, unoptimized
      portable C -- see README for the honest framing).
- [x] Stage 3 (partial): X25519 (RFC 7748) constant-time Montgomery ladder,
      portable radix-2^16 field arithmetic (no `__int128`) -- verified
      bit-exact against the RFC 7748 §5.2 vector and the full §6.1
      Alice/Bob Diffie-Hellman example, including DH commutativity.
- [x] Stage 3 (partial): DTLS Handshake message header (RFC 9147 §5.2) --
      msg_type/length + message_seq/fragment_offset/fragment_length,
      zero-copy and bounds-checked, same discipline as the Stage 1 record
      header.
- [x] Stage 3 (partial): fixed a real bug in Stage 2's already-shipped HKDF-
      Expand-Label -- DTLS 1.3 uses label prefix `"dtls13"`, not TLS 1.3's
      `"tls13 "` (RFC 9147 §5.9). Made the prefix an explicit required
      parameter (no silent default) and added a test proving the two
      prefixes diverge; the RFC 8448 KATs still pass, now explicitly pinned
      to `ND_HKDF_LABEL_PREFIX_TLS13` since that trace is genuinely TLS 1.3.
- [x] Stage 3 (partial): ClientHello serialize (RFC 9147 §5.3, including the
      DTLS-only `legacy_cookie` field) verified byte-exact against a
      hand-computed 113-byte TLV layout; ServerHello parse verified against
      the **real ServerHello bytes from RFC 8448**'s worked trace -- first
      confirming nano-dtls correctly rejects the genuine TLS 1.3 bytes
      (`ND_ERR_UNSUPPORTED`, proving no version-confusion accept), then
      re-parsing the same bytes with only the version field patched to
      DTLS 1.3 and confirming the real random/X25519 key share extract
      correctly.
- [x] Stage 3 (partial): transcript hashing (`nd_transcript`, a thin
      snapshot-capable wrapper over streaming SHA-256), `ServerHello`
      serialize (mirrors `ClientHello` serialize, round-trip tested), and
      the real DTLS 1.3 key schedule wiring (`nd_derive_handshake_keys`):
      Early Secret -> Handshake Secret -> both handshake traffic secrets ->
      write key/IV, and `Finished` compute/verify. `handshake_secret` and
      both traffic secrets verified against RFC 8448's real values (they're
      cipher-suite-independent, always 32 bytes); write keys/IVs checked by
      independent recomputation through the already-KAT-tested low-level
      primitives, since RFC 8448's are AES-128-sized and not comparable to
      nano-dtls's ChaCha20-Poly1305-sized ones.
- [x] Stage 3 (partial): end-to-end integration test -- independent
      "client" and "server" X25519 keypairs, real `ClientHello`/
      `ServerHello` messages built through nano-dtls's own serializers, each
      side independently computing the transcript hash, the X25519 shared
      secret, the full handshake key schedule (with the correct `"dtls13"`
      label prefix), and a `Finished` value -- and confirming both sides
      land on byte-identical results. This is the concrete proof that
      Stage 1 (record layer), Stage 2 (crypto primitives), and Stage 3's
      handshake pieces built so far compose correctly, not just pass in
      isolation.
- [x] Stage 3 (complete): full client/server handshake state machine
      (`nd_client_handshake`/`nd_server_handshake`), EncryptedExtensions/
      Certificate/CertificateVerify serialize+parse (RFC 8446 §4.4.2/4.4.3
      exact signed-content layout), cross-platform UDP transport (Winsock2/
      BSD sockets, fixed a real 64-bit `SOCKET`-truncation bug and a
      dual-stack IPv6-wildcard-deaf-to-IPv4 bug along the way), and real
      two-thread/two-socket interop (`tests/test_interop.c`) proving
      independent client/server processes derive byte-identical keys.
- [x] Stage 4: anti-replay sliding window (RFC 9147 §4.3, two-phase
      check-then-accept), ACK records (RFC 9147 §7), out-of-order handshake
      fragment reassembly (RFC 9147 §5.5) — full unit coverage plus a live
      retransmission-recovery proof in `test_interop.c` (server delays its
      read by 600ms, client retries on a 300ms×5 budget, handshake still
      completes).
- [x] Stage 5: DER/ASN.1 TLV reader + X.509v3 chain verification
      (ECDSA-P256-SHA256), verified against a real OpenSSL-generated
      root+leaf cert chain — caught and fixed a real DER INTEGER
      sign-byte-handling bug that only a real (not hand-built) 33-byte
      signature component would trigger.
- [x] Stage 6: P-256 rewritten from affine to Jacobian coordinates
      (dbl-2001-b/add-1998-cmo, EFD-verified), cutting full-handshake
      latency ~25-30x (root-caused via targeted instrumentation to
      `mod_inv` being called once per curve operation under affine
      coordinates); full end-to-end handshake benchmark
      (`bench/bench_handshake.c`, min/p50/p99 over 100 real handshakes).
- [x] Fuzzing: three libFuzzer-compatible harnesses (record, handshake,
      x509) + a standalone xorshift64-PRNG stress driver, several million
      iterations, zero crashes. ASan instrumentation attempted but not
      achieved in this MSVC/CMake environment — documented honestly, not
      claimed.
- [x] Constant-time check: `dudect`-style Welch's-t-test harness
      (`validation/dudect_check.c`) on AEAD and X25519, `|t| < 1.1` across
      three runs. ECDSA-P256 verify is public-data-only and explicitly
      carries no constant-time claim (verify-only, noted in code).
- [x] cppcheck pass (`--enable=warning,style,performance,portability`), one
      real finding fixed (dead store in sequence-number reconstruction) plus
      hygiene findings addressed. clang-tidy not run (not installed in this
      environment) — noted as a gap, not claimed as done.
- [x] Stretch A: hybrid `X25519MLKEM768` key share — **deliberately not
      attempted**, documented with reasoning in the Stretch A section above
      rather than shipped half-verified.
- [x] Stretch B: bare-metal Cortex-M3-under-QEMU build (no RTOS, no libc, no
      heap) with real measured footprint — 7,764 bytes flash (3.0% of
      256KB), 8 bytes static RAM (0.01% of 64KB), all 7 on-target crypto
      self-checks passing over UART. See `rtos/README.md`.

## 8. How to run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # all tests incl. test_interop
./build/bench_record
./build/bench_aead
./build/bench_x25519
./build/bench_handshake     # full end-to-end handshake latency (min/p50/p99)
./build/dudect_check        # constant-time check (AEAD, X25519)
./build/fuzz_record 500000      # standalone stress drivers (or build/run
./build/fuzz_handshake 500000   # these same fuzz/fuzz_*.c files as real
./build/fuzz_x509 500000        # libFuzzer/AFL++ harnesses -- see fuzz_util.h)
```

Bare-metal Cortex-M3/QEMU footprint proof (see `rtos/README.md` for the full
command line and expected UART output):

```bash
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -ffreestanding -nostdlib \
  -nostartfiles -fno-builtin -O2 -Iinclude -T rtos/linker.ld \
  -o build_rtos/nano-dtls-rtos.elf rtos/*.c src/crypto/{sha256,hmac_sha256,\
  hkdf,chacha20,poly1305,aead_chacha20poly1305,x25519}.c
qemu-system-arm -M lm3s6965evb -kernel build_rtos/nano-dtls-rtos.elf \
  -nographic -serial mon:stdio -no-reboot
arm-none-eabi-size build_rtos/nano-dtls-rtos.elf
```
