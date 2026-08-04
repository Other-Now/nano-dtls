# Stretch B: bare-metal embedded footprint proof

Proves nano-dtls's crypto core has no hidden OS/heap/libc dependency by
running it on an emulated Cortex-M3 with zero RTOS, zero heap allocation,
and zero libc beyond three freestanding `<string.h>` stubs this repo
provides itself (`freestanding_stubs.c`).

## Scope

This is a **crypto-primitives footprint proof**, not a full DTLS handshake
on hardware. It links and runs, under QEMU, the same translation units the
host build uses unmodified:

- `src/crypto/sha256.c`, `hmac_sha256.c`, `hkdf.c`
- `src/crypto/chacha20.c`, `poly1305.c`, `aead_chacha20poly1305.c`
- `src/crypto/x25519.c`

`rtos/main.c` exercises each of them with self-consistency checks
(determinism, round-trip agreement, tamper detection, independent
Alice/Bob DH agreement) rather than embedded hex KATs, to avoid a
hand-transcription error in a constant nobody can double-check on this
target. The host-side test suite (`ctest`) already covers these primitives
against real RFC test vectors exhaustively — that's not re-proven here.

A full on-target DTLS handshake would additionally need a UDP-capable
network stack (lwIP or similar) wired to a real NIC/QEMU network device,
which is out of scope for what this stretch goal set out to demonstrate.

## Target

QEMU's `lm3s6965evb` machine model: a TI/Stellaris LM3S6965 (Cortex-M3),
256KB flash at `0x00000000`, 64KB SRAM at `0x20000000` — see
`rtos/linker.ld`. Output goes over UART0, polled (no interrupts, no DMA,
no baud-rate setup — QEMU's model doesn't require it).

`rtos/startup.c` provides the minimal 16-entry Cortex-M vector table and
`Reset_Handler` (copy `.data` from flash, zero `.bss`, call `main()`) every
C runtime needs before touching a global — no RTOS, no HAL, no libc
startup file.

## Build

```sh
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -ffreestanding -nostdlib \
  -nostartfiles -fno-builtin -Wall -Wextra -O2 -std=c11 -Iinclude \
  -T rtos/linker.ld -o build_rtos/nano-dtls-rtos.elf \
  rtos/startup.c rtos/uart.c rtos/freestanding_stubs.c rtos/main.c \
  src/crypto/sha256.c src/crypto/hmac_sha256.c src/crypto/hkdf.c \
  src/crypto/chacha20.c src/crypto/poly1305.c \
  src/crypto/aead_chacha20poly1305.c src/crypto/x25519.c
```

Builds clean with `-Wall -Wextra`, no warnings.

## Run

```sh
qemu-system-arm -M lm3s6965evb -kernel build_rtos/nano-dtls-rtos.elf \
  -nographic -serial mon:stdio -no-reboot
```

Observed output:

```
=== nano-dtls bare-metal Cortex-M3 (QEMU lm3s6965evb) crypto smoke test ===
  ok:   SHA-256 deterministic
  ok:   SHA-256 sensitive to input
  ok:   AEAD decrypt succeeds with correct tag
  ok:   AEAD round-trip recovers plaintext
  ok:   AEAD rejects a tampered tag
  ok:   X25519 DH agreement (Alice == Bob)
  ok:   HKDF-Extract deterministic

=== 7 checks, 0 failures ===
RESULT: PASS
```

## Measured footprint

`arm-none-eabi-size -A build_rtos/nano-dtls-rtos.elf`, `-O2`, all seven
crypto primitives above linked in:

| section      | bytes |
|--------------|------:|
| `.isr_vector`|    64 |
| `.text`      | 7,700 |
| `.bss`       |     8 |
| **flash (isr_vector+text)** | **7,764 / 262,144 (3.0%)** |
| **static RAM (bss)**        | **8 / 65,536 (0.01%)** |

No `.data` section (no initialized globals needing flash-to-RAM copy).
Stack usage is not separately measured here (no per-primitive stack-depth
instrumentation on this target); the 64KB RAM region leaves ample headroom
for the whole call stack of this test on top of the 8-byte `.bss`.
