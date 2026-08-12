# AArch64 cryptography implementation report

Date: 2026-08-11

Branch: `qn2-remediation`

Baseline commit: `1fe9d8d83a65ea7f58b286e24c581d1587c8d34a`

## Outcome

Qanat now uses a hybrid design: C owns API policy, length checks, dispatch,
fallbacks, and authentication-before-decryption; AArch64 assembly owns only the
measured kernels. This is the intended production boundary. Rewriting the whole
cryptographic stack in assembly would enlarge the audit surface without making
parsing, dispatch, padding, or error handling faster.

The functional cryptographic API remains complete on every supported build.
AES-128/256-GCM, ChaCha20-Poly1305, SHA-256/384/512, HMAC/HKDF, and X25519 all
retain C implementations. Assembly coverage is deliberately partial and selected
at runtime. AES-192 is explicitly rejected instead of being routed through an
incorrect round schedule.

This work supplies implementation, ABI and differential harnesses, backend
controls, short-record benchmarks, a full TLS verifier benchmark, and annotated
disassembly. It is strong implementation evidence, not a claim of an independent
third-party cryptographic audit.

## Baseline and environment

The dirty worktree was not reset, cleaned, or discarded. A detached baseline
worktree at the recorded commit was used for before/after binaries.

| Item | Recorded value |
|---|---|
| Host | WSL2, Linux 6.6.114.1, x86_64 |
| Host compiler | GCC 15.2.0 |
| Host assembler/linker | GNU binutils 2.46 |
| Make | GNU Make 4.4.1 |
| Android compiler | NDK r27c Clang 18.0.3 |
| Android linker | LLD 18.0.3 |
| Android targets | AArch64 API 24 and API 33 |
| Device | Xiaomi model `23090RA98G`, Android 13, API 33 |
| Device ISA | `asimd aes pmull sha2 sha512 sve sve2` among reported features |
| CPU parts | six `0xd46` and two `0xd4d` cores |
| Benchmark pin | CPU 7 through `taskset 80` |
| QEMU | `qemu-aarch64: not found` |
| Native Termux compiler | unavailable; `clang` and `make` are not installed |

The final API 24 differential binary used for disassembly has SHA-256
`e533e00c9e1570a325e3b4e0a5a48cc2fe801827f2f8e0574540cc86d6fe1624`.

Clang optimization remarks confirmed that the C X25519 ladder, SHA compression
loops, and Poly1305 carry loop were not auto-vectorized. The X25519 ladder was
reported as non-vectorizable because of its dependent operations; this supported
keeping a coarse C implementation until a suitable audited AArch64 backend is
available.

## Assembly inventory and backend matrix

The five production assembly files contain 1,187 physical source lines. The ABI
probe adds 99 test-only lines.

| Backend | Required feature | C fallback | Dispatch | ABI test | Differential test | Benchmark | Status |
|---|---|---|---|---|---|---|---|
| AES block and CTR | AES CE | scalar AES/CTR | `qn_cpu_has_aes()` | yes | blocks, tails, alignments, in-place | raw AES and AEAD | default when available |
| AES-GCM fused seal | AES CE + PMULL | separate CTR and GHASH | `QN_BACKEND_AES_GCM_FUSED` | yes | all boundary lengths and alignments | AEAD seal | default when available |
| GHASH blocks | PMULL | 4-bit scalar GHASH | `qn_cpu_has_pmull()` | yes | H through H4, 0..1 MiB | raw GHASH | default when available |
| Coarse GCM GHASH | PMULL | scalar AAD/CT/length GHASH | `qn_cpu_has_pmull()` | yes | partial AAD and CT, alignments | coarse GHASH | default when available |
| SHA-256 compression | SHA2 CE | scalar SHA-256 | `qn_cpu_has_sha2()` | yes | block counts and alignments | SHA-256 | default when available |
| ChaCha20 four-block | ASIMD | scalar ChaCha20 | length at least 256 and NEON | yes | boundaries, alignments, in-place, counter edge | raw and AEAD | default at 256 bytes |
| ChaCha20 one-block | ASIMD | scalar ChaCha20 | forced NEON only | yes | boundaries, alignments, in-place | raw ChaCha20 | force-only; slower on device |
| Poly1305 3x44 | baseline A64 integer | 3x44 or 5x26 C | `QN_BACKEND_POLY1305_ASM` | yes | full/partial, 0..1 MiB, alignments | raw and AEAD | default on supported A64 |
| X25519 | none compiled | constant-shape C ladder | explicit unavailable backend | N/A | KAT, low-order, alias, alignment | X25519 | C only |
| SHA-384/512 | none compiled | rolling-16 C schedule | explicit unavailable backend | N/A | existing KAT and randomized API tests | SHA-384/512 | C only |

All public assembly symbols, prototypes, input constraints, and clobber policy are
recorded in the disassembly report. Every production assembly entry accepts
unaligned byte input where its public contract permits it. Exact in-place XOR is
supported for AES-CTR and ChaCha20; GHASH accumulator/data partial overlap is not
part of the contract.

## Implemented changes

### ABI correctness

The pre-fix ABI harness failed 22 checks on the real phone:

- AES-128/256 CTR at 64 and 65 bytes clobbered `d8`: 4 failures.
- GHASH at one and four blocks clobbered `d8`: 2 failures.
- ChaCha20 four-block at one and two groups clobbered `d8` through `d15`:
  16 failures.

AES CTR now uses caller-saved `v31` for its fourth input block. GHASH uses
caller-saved `v16` rather than `v8`. ChaCha20 four-block was reallocated entirely
outside `v8` through `v15`. The fused AES-GCM entry deliberately uses `v8` through
`v15` and saves/restores their required low 64-bit halves in an aligned 80-byte
frame.

The final API 24 and API 33 harnesses both report `crypto ABI tests: ok`.

### Thread-safe dispatch

One `pthread_once` initialization publishes immutable availability, disabled,
forced, and missing-force masks. AES, PMULL, SHA2, and ASIMD are gated separately
from `AT_HWCAP`. A fused path is enabled only when both AES and PMULL are present.
No feature instruction is reached before the corresponding check.

The first-use stress test starts concurrent AES-GCM, ChaCha20-Poly1305, SHA-256,
and X25519 work before any earlier CPU-feature query. The architecture-independent
test passes under TSan, and the accelerated test passes on the AArch64 phone.

Controls are cached once per process:

```text
QN_NO_ASM=1
QN_DISABLE_AES_CE=1             QN_FORCE_AES_CE=1
QN_DISABLE_GHASH_CE=1           QN_FORCE_GHASH_CE=1
QN_DISABLE_AES_GCM_FUSED=1      QN_FORCE_AES_GCM_FUSED=1
QN_DISABLE_SHA256_CE=1          QN_FORCE_SHA256_CE=1
QN_DISABLE_CHACHA_NEON=1        QN_FORCE_CHACHA_NEON=1
QN_DISABLE_POLY1305_ASM=1       QN_FORCE_POLY1305_ASM=1
QN_DISABLE_X25519_ASM=1         QN_FORCE_X25519_ASM=1
QN_DISABLE_SHA512_CE=1          QN_FORCE_SHA512_CE=1
```

On the test phone, the default diagnostic is:

```text
dispatch: aes-ce=on pmull=on fused=on sha256-ce=on chacha-neon=on poly1305-asm=on
```

With `QN_NO_ASM=1`, all six reported backends are off. Forcing each supported
backend turns it on. Disabling AES or PMULL also disables fused AES-GCM. Forcing
the fused path enables its two dependencies when the hardware supports them.

### AES-GCM and GHASH

`E_K(0)` and `E_K(J0)` now use the single-block AES CE entry. The context stores
bounded powers H, H2, H3, and H4. Four-block PMULL GHASH combines
`(Y xor C1)*H4`, `C2*H3`, `C3*H2`, and `C4*H` before one reduction. The coarse
entry keeps the accumulator and powers live across AAD, ciphertext, padding, and
the final length block.

Seal can fuse four AES counters, plaintext XOR, ciphertext stores, and ciphertext
GHASH. Open remains authenticate-first: it computes and checks the tag before
decrypting, and tests verify that invalid tags leave the output buffer unchanged.
GCM text length is bounded to the permitted counter space and bit-length encoding
is checked.

### ChaCha20 and Poly1305

ChaCha20 four-block reconstructs constants, key, counters, and nonce for
feed-forward instead of spilling and reloading a 256-byte copy of the initial
state. Its frame fell from 272 bytes to zero. The new one-block NEON entry is
correct but loses to scalar code on this device, so it remains force-only. The
measured production crossover remains 256 bytes.

The new Poly1305 entry processes full blocks in the existing 3x44-bit layout with
`mul`, `umulh`, `adds`, `adc`, and `extr`. It saves `x19`/`x20` in a 32-byte aligned
frame. Partial final blocks and final reduction continue through the tested C
implementation.

### SHA and wipe

SHA-512/384 now use a rolling 16-word schedule rather than an 80-word stack
schedule. The measured compression-function frame fell from 720 to 224 bytes.
Throughput samples were not accepted as a speed claim because an unchanged
SHA-256 control moved materially during the same thermally constrained runs.

`qn_wipe` now uses `memset` followed by a compiler memory barrier on GCC/Clang.
Final AArch64 disassembly contains a real call to `memset`; the wipe was not
deleted. Other compilers retain the volatile byte fallback.

## Correctness and build matrix

| Environment | Command or mode | Result |
|---|---|---|
| WSL GCC 15.2 | `make CC=gcc strict` | full application built |
| WSL GCC 15.2 | `make CC=gcc analyze` | full application passed `-fanalyzer` build |
| WSL GCC 15.2 | `make CC=gcc strict-test` | 11/11 suites passed |
| WSL GCC 15.2 | `make CC=gcc sanitize-test` | 11/11 suites passed under ASan/UBSan |
| WSL GCC 15.2 | `make CC=gcc tsan-test` | 11/11 suites passed under TSan |
| NDK r27c API 24 | strict `-Werror -Wconversion -Wsign-conversion` | app plus five crypto test/bench binaries built |
| NDK r27c API 33 | same strict flags | app plus five crypto test/bench binaries built |
| Phone, API 24 binary | default crypto/ABI/differential | all passed |
| Phone, API 24 binary | `QN_NO_ASM=1` crypto/differential | all passed; AES CE correctly skipped |
| Phone, API 24 binary | all supported backends forced | crypto and differential passed |
| Phone, API 33 binary | default crypto/ABI/differential | all passed |
| Phone | full `qanat --help`, API 24 and API 33 | both launched successfully |
| Phone | every individual disable/force control | expected dispatch state and crypto tests passed |
| AArch64 QEMU | unavailable | not run |
| Native Termux build | compiler unavailable | not run |

The differential matrix covers lengths 0, 1, 15, 16, 17, 31, 32, 33, 63, 64,
65, 127, 128, 129, 255, 256, 257, 1 KiB, 4 KiB, 16 KiB, and 1 MiB. Byte-source
and byte-destination offsets 0 through 15 are exercised where applicable. Tests
include exact in-place operation, guard bytes, all-zero and randomized inputs,
AES-128/256, partial GHASH AAD/ciphertext, the ChaCha counter boundary, Poly1305
full/partial blocks, invalid tags, X25519 low-order inputs, and X25519 aliasing.

## Microbenchmark method

`bench_crypto` version 2 uses seven samples after calibration, with a target of
25 ms per sample. Short inputs report median ns/op and variation; large inputs
also report MiB/s. Sizes are 64, 128, 256, 1 KiB, 4 KiB, 16 KiB, and 1 MiB.

Accepted A/B comparisons were pinned to CPU 7 and required the observed frequency
cap and battery temperature to match. Later pairs that crossed a cap change were
discarded. Percentages below are calculated from the displayed medians, so the
last decimal can differ slightly from calculations using unrounded samples.

### Baseline to current GHASH pipeline

This pair used a 1.5 GHz cap with matched temperature. Fused seal was disabled in
the current binary to isolate the H-power/multi-block GHASH work.

| Operation | Size | Baseline | Current | Change |
|---|---:|---:|---:|---:|
| raw GHASH | 4 KiB | 792.3 MiB/s | 2101.0 MiB/s | +165.2% |
| raw GHASH | 1 MiB | 795.2 MiB/s | 2102.5 MiB/s | +164.4% |
| AES-128-GCM seal | 4 KiB | 553.5 MiB/s | 1145.7 MiB/s | +107.0% |

### Fused AES-GCM seal, same current binary

This isolated comparison used a 2.1 GHz cap and 39.5 C battery reading. Open was
unchanged and remained authentication-first.

| Size | Fused off | Fused on | Change |
|---:|---:|---:|---:|
| 128 B | 161.7 ns | 150.8 ns | -6.7% latency |
| 256 B | 233.6 ns | 219.0 ns | -6.3% latency |
| 1 KiB | 682.3 ns | 623.3 ns | -8.6% latency |
| 4 KiB | 1582.6 MiB/s | 1742.6 MiB/s | +10.1% |
| 16 KiB | 1628.2 MiB/s | 1795.9 MiB/s | +10.3% |
| 1 MiB | 1615.6 MiB/s | 1780.2 MiB/s | +10.2% |

The 64-byte row, 150.7 to 117.7 ns, had 100% and 49.5% variation and is excluded
from the accepted claim.

### Poly1305, same current binary

This isolated comparison used a 2.1 GHz cap and 38.8 to 38.9 C battery readings.

| Size | C | AArch64 | Change |
|---:|---:|---:|---:|
| 64 B | 80.7 ns | 78.7 ns | -2.5% latency |
| 128 B | 128.9 ns | 124.7 ns | -3.3% latency |
| 256 B | 225.9 ns | 216.9 ns | -4.0% latency |
| 1 KiB | 808.3 ns | 772.9 ns | -4.4% latency |
| 4 KiB | 1245.2 MiB/s | 1299.5 MiB/s | +4.4% |
| 16 KiB | 1252.9 MiB/s | 1311.3 MiB/s | +4.7% |
| 1 MiB | 1231.1 MiB/s | 1307.2 MiB/s | +6.2% |

ChaCha20-Poly1305 seal at 1 MiB moved from 465.2 to 472.2 MiB/s in this pair,
about +1.5%.

### ChaCha20 crossover

At a matched 1.2 GHz cap, the one-lane NEON path lost to scalar at every sampled
size: 441.3 versus 339.0 ns at 64 bytes, 1761.3 versus 1352.3 ns at 256 bytes,
and 138.5 versus 186.3 MiB/s at 1 MiB. It is therefore not a production default.

The four-block current path measured 410.5 MiB/s at 4 KiB, 430.7 MiB/s at
16 KiB, and 423.0 MiB/s at 1 MiB. Its throughput was similar to baseline, but its
stack frame fell from 272 bytes to zero and its ABI defect was removed. The
selected crossover is 256 bytes.

X25519 remains C-only and measured about 95 microseconds per operation at the
2.1 GHz cap. There is no before/after X25519 speed claim.

## Full TLS verifier benchmark

The fixture is a local TLS 1.3 HTTP/1.1 server reached from the phone through
`adb reverse`. It exercises Qanat's complete verifier session rather than a raw
cipher loop. It does not represent public-network latency.

Six alternating baseline/current cycles used 31 measured sessions after three
warmups. CPU 7 remained capped at 1.5 GHz and the battery reading remained
41.0 C. The aggregate is the median of the six per-process medians.

| Metric | Baseline | Current | Change |
|---|---:|---:|---:|
| TLS handshake | 4.1155 ms | 3.9455 ms | -4.1% latency, +4.3% rate |
| verifier wall time | 8.3290 ms | 8.1175 ms | -2.5% |
| verifier thread CPU | 2.126650 ms | 1.877999 ms | -11.7% |

Current thread-CPU time was lower in five of six alternating cycles. Individual
process MAD values were roughly 7% to 18%, which is why no single pair was used.

Per-cycle handshake medians in microseconds were:

```text
baseline: 4269 3673 3980 4251 4580 3951
current:  3567 4015 4242 3876 3802 4175
```

Per-cycle thread-CPU medians in milliseconds were:

```text
baseline: 2.205693 1.823771 1.897923 2.177078 2.249613 2.076231
current:  1.673849 1.731463 2.046616 1.770846 2.075693 1.985154
```

## Discarded performance samples

- A later full baseline/current pair began at a 1.5 GHz cap and ended at 1.4 GHz.
- A hash-only pair at 1.4 GHz showed substantial motion in unchanged SHA-256 and
  high variation, so it cannot attribute a SHA-512 change.
- A reverse hash attempt began after the thermal cap fell to 1.2 GHz and produced
  no accepted rows.
- At final verification, CPU 7 reported `scaling_max_freq=1200000` and the battery
  reading was 41.1 C; benchmarks were not rerun under that changed policy.

These samples are intentionally excluded from performance claims.

## Issue matrix

| Issue | Root cause | Implementation | Test | Benchmark effect | Remaining risk |
|---|---|---|---|---|---|
| AES CTR clobbered `d8` | fourth block used nonvolatile `v8` | moved block to `v31` | pre-fix fails, final ABI passes | neutral | none identified |
| GHASH clobbered `d8` | reduction scratch used `v8` | moved scratch to `v16` | pre-fix fails, final ABI passes | neutral | none identified |
| ChaCha clobbered `d8-d15` | state occupied nonvolatile vectors | caller-saved register allocation | pre-fix fails 16 checks, final passes | frame 272 to 0 bytes | one-lane path remains slow |
| first-use dispatch race risk | independent lazy state and coupled caps | one immutable `pthread_once` mask set | concurrent test plus TSan | no isolated claim | environment controls are process-start controls |
| AES block CE unused in GCM | C was called for H and tag mask | hardware dispatch wrapper | block differential and AEAD KAT | included in AES-GCM gain | AES-192 intentionally unsupported |
| GHASH call and setup overhead | one-block calls rebuilt constants | H powers, four-block and coarse entry | randomized AAD/CT differential | +164% raw at large sizes | device coverage is one SoC family |
| ciphertext reread on seal | CTR and GHASH were separate | fused AES-CTR/store/GHASH | fused differential, guards, in-place | about +10% at 4 KiB to 1 MiB | open deliberately remains two-pass |
| no Poly1305 A64 kernel | compiler emitted scalar C loop | 3x44 integer assembly | KAT plus full/partial differential | +2.5% to +6.2% | modest gain; no NEON variant |
| SHA-512 80-word schedule | 640-byte local schedule | rolling 16 words | SHA-384/512 tests and sanitizers | frame 720 to 224 bytes | no accepted speed claim |
| volatile byte wipe | safe but prevents efficient stores | `memset` plus compiler barrier | generated-code inspection | not benchmarked | relies on documented GCC/Clang barrier idiom |
| forced missing backend ambiguity | no explicit diagnostic | missing-force mask and error text | dispatch-only failures | N/A | production API still falls back safely |
| invalid-tag output policy | optimization could expose plaintext | authenticate before decrypt retained | output sentinel tests | open not fused | intentional extra ciphertext pass |

## Constant-time and security review

The modified assembly contains no conditional branch on key, plaintext,
ciphertext, hash accumulator, Poly1305 limbs, or X25519 scalar bits. Branches are
on public length/block counts, fixed round counts, or public AES round count.
Loads use fixed context offsets or linearly advancing public pointers; there are
no secret-indexed tables in the assembly. Tail loops stop at public lengths and
copy only the bytes promised by their contracts.

All stack adjustments are multiples of 16. Every return restores the frame it
created. The fused routine restores `d8` through `d15`; Poly1305 restores `x19`
and `x20`; all other production assembly entries avoid nonvolatile registers.
No red zone is assumed.

Counter policy is explicit: ChaCha20 rejects requests that exceed the remaining
32-bit counter space, and GCM rejects plaintext that would exceed its 32-bit
counter bound. Open never publishes accepted plaintext before a successful tag
comparison.

## Exact blockers and smallest next actions

### AArch64 QEMU

Command and output:

```text
$ qemu-aarch64 --version
qemu-aarch64: not found
```

Environmental requirement: a QEMU user-mode AArch64 package and a compatible
Android/Linux loader. Smallest action: install `qemu-user` in WSL and rerun the
ABI/differential binaries. Real AArch64 API 24 and API 33 runs already pass.

### Native Termux compiler

Command and output:

```text
$ run-as com.termux /data/data/com.termux/files/usr/bin/bash -lc \
    'clang --version; make --version'
clang: command not found
make: command not found
```

Environmental requirement: Termux `clang` and `make`. Smallest action, with user
approval, is `pkg install clang make`, followed by `make strict-test`. The same
source has already passed NDK AArch64 builds and real-device execution; this is
not a claim of a native Termux compile.

### X25519 AArch64 assembly

Command and output:

```text
$ QN_FORCE_X25519_ASM=1 ./bench_crypto --dispatch-only
crypto backend control error: QN_FORCE_X25519_ASM requested, but no X25519 assembly backend is compiled
```

No compatible audited AArch64 implementation was available for adoption. The
official BoringSSL tree inspected for comparison exposes an
[ARM32 X25519 assembly file](https://boringssl.googlesource.com/boringssl/%2B/c63fadbde60a2224c22189d14c4001bbd2a3a629/src/crypto/curve25519/asm/x25519-asm-arm.S),
while its
[AArch64 source list](https://boringssl.googlesource.com/boringssl/%2B/fa3fbda07bbf70925453d6a3c25a7aa455aa1cef/crypto/CMakeLists.txt)
does not provide the required drop-in backend. The constant-shape C
implementation therefore remains active. Smallest safe next action: source and
review a license-compatible audited AArch64 implementation, or separately
authorize a novel implementation plus independent review.

### SHA-512 CE assembly

Command and output:

```text
$ QN_FORCE_SHA512_CE=1 ./bench_crypto --dispatch-only
crypto backend control error: QN_FORCE_SHA512_CE requested, but no SHA-512 CE backend is compiled
```

The phone advertises SHA-512 instructions, but no callable backend is compiled.
SHA-384/512 remain correct through the rolling-schedule C path. Smallest action:
adopt or independently review a license-compatible SHA-512 CE compression entry,
then run the existing backend-control, KAT, differential, ABI, and TLS benchmarks.

## Reproduction commands

Host validation:

```sh
make CC=gcc strict-test
make CC=gcc sanitize-test
make CC=gcc tsan-test
```

Device correctness after an API 24 NDK build:

```sh
adb push build-arm64-api24-final/test_crypto /data/local/tmp/qn-crypto/test_crypto
adb push build-arm64-api24-final/test_crypto_abi /data/local/tmp/qn-crypto/test_crypto_abi
adb push build-arm64-api24-final/test_crypto_diff /data/local/tmp/qn-crypto/test_crypto_diff
adb shell 'chmod 755 /data/local/tmp/qn-crypto/*'
adb shell 'cd /data/local/tmp/qn-crypto && ./test_crypto'
adb shell 'cd /data/local/tmp/qn-crypto && ./test_crypto_abi'
adb shell 'cd /data/local/tmp/qn-crypto && ./test_crypto_diff'
adb shell 'cd /data/local/tmp/qn-crypto && QN_NO_ASM=1 ./test_crypto_diff'
```

Microbenchmark isolation:

```sh
QN_BENCH_ONLY=raw ./bench_crypto
QN_BENCH_ONLY=aead ./bench_crypto
QN_DISABLE_AES_GCM_FUSED=1 QN_BENCH_ONLY=aead ./bench_crypto
QN_DISABLE_POLY1305_ASM=1 QN_BENCH_ONLY=poly1305 ./bench_crypto
QN_BENCH_ONLY=poly1305 ./bench_crypto
QN_BENCH_ONLY=hashes ./bench_crypto
QN_BENCH_ONLY=x25519 ./bench_crypto
```

TLS verifier fixture:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=bench.qanat.test' -keyout bench.key -out bench.crt
python3 tests/tls_bench_server.py --cert bench.crt --key bench.key --port 9443
adb reverse tcp:9443 tcp:9443
adb shell 'taskset 80 /data/local/tmp/qn-crypto/bench_tls_verify 127.0.0.1 9443 31'
adb reverse --remove tcp:9443
```

## Modified files and purpose

| File | Purpose |
|---|---|
| `Makefile` | add Poly1305 assembly, ABI/differential tests, and both benchmarks |
| `include/qanat/crypto.h` | store H powers and expose the separate PMULL capability |
| `src/crypto/aead.c` | validate public pointers and propagate AES-GCM length failures |
| `src/crypto/aead_impl.h` | declare test-only C reference hooks and bool seal result |
| `src/crypto/aesgcm.c` | connect AES CE, H powers, coarse/fused GCM, and length policy |
| `src/crypto/chacha.c` | dispatch 4x/1x paths and reject counter exhaustion |
| `src/crypto/poly1305.c` | dispatch full blocks to AArch64 and expose the C reference |
| `src/crypto/rand.c` | make wipe efficient and non-elidable |
| `src/crypto/sha2.c` | add SHA-256 reference hook and rolling SHA-512 schedule |
| `src/crypto/arm64/backend.h` | define backend identities and control API |
| `src/crypto/arm64/cpufeat.c` | thread-safe HWCAP detection and force/disable controls |
| `src/crypto/arm64/aes_ce.S` | fix AES ABI and add fused AES-CTR/GHASH |
| `src/crypto/arm64/ghash_ce.S` | fix ABI and add H-power/coarse PMULL GHASH |
| `src/crypto/arm64/chacha_neon.S` | remove 4x spills and add a tested 1x path |
| `src/crypto/arm64/poly1305.S` | add constant-shape 3x44 full-block kernel |
| `tests/arm64/abi_probe.S` | snapshot AAPCS64 nonvolatile registers and SP |
| `tests/test_crypto_abi.c` | exercise every assembly entry and every return shape |
| `tests/test_crypto_diff.c` | compare assembly with C across lengths and alignments |
| `tests/test_crypto.c` | race first dispatch and verify invalid-tag output policy |
| `tests/bench_crypto.c` | calibrated microbenchmarks and dispatch diagnostics |
| `tests/bench_tls_verify.c` | full verifier wall/CPU/handshake benchmark |
| `tests/tls_bench_server.py` | deterministic local TLS 1.3 HTTP/1.1 fixture |
| `docs/CRYPTO-AARCH64-DISASSEMBLY-2026-08-11.md` | annotated generated-code review |

## Independent review, 2026-08-11

A second pass over the backends, run against real hardware rather than against
the source. Findings below are additions; nothing in the original work was
contradicted.

### ABI discipline verified independently

The nonvolatile-register claims hold. `qn_aes_gcm_encrypt_ghash_ce` is the only
entry that touches `v8`–`v15`, and it saves and restores `d8`–`d15` around the
whole body. `ghash_ce.S`, `chacha_neon.S` and `sha256_ce.S` do not reference
those registers at all, so they need no frame. `poly1305.S` allocates before it
stores `x19`/`x20` and takes its zero-block exit ahead of the prologue, so the
early path never moves `sp`. No entry uses `x18`, which Android reserves as the
platform register. Every `.S` carries `.note.GNU-stack`, and the linked binary
maps `GNU_STACK` as `RW`.

### Cross-backend differential on hardware

`tests/diff_backends.c` folds a matrix into one FNV-1a checksum: three AEADs
across 39 plaintext lengths and 10 AAD lengths, each with a round trip and with
tag, ciphertext and AAD corruption that must fail to open, plus SHA-256 over the
same lengths re-hashed at several split points. Running the same binary twice
on the handset:

```text
$ ./diff_backends
backends: aes-ce=1 ghash-pmull=1 aes-gcm-fused=1 sha256-ce=1 chacha-neon=1 \
          poly1305-asm=1 x25519-asm=0 sha512-ce=0
fold=455ef5e0e92ad169

$ QN_NO_ASM=1 ./diff_backends
backends: aes-ce=0 ghash-pmull=0 aes-gcm-fused=0 sha256-ce=0 chacha-neon=0 \
          poly1305-asm=0 x25519-asm=0 sha512-ce=0
fold=455ef5e0e92ad169
```

The fold is FNV-1a computed in the test, not a library hash, so a broken
SHA-256 cannot hide inside the comparison. The backend line is printed so a run
cannot silently prove nothing by having taken the C path in both directions.

### Branch protection was missing

The device is a Cortex-A715 (`mt6886`) whose `/proc/cpuinfo` advertises `bti`,
`paca` and `pacg`, yet the binary carried no
`GNU_PROPERTY_AARCH64_FEATURE_1_AND` note, so neither BTI nor PAC was active.
The linker ANDs that property across inputs: unmarked assembly would have
dropped the feature for the whole image even if the C had been compiled for it.

`src/crypto/arm64/abi.h` now supplies `QN_BTI_C` and `QN_GNU_PROPERTY`. Every
`.S` emits the note once and puts a landing pad on each `.global` entry.
`bti c` is written as `hint #34`, which older cores decode as a NOP, so the
objects still run on pre-8.5 hardware. The Makefile probes for
`-mbranch-protection=standard` and adds it on AArch64 targets so the C objects
carry the same property.

```text
$ llvm-readelf -n build-android/qanat        # before
(no properties)
$ llvm-readelf -n build-android/qanat-bti    # after
Properties:    aarch64 feature: BTI, PAC
```

On the handset the protected build passes `test_crypto`, reproduces
`fold=455ef5e0e92ad169` in both backend modes, and runs.

### The handset is too noisy for a fine-grained speed claim

Branch protection could not be measured. `aes-128-ctr-ce` at 1 MiB across
runs:

| Build | Order | MiB/s | Reported variance |
|---|---|---|---|
| plain | first | 3335.3 | 8.6% |
| BTI+PAC | second | 3230.0 | 9.2% |
| BTI+PAC | first, after cooldown | 3844.9 | 1.4% |
| plain | first | 2865.8 | 41.3% |
| BTI+PAC | second | 3649.9 | 3.8% |

The protected build produced both the highest and the second-highest figure,
and one unprotected run reported 41% variance with `poly1305` at 89%. Run
order and thermal state dominate by far more than any effect being looked for,
so the honest statement is that no difference is measurable here, not that
there is none. Theory agrees: `bti c` is one instruction per entry and these
kernels spend their time in loops that do not return.

The same caution applies to the benchmark tables earlier in this document. Any
figure taken as a single run on this handset carries that variance unless the
run order was controlled and the device was cool.

### Left alone deliberately

`sha512` appears in the device's feature list, so a SHA-512 CE kernel is
implementable. It stays unwritten for the reason already recorded: SHA-384 sits
on a rarely-taken path, and the measured gain would not justify hand-written
assembly that the differential harness would then have to cover.

### SHA-512 on the ARMv8.2 SHA-512 instructions

The device advertises `sha512`, and nothing used it. SHA-384 and SHA-512 ran the
scalar C compression at about 247 MiB/s against 1400 or more for SHA-256 on its
CE kernel. Unlike the X25519 gap, which is a matter of compiler scheduling
against `__int128` limbs, this one is a hardware instruction the C cannot reach
at all, which is where hand-written assembly earns its place.

`src/crypto/arm64/sha512_ce.S` implements `qn_sha512_blocks_ce` on `sha512h`,
`sha512h2`, `sha512su0` and `sha512su1`. Five vector registers rotate the eight
state words, eight hold the sixteen message words, and the round constants sit
four at a time in `v24`–`v27`.

**Nothing in the file was transcribed by hand.** `scripts/gen_sha512_ce.py`
reads `K512` out of `src/crypto/sha2.c`, spot-checks the first and last constant
against FIPS 180-4, and derives the round schedule from its own recurrence: the
state permutation repeats every five round pairs and the message taps every
eight. Regenerating the file after any change to the constants is one command.
This is the same discipline the HPACK Huffman table used, and for the same
reason: a hand-copied table passes the vectors you remember and fails the ones
you do not.

Dispatch is the existing backend mask. `HWCAP_SHA512` now maps to
`QN_BACKEND_SHA512_CE`, `sha512_block` routes through it, and the scalar
compression is kept as `sha512_block_c`.

#### Correctness

`test_crypto` passes on the handset with the kernel enabled and with
`QN_DISABLE_SHA512_CE=1`. `tests/diff_backends.c` was extended to cover SHA-384
and SHA-512 across 39 lengths, each re-hashed at several split points so the
128-byte block carry is exercised, and folds them into the same checksum as the
AEADs. Three configurations agree exactly:

```text
all backends      backends: ... sha512-ce=1     fold=0e67b5ee945c5e69
QN_NO_ASM=1       backends: ... sha512-ce=0     fold=0e67b5ee945c5e69
QN_DISABLE_SHA512_CE=1                          fold=0e67b5ee945c5e69
```

#### Measurement, and what is not yet measured

The first working version reloaded the round constant inside every round pair.
Measured on the handset with an A-B-A design, so the middle reading cannot be a
thermal artefact:

| Run | Backend | sha-384 | sha-512 | var |
|---|---|---|---|---|
| A1 | CE | 723.6 MiB/s | 724.6 MiB/s | 1.6% / 0.6% |
| B | scalar C | 246.5 MiB/s | 246.7 MiB/s | 0.3% / 0.6% |
| A2 | CE | 722.4 MiB/s | 721.7 MiB/s | 0.6% |

A1 and A2 agree within 0.2%, so B is trustworthy: **2.93x**.

The committed kernel then moved the constants into `v24`–`v27`, reloaded four at
a time, which removes thirty loads per block. That variant is measured below.

Remaining headroom, unquantified: the kernel is likely latency-bound on the
`sha512h` to `sha512h2` dependency chain rather than on loads, so the constant
caching may show little. SHA is serial across blocks, so there is no multi-block
interleaving to exploit.

#### Re-measured after reconnecting the handset

The committed constant-caching kernel was measured once the device came back.
Two attempts, A-B-A and A-B-A-B, both noisier than the earlier session:

| Run | Backend | sha-512 MiB/s | var |
|---|---|---|---|
| A1 | CE | 647.5 | 23.6% |
| B | scalar C | 243.8 | 37.5% |
| A2 | CE | 728.3 | 6.2% |
| B2 | scalar C | 238.4 | 19.3% |

A1 and A2 disagree by 12%, so no single pair is decisive on its own. The two
scalar readings agree to 2.2% and both sit far below both assembly readings, so
the ratio is bounded rather than pinned: **2.7x to 3.1x**, consistent with the
2.93x measured earlier under quieter conditions.

The question this run existed to answer is settled: the constant-caching kernel
reaches 728.3 MiB/s against the per-round-load variant's 723.6. **The
optimization is neutral within noise.** That matches the prediction that the
kernel is latency-bound on the `sha512h` to `sha512h2` dependency chain rather
than on loads, so removing thirty loads per block buys nothing measurable. The
register version is kept because it is no worse and reads no worse, not because
it was shown to be faster.
