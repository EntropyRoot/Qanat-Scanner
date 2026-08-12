# P0 remediation, 2026-08-12

Baseline for this work: branch `qn2-remediation` at `c24e92a`, working tree
clean, every gate green before a line was edited.

| Gate | Baseline result |
| --- | --- |
| `make CC=gcc BUILD=build-base0 LTO= test` | 11/11 suites `ok` |
| `make CC=gcc strict` | application built, no warning |
| `make CC=gcc strict-test` | 11/11 suites `ok` |
| `make CC=gcc analyze` | linked, 0 diagnostics |
| `make CC=gcc sanitize-test` | 11/11 ASan+UBSan suites `ok` |
| `make CC=gcc tsan-test` | 11/11 TSan suites `ok` |
| `make CC=gcc tls-test` | OpenSSL matrix `ok` |
| `make CC=gcc menu-test` | `menu PTY tests: ok` |
| `make CC=gcc fuzz-smoke` | 6 x 20,000 inputs `ok` |
| `sh scripts/check_first_audit.sh` | `27 ok, 0 failed` |

Toolchain: WSL2 Ubuntu, GCC 15.2.0, GNU Make 4.4.1, 12 CPUs. No Clang, no
`qemu-aarch64` and no `aarch64-linux-gnu-gcc` in WSL; AArch64 coverage still has
to come from the NDK cross-build and the handset.

## Bug-by-bug

### P0-1 — a deliberate stop was reported as work never attempted

**Reproduce.** `tests/test_engine.c::test_stop_condition_is_a_success` builds the
exact shape `--limit` uses: a task that declines further work while indices
remain in the domain. Against `c24e92a`:

```
  stop-condition: reserved 64 indices but claimed 63
FAIL tests/test_engine.c:671: sn.claimed == reserved
  stop-condition: 23 of 63 reported never attempted
FAIL tests/test_engine.c:678: sn.unattempted == 0u
engine tests: 2 failure(s)
```

**Root cause.** Two defects behind one boolean.

`worker_fill()` drew an index with `claim_next()`, which advances `claim_cur`,
and only counted it as `claimed` *after* `t->next()` returned true. When
`next()` declined, the function returned immediately, so that one index was counted
nowhere: `worker_retire()` accounts the chunk tail from `claim_cur`, which had
already moved past it. One index per worker vanished from the ledger.

Separately, `bool next()` could not say *why* it declined. Exhaustion, a
satisfied `--limit`, a cancel and an internal fault were the same value. The
engine treated all four as "drained", `worker_retire()` charged the unused chunk
tail to `unattempted`, and `main.c` turned any `unattempted != 0` into exit code
4 plus "candidates were never attempted". A `--limit` that did exactly what it
was asked exited 4.

**Fix.** `qn_task.next` now returns `qn_task_next`: `QN_TASK_JOB`,
`QN_TASK_EXHAUSTED`, `QN_TASK_STOP_CONDITION`, `QN_TASK_CANCELLED`,
`QN_TASK_FATAL`. The index is counted as `claimed` the moment it is drawn, so
nothing can fall between the draw and the decision. Accounting became a
three-way partition, `claimed == completed + skipped + unattempted`, where
`skipped` is work deliberately not run and `unattempted` is work still owed.
A stop condition settles the engine at `QN_ENGINE_STOPPED`, and the chunk tail
after a deliberate stop is `skipped`, not `unattempted`.

`qn_run_outcome` (`SUCCESS`, `CANCELLED`, `INCOMPLETE`, `FAILED`) with
`qn_run_exit_code()` (0, 130, 4, 3) is now the single exit-code contract.
`main.c` and `src/ui/app.c` both derive their exit code from it;
`qn_engine_finalize()` fills `finalization.outcome` so neither front end can
invent its own rule. `cf_next_sweep` reports `QN_TASK_STOP_CONDITION` when the
retention target is met and `QN_TASK_FATAL` when the scheduler picks an address
the range set cannot produce, which used to be silently skipped.

**Evidence.**

```
  run build-p01/test_engine
  tokens: 384 claimed, 384 issued, 118 launch retries
engine tests: ok
  run build-p01/test_task_cf
task tests: ok
```

`tests/test_task_cf.c::test_limit_reports_a_stop_condition` pins the task-level
contract: with `cf_limit = 5` and a range set far larger, `next()` returns
`QN_TASK_JOB` before the limit and `QN_TASK_STOP_CONDITION` after it, never
`QN_TASK_EXHAUSTED`.

**Test oracle corrected, not deleted.** `tests/test_discover.c` compared
`hd_next_tcp()` against a boolean. `QN_TASK_JOB` is 0, so the old assertions
inverted. They now assert the enum values they mean.

### P0-2 — an HTTP/2 trailer destroyed a verified edge

**Reproduce.** A probe built against `c24e92a`, feeding a 200 response head, a
`colo=FRA` trace body, and then a legal `grpc-status: 0` trailer in its own read:

```
after head+body: status=200 edge_verified=1 colo=FRA
trailer event: flags=0x05 status=0
after trailer:  status=0 edge_verified=0 colo=FRA
```

**Root cause.** `complete_hblock()` set `QN_HTTP_FACT_HEADERS` on every completed
header block, trailers included. Trailers legally carry no `:status`, so the
event's status was 0. `qn_observation_apply_http()` then did

```c
if (event->flags & QN_HTTP_FACT_HEADERS) {
    observation->http.final_headers = true;
    observation->http.status = event->status;
}
```

overwriting 200 with 0, and `qn_edge_policy_apply()` requires `status == 200`, so
`edge.verified` flipped back to false. A well-behaved endpoint that sent trailers
was demoted. HTTP/1 was already correct here — its trailer path ends in
`complete()`, which restates the real status — so the two protocols disagreed on
policy, which is exactly what the canonical observation model exists to prevent.

**Fix.** Informational, final and trailing header blocks are now three distinct
facts. `QN_HTTP_FACT_TRAILERS` was added; `complete_hblock()` emits it instead of
`QN_HTTP_FACT_HEADERS` for a trailing block. `qn_observation.http.trailers`
records it. `qn_observation_apply_http()` only takes a status from the *first*
final head, so no later block can rewrite it. HTTP/1 emits the same
`QN_HTTP_FACT_TRAILERS` fact when a chunked body ends with real trailer fields —
and not when only the terminating CRLF arrives — so both protocols now reach the
classifier through one vocabulary.

**Evidence.** Same probe after the fix:

```
after head+body: status=200 edge_verified=1 colo=FRA
trailer event: flags=0x104 status=0
after trailer:  status=200 edge_verified=1 colo=FRA
```

`0x104` is `QN_HTTP_FACT_TRAILERS | QN_HTTP_FACT_DONE`, with no
`QN_HTTP_FACT_HEADERS`. Pinned by
`tests/test_core.c::test_http2_trailers_do_not_overwrite_the_status`.

### P0-6 — changing compiler flags did not rebuild anything

**Reproduce.** Three builds into one `BUILD` directory, each asking for
different flags, against `c24e92a`:

```
--- pass 1: -O0, assertions live ---
f70dd4cdab91cc8b1a9dc716a6b0864f  src/net/engine.o
--- pass 2: same BUILD dir, -O3 -DNDEBUG ---
f70dd4cdab91cc8b1a9dc716a6b0864f  src/net/engine.o
--- pass 3: same BUILD dir, -fsanitize=address ---
f70dd4cdab91cc8b1a9dc716a6b0864f  src/net/engine.o
--- does the linked binary actually contain ASan? ---
asan: ABSENT (pass 3 produced a non-sanitized binary)
```

Make did nothing in passes 2 and 3. Identical object, identical binary size. The
"sanitized" build contained no sanitizer at all.

**Root cause.** `$(BUILD)/%.o: %.c` depends only on sources and headers. An
object file records nothing about the compiler, target or flags that produced
it, so any configuration change that leaves the sources alone reuses stale
output. The shipped gates each use their own `BUILD` directory, which hides the
defect; any `BUILD=` override, `CC=` change, `NATIVE=1`, `LTO=` change, or an
edited `CFLAGS` hits it. A gate that silently reports a non-sanitized binary as
having passed the sanitizer is a false green.

**Fix.** `CONFIG_SIG` captures compiler, compiler version, `-dumpmachine`
target, target and host architecture, `NATIVE`, LTO mode, version, `CFLAGS` and
`LDFLAGS`. `$(BUILD)/.build-config` holds it and is rewritten only when it
actually changes, so it is not itself a rebuild trigger. Every object, every
test binary and both benches depend on it. `BUILD_FINGERPRINT` is the first 16
hex digits of its hash; it is compiled in as `QN_BUILD_FINGERPRINT`, printed by
the build and reported by `qanat --version`, so an artifact names the
configuration that produced it. `make config-fingerprint` prints the hash and
the full signature.

The version literal also stopped being duplicated: `include/qanat/qanat.h` is
the only place it is written and the Makefile reads it from there.

**Evidence.** Same reproducer after the fix:

```
--- pass 1: -O0, assertions live ---
  config 725711f5afea87c3 (gcc, lto=off, x86_64)
19132bd1d3f5004c2d7182eb9ba3f490  src/net/engine.o
--- pass 2: same BUILD dir, -O3 -DNDEBUG ---
  config a6976e641b0a16be (gcc, lto=off, x86_64)
89c9dd98d91ee3a896ece21c4d62a266  src/net/engine.o
--- pass 3: same BUILD dir, -fsanitize=address ---
  config 4e9daa09d3fef1a3 (gcc, lto=off, x86_64)
5ad003512ffc594cb79886e0183f5973  src/net/engine.o
--- does the linked binary actually contain ASan? ---
asan: PRESENT
```

`scripts/check_build_config.sh` keeps it honest:

```
  ok    optimisation level change recompiles
  ok    the rebuilt object really used the new flags
  ok    preprocessor define change recompiles
  ok    sanitizer change recompiles
  ok    the sanitized object contains ASan instrumentation
  ok    an unchanged configuration does not rebuild
build-config checks: 6 ok, 0 failed
```

The last check matters as much as the others: a stamp that always fires would
trade a false green for a permanent full rebuild.

## P0-3 — historical pre-fix reproduction (fixed in the continuation below)

This is the preserved before-fix evidence. The current implementation and its
regression evidence are recorded in the continuation below.

`qn_input_poll()` in `src/ui/term.c` reads up to 32 bytes and returns **exactly
one key**, discarding the rest of the buffer on every path. A probe over a real
PTY in raw mode, against this tree:

```
case                          in  out
  burst "abcdefgh"             bytes= 8 keys=1 got="a"
  paste-like 20 chars          bytes=20 keys=1 got="q"
  two arrows in one read       bytes= 6 keys=1 got="<UP>"
  arrow then letter            bytes= 4 keys=1 got="<UP>"
  split escape: ESC alone      bytes= 1 keys=1 got="<ESC>"
  split escape: rest "[A"      bytes= 2 keys=1 got="["
  modified arrow ESC[1;5A      bytes= 6 keys=1 got="<ESC>"
  UTF-8 two-byte é             bytes= 2 keys=1 got="<CHAR>"
  UTF-8 four-byte emoji        bytes= 4 keys=1 got="<CHAR>"
  bracketed paste wrapper      bytes=12 keys=1 got="<ESC>"
```

Every case yields one key no matter how many bytes arrived. Five distinct
defects sit behind that:

1. **Bytes after the first key are dropped.** Fast typing loses characters and a
   paste loses all but its first byte.
2. **A split escape sequence cannot be reassembled.** There is no state between
   calls, so `ESC` arriving alone is reported as the ESC key and the `[A` that
   follows becomes a literal `[` with the `A` discarded.
3. **Parameterised CSI is not parsed.** `ESC [ 1 ; 5 A` (Ctrl+Up) does not match
   the two hard-coded shapes and degrades to ESC, losing five bytes.
4. **UTF-8 is not decoded.** `out->ch = b[0]` takes one byte, so any non-ASCII
   character becomes mojibake and its continuation bytes vanish.
5. **Bracketed paste is not recognised.** `ESC [ 200 ~` is read as ESC and the
   pasted payload is thrown away.

The fix is the rewrite the task calls for: a persistent input ring plus an
incremental state machine over GROUND, ESC, CSI, SS3, UTF8 and BRACKETED_PASTE,
where a `read()` appends to the ring and the decoder drains complete keys from
it, keeping any partial sequence for the next call. The probe above becomes the
PTY test: burst, split escape, standalone ESC, paste, UTF-8 and malformed input.

## Contract changes callers must know about

| Symbol | Change |
| --- | --- |
| `qn_task.next` | returns `qn_task_next`, not `bool`. `QN_TASK_JOB` is 0, so old boolean tests invert |
| `qn_engine_status` | gained `QN_ENGINE_STOPPED`, printed as `stop-condition-met` |
| `qn_wstats` / `qn_engine_snapshot` | gained `skipped`; the accounting identity is now `claimed == completed + skipped + unattempted` |
| `qn_engine_finalization` | gained `outcome` |
| `qn_run_outcome`, `qn_run_exit_code`, `qn_run_outcome_worst` | new; the single exit-code contract for both front ends |
| `QN_HTTP_FACT_TRAILERS` | new fact; `qn_observation.http.trailers` records it |
| `QN_BUILD_FINGERPRINT` | new; defaults to `"unrecorded"` when the build does not set it |

## Gates after the change

```
make CC=gcc BUILD=build-p01 LTO= test    11/11 ok
make CC=gcc strict                       built, config 376041983c73cab1
make CC=gcc strict-test                  11/11 ok
make CC=gcc analyze                      linked, 0 diagnostics
make CC=gcc tls-test                     ok
make CC=gcc menu-test                    menu PTY tests: ok
make CC=gcc fuzz-smoke                   6 x 20,000 inputs ok
sh scripts/check_first_audit.sh          27 ok, 0 failed
CC=gcc sh scripts/check_build_config.sh  6 ok, 0 failed
git diff --check                         clean
```

## Residual risk

- The engine reports `QN_ENGINE_CANCELLED` in preference to `QN_ENGINE_STOPPED`
  when an operator cancel and a stop condition land together. That is
  deliberate — an explicit cancel is a fact the operator should see — but it
  means a stop condition reached in the same instant as `q` is reported as a
  cancel.
- RFC 9113 requires a trailing header block to carry END_STREAM. That is not
  enforced; a trailer without it is still accepted as a trailer. Adding the
  rejection is correct by the RFC but is a new refusal path, and this project
  has twice regressed by tightening a parser without device evidence.
- `QN_TASK_FATAL` from `cf_next_sweep` is reachable only if the bandit and the
  range set disagree, which should be impossible. It has no test, because
  constructing the inconsistency means corrupting one of them.
- `scripts/check_build_config.sh` uses `md5sum`, `stat` and `nm`. On a host
  without them it fails rather than skipping.

## Current remediation continuation, 2026-08-12

This section supersedes historical status labels above. The dirty working tree
was preserved throughout; no reset, clean, restore, checkout, commit, or push
was performed. At the user's request, no live scan, loopback peer, socket-based
engine suite, TLS loopback, or other network test was run in this continuation.
`offline-test` is an explicit allowlist. Its engine and verifier failure suites
compile with fake transports that cannot open a network socket.

### Bug-by-bug closure matrix

| Defect | Before-fix reproducer | Root cause | Contract-level fix | Regression evidence |
| --- | --- | --- | --- | --- |
| TUI input lost burst bytes and split sequences | `docs/evidence/probe_p03.c` produced one key for 8-byte typing, 20-byte paste, two arrows, UTF-8, and bracketed paste | `qn_input_poll()` read a transient 32-byte buffer, returned one event, and discarded the tail; it retained no decoder state | persistent bounded byte ring plus incremental GROUND/ESC/CSI/SS3/UTF8/BRACKETED_PASTE state machine; standalone ESC has a bounded ambiguity timeout | `tests/test_input.c`: burst, split ESC, UTF-8/malformed, paste; `tests/test_menu_pty.py`: split CSI writes, burst arrows, bracketed-paste numbers, resize: `input tests: ok`, `menu PTY tests: ok` |
| ClientHello advertised a shape independently of implemented capability | reverting the capability gate makes `test_hello_wire_contract`, `test_hrr_capability_path`, and `test_tls13_cert_verify_capability` accept unsupported or incoherent paths | profile metadata, ClientHello serialization, HRR handling, and verifier capability were separate policies | `qn_tls_capability` is the single advertisement gate; profiles are exact, capability-constrained, or rejected; cipher/group/key-share/HRR/signature/ALPN paths must all be implemented | `tests/test_tls.c`: no duplicate extensions, exact wire contract, HRR path, ServerHello validation, all split points: `tls tests: ok` |
| preview, verifier, export, HTTP/1 and HTTP/2 could resolve random profiles separately | old random APIs could be called without a resolved persona; `test_random_requires_instance` and `test_profile_instance_wire_identity` pin the regression | callers passed a mutable profile name and seed to several builders, so each layer could make a different random/GREASE choice | one immutable versioned `qn_profile_instance` is instantiated once from profile/seed/SNI/policy and consumed by all wire, preview, verifier, and export paths | `tests/test_tls.c::test_profile_instance_wire_identity`; CLI regression verifies requested `right=random` and reports `right_resolved` separately |
| verifier partial/fatal startup could be reported as success or overwrite output | fake allocation, epoll, socket, read and short-write faults exercise every startup boundary; `QN_VERIFY_PARTIAL` has an explicit outcome assertion | verifier state was not mapped through the run-wide outcome contract, and a non-complete batch could fall into completion handling | `qn_verify_run_outcome()` maps only COMPLETE to success; PARTIAL/CANCELLED/INFRA map to incomplete/cancelled/failed; caller output commits only after successful startup | `tests/test_verify_faults.c`: `verify fault tests: ok`; main and TUI consume the same mapping |
| engine thread/socket failure and stop boundaries could produce empty success or broken accounting | fault injection covers thread create, epoll fallback, socket exhaustion and every stop point 0..129 across 64/128 claim boundaries | lifecycle errors and task exhaustion shared ambiguous states; reserved claim tails were not a first-class partition | typed engine finalization; successful stop is `QN_ENGINE_STOPPED`; invariant is `claimed == completed + skipped + unattempted`; local terminal failure forces `QN_RUN_FAILED` | `tests/test_engine_faults.c`: model and injected faults: `engine fault tests: ok` |
| range input could mix two file generations or accept a short/truncated snapshot | `tests/test_core.c::test_cidr_snapshot_loader` injects short read, truncate, replacement, metadata change, embedded NUL and overflow | count and parse passes observed the path independently and trusted size/metadata without binding all bytes to one opened object | one exact bounded read from one descriptor, checked allocation arithmetic, pre/post metadata identity, EOF/short-read validation, SHA-256 digest, then normalization | `core tests: ok`; overlap case normalizes 3 prefixes/10 input addresses to 1 prefix/8 unique addresses with 2 duplicates removed |
| renderer committed a model the terminal had not fully received | `tests/test_screen.c::test_flush_commits_only_after_complete_write` injects a short write | the front model advanced before the complete frame write, so a later render believed missing bytes were already visible | frame construction and write are transactional; front commits only after full short-write-aware flush; too-small dimensions remain truthful; all exits restore termios/screen/cursor/signals | `screen tests: ok`; PTY resize while Scan Plan is open: `menu PTY tests: ok` |
| traversal, reachable target, candidate cap, finalists, output count and concurrency were conflated | old `CF_DEFAULT_CAP=16384`, `CF_RTT_FINALISTS=64`, and `cf_limit` made 65,536 candidates or 1,024 finalists unrepresentable | a handful of constants and fields stood in for six independent concepts and no preflight owned cross-field validation | one validated immutable `qn_scan_plan`; five modes, four selection policies, independent pipeline sizes and three concurrency limits, checked products, memory/FD rejection or deterministic Auto adjustment | `tests/test_scan_plan.c` covers >2^32 rounding, full=100%, 65,536 candidates, finalists 257/1,024/all, verify concurrency 32, overflow and low memory: `scan plan tests: ok` |
| full/coverage/budget traversal could omit later ranges or duplicate overlaps | synthetic ranges `10.0.0.0/30`, `10.0.0.2/31`, `10.0.0.4/30` expose both overlap and multiple-range traversal | traversal was not defined over one normalized global domain | every mode consumes a deterministic without-replacement domain; full and coverage 100 normalize to the identical path; budget is attempts, reachable is successful retained candidates | `tests/test_task_cf.c::test_full_and_coverage_100_cover_all_normalized_ranges_once` and all four selection policies: `task tests: ok` |
| large finalist sets implied one giant result array and could be capped by verifier concurrency | old design treated the verifier cohort and simultaneous slots as effectively the same limit | allocation cardinality followed total finalists instead of an explicit bounded batch | finalist total is independent; address/results batches are at most `min(remaining, max(32, 4*verify_concurrency))`; verifier and stability pools are separately bounded | 65,536 candidates with finalists 1,024 and all allocate batch 128 at concurrency 32; `task tests: ok`, `verify fault tests: ok` |
| one lucky minimum RTT could dominate ranking | synthetic candidate with 100 us once and 600,000 us thereafter beat stable candidates under min-only ordering | sweep minima were reused as final evidence and no robust stage or diversity reservation existed | score version 2 uses fresh calibration, median, p90, loss, jitter, confidence, verified edge evidence, optional throughput and deterministic diversity/tie breaks | `tests/test_task_cf.c::test_robust_samples_select_finalists_after_calibration`: `task tests: ok` |
| compatibility `--limit N` accidentally changed candidate capacity | early compatibility translation copied N into both reachable target and candidate capacity | legacy intent and resource capacity were still coupled inside the shim | `--limit` now sets only reachable mode/target and emits a deprecation; Auto capacity grows to contain the target or the resource plan rejects it | `tests/test_scan_plan.c::test_reachable_auto_does_not_conflate_candidate_capacity`; conflicting old/new scope options are rejected by PTY CLI tests |
| fingerprint diff hid a requested random profile behind its resolved persona | `fingerprint diff chrome random --seed 7 --sni example.com` printed `right=safari-ios-17` | display labels reused the resolved profile name | output preserves `right=random` and separately reports `right_resolved=safari-ios-17` | `tests/test_menu_pty.py`: `fingerprint diff preserves requested random profile`; `menu PTY tests: ok` |
| output write/fsync/rename failure could leave an ambiguous success | injected open/write/flush/fsync/rename failures target each commit boundary | exporter success was inferred from an attempted write rather than durable commit | transactional temporary output plus flush, fsync and atomic rename; all failures return the shared typed outcome and preserve the previous destination | `tests/test_export.c::test_output_failures_are_typed_and_transactional`: `export tests: ok` |
| documented Termux install launched an old binary with no menu | on the connected phone, `qanat` printed Usage and exited 2; `~/Qanat` was an old 1.1.0 checkout while the newly cloned code was in `~/Qanat-Scanner`; a separate attempted artifact was zero bytes | documentation cloned `Qanat-Scanner.git` into its implicit `Qanat-Scanner` directory, then ran `cd Qanat`, so an existing stale checkout was built; compiling also did not refresh `$PREFIX/bin/qanat` without `make install` | clone now names the destination explicitly, `cd` matches it, the primary flow installs and flushes the shell command cache, and an existing checkout uses inspected `git pull --ff-only` rather than another clone | `scripts/check_install_docs.sh`: `3 ok, 0 failed`; installed artifact was backed up and replaced atomically; real Android PTY command `qanat` displayed modes 1/2/3/0, entered CDN Settings, returned without a scan, and exited 0 |
| a normal phone terminal was falsely rejected as too small | the connected Termux session reported `stty size` = `31 66`; Scan Plan displayed `Terminal is 66x28; Scan Plan needs at least 72x14` instead of any settings | the renderer required a desktop-style two-column layout even though one scrollable settings column fits safely on a phone | width 72 and above keeps the complete two-panel layout; 48..71 uses a truthful single-panel mobile layout and switches to a compact complete Resource Plan after Review; only a body below 48x12 is rejected | offline PTY resizes through 66x31, 47x10 and back while retaining Candidate/Finalist state; real Android PTY at 66x31 found `Scan Plan` and `Candidate Capacity` with no `Terminal is`; compact Review showed planned/unique, pipeline sizes, concurrency, memory and FDs, then Esc cancelled before probing with exit 130 |

### Resolved scan-plan examples

The following are supported independently; all are parsed and validated before
any scan begins:

```text
qanat scan cf --scan-mode full
qanat scan cf --scan-mode coverage --coverage 10% --selection hybrid
qanat scan cf --scan-mode budget --address-budget 250000
qanat scan cf --scan-mode reachable --reachable-target 4096
qanat scan cf --scan-mode budget --address-budget 100000 --candidate-cap 65536
qanat scan cf --scan-mode coverage --coverage 10% --finalists 256 --verify-concurrency 32
qanat scan cf --scan-mode full --finalists all --output-top all
```

Partial modes export `best-observed-among-scanned-addresses`; only exact full
coverage may describe the complete normalized range set.

### Measured allocation units

The resolver uses the running target's `sizeof` values. The current x86-64 GCC
ABI reported by `qanat doctor` is:

| Unit | Bytes | Bound |
| --- | ---: | --- |
| `cf_record` candidate | 208 | candidate capacity |
| candidate auxiliary arrays | 44 per candidate | candidate capacity |
| candidate fixed arena reserve | 49,152 | one scan |
| `qn_verify_result` batch entry | 660 | verification batch size, not finalist total |
| verifier connection slot | 65,768 | active plus stability pool slots |

AArch64 may pad these types differently; `doctor`, plan validation, TUI and
export all report the target values rather than assuming this table.

### Exact offline validation output

Current x86-64 offline allowlist (`make CC=gcc BUILD=build-offline-now LTO=off offline-test`):

```text
core tests: ok
crypto tests: ok
tls tests: ok
property tests: ok
engine fault tests: ok
verify fault tests: ok
export tests: ok
task tests: ok
outbuf tests: ok
screen tests: ok
discover tests: ok
scan plan tests: ok
scan editor tests: ok
input tests: ok
```

The same 14 suites passed under strict warnings, ASan/UBSan, and TSan.
`make CC=gcc analyze` linked with zero analyzer diagnostics. Six fuzz targets
each reported `20000 random inputs ok` (120,000 total). The offline PTY command
reported `menu PTY tests: ok`. Build-configuration regression reported
`build-config checks: 6 ok, 0 failed`; the first-audit regression reported
`27 ok, 0 failed`.

Current NDK r27.2 strict cross-build used Android API 24, AArch64, LTO off,
`-Werror -Wconversion -Wsign-conversion -mbranch-protection=standard`, and
finished with:

```text
built build-arm64-current/qanat (aarch64, lto=off, config 5191f72c5407395a)
```

Only the offline allowlist was copied to the connected `23090RA98G` (Android
13). From writable cwd `/data/local/tmp/qanat-p0-current`, exact result:

```text
core tests: ok
crypto tests: ok
tls tests: ok
property tests: ok
engine fault tests: ok
verify fault tests: ok
export tests: ok
task tests: ok
outbuf tests: ok
screen tests: ok
discover tests: ok
scan plan tests: ok
scan editor tests: ok
input tests: ok
crypto ABI tests: ok
crypto differential tests: ok
QN_NO_ASM=1: crypto differential: AES CE skipped
QN_NO_ASM=1: crypto differential tests: ok
AArch64 BTI/PAC artifacts: 17/17
```

No network validation is implied by these results. Socket-based suites and
live TLS/HTTP peers remain deliberately not run under the user's boundary.

## Post-update review, 2026-08-12 — one defect found and fixed

The rewritten decoder was reviewed against the pre-rewrite probe. Bursts,
pastes, split escapes, split UTF-8 and bracketed paste were all confirmed
correct. One defect survived, and one earlier suspicion was a measurement
error on my side.

### Fixed: a modified or unknown CSI typed a stray character into the UI

**Reproduce.** Through the pure API, so no read timing is involved:

```
  plain arrow ESC[A                keys= 1 got="<UP>"
  ctrl-up ESC[1;5A                 keys= 1 got="U+FFFD"
  shift-up ESC[1;2A                keys= 1 got="U+FFFD"
  alt-left ESC[1;3D                keys= 1 got="U+FFFD"
  ctrl-right ESC[1;5C              keys= 1 got="U+FFFD"
  modified home ESC[1;5H           keys= 1 got="U+FFFD"
  unknown CSI ESC[999Z             keys= 1 got="U+FFFD"
```

**Root cause.** `decode_csi()` matched the arrow and navigation letters only
when `seq_len == 1`, so any parameterised form missed the table. Every path
that fell through the two switches ended at a shared

```c
out->kind = QN_KEY_CHAR;
out->ch = 0xfffdu;
return true;
```

so a well-framed sequence the decoder simply did not recognise was reported as
printable text. In the Scan Plan editor's Custom numeric fields, pressing
Ctrl+arrow or Shift+arrow typed a replacement character into the field.

**Fix.** Parameters are parsed properly and only the first one names the key;
a modifier says how a key was pressed, never which key it was, so the letter
finals map to their base key regardless of parameters. A well-framed sequence
that is not a key we act on is consumed and emits **nothing**. `U+FFFD` is now
reserved for genuinely malformed input.

**Evidence.**

```
  plain arrow ESC[A                keys= 1 got="<UP>"
  ctrl-up ESC[1;5A                 keys= 1 got="<UP>"
  shift-up ESC[1;2A                keys= 1 got="<UP>"
  alt-left ESC[1;3D                keys= 1 got="<LEFT>"
  ctrl-right ESC[1;5C              keys= 1 got="<RIGHT>"
  modified home ESC[1;5H           keys= 1 got="<HOME>"
  ctrl-up then 'z'                 keys= 2 got="<UP>z"
  unknown CSI ESC[999Z             keys= 0 got=""
```

Pinned by `tests/test_input.c::test_parameterised_csi`, which asserts that no
case yields `QN_KEY_CHAR`, that the ring drains to `QN_INPUT_GROUND`, and that
a character following the sequence still arrives.

### Withdrawn: the reported byte loss after a bracketed paste

An earlier probe appeared to show input lost after `ESC[201~`. That was a race
in the probe, which ended its drain loop while the PTY had not yet delivered
the remaining bytes. A call-by-call trace shows the decoder is correct:

```
  call 1..5: h i x y z   count=10 -> 0   state=BRACKETED_PASTE -> GROUND
  call 6: got=0
```

## Device validation, 2026-08-12

NDK r27c Clang, `aarch64-linux-android30`, `-mbranch-protection=standard`,
`-Werror -Wconversion -Wsign-conversion`. Handset `23090RA98G` (`zircon`),
Android 13, serial `AYCQ8DMVOVTCDMBI`. Binaries were pushed to
`/data/local/tmp/qanat-p0` and hashed on both sides before running.

```
19/19 artifacts: host and device SHA-256 identical
19/19 artifacts: llvm-readelf -n reports aarch64 feature: BTI, PAC

device suites: 18 ok, 0 failed
  core crypto tls props engine engine_faults verify verify_faults export
  task_cf outbuf screen discover scan_plan scan_editor input
  crypto_abi crypto_diff

qanat 1.0.0 (build dd843e79ba6e208f)
```

The scan plan resolves on the handset with a device-derived budget rather than
the host's:

```
  scan-plan  mode=coverage selection=hybrid rank=balanced
  ranges     input=3 normalized=1 unique=512 duplicates=128
  pipeline   planned=64 candidates=65536 finalists=256 output=50 batch=128
  resources  memory=27179776/85811200 bytes working=4096 candidate=16519168 verifier=10656512
  resources  fds=320/32768 scan=256 verify=32 stability=128
```

12.5% of 512 is exactly 64 planned, the `/25` overlap is detected and
deduplicated, and the memory ceiling is 82 MiB on the phone against 256 MiB on
the host. **No public scan was run**; this is plan resolution and offline
suites only.

## Profile support became a measurement, 2026-08-12

`qn_profile_instance.support` was assigned `QN_PROFILE_CAPABILITY_CONSTRAINED`
unconditionally in `qn_profile_instance_init`. `QN_PROFILE_EXACT` was declared
and never assigned anywhere, so a three-state field could only ever report one
state. It happened to be right, which is the worst kind of wrong: it could not
become wrong, and it could not become right either.

**Root cause.** The value was stored on the immutable configuration object,
which is built before any hello exists. "Can we finish everything we offered"
is a property of an emitted extension set, not of a profile table, so there was
nothing at that point to compute it from.

**Fix.** The two questions are now separate functions with separate names.
`qn_tls_hello_capability_check` keeps the first: may we send this at all, and
is there at least one usable group, share and signature scheme.
`qn_tls_capability_assess` answers the second against the hello that was
actually built, and returns a typed report rather than a label:

- `QN_PROFILE_UNSUPPORTED` when the hello cannot even start, including a parse
  that overflowed a bounded list and so proves nothing;
- `QN_PROFILE_CAPABILITY_CONSTRAINED` with the list of gaps;
- `QN_PROFILE_EXACT` when nothing is owed.

A gap carries its kind, codepoint and a static reason. Signature schemes count
only when TLS 1.2 is allowed, because that is where a signature is actually
checked; groups count always, since a 1.2 server picks the curve and 1.3 can
demand one with a retry.

**What it found.** All three personas advertise `secp384r1` and no key exchange
implements it, so a HelloRetryRequest for P-384 cannot be answered. Firefox
additionally offers `secp521r1`, `ffdhe2048` and `ffdhe3072`. This was invisible
while the field was a constant.

```
=== chrome-android-151 ===
support=capability-constrained
capability_gaps=8
capability_gap=extension 0x001B compressed certificate chains are never decompressed
capability_gap=group 0x0018 offered, but no key exchange implements it
capability_gap=signature-scheme 0x0904 offered, but ServerKeyExchange would reject it
...
```

**Tests.** `tests/test_tls.c::test_capability_assessment` proves `EXACT` is
reachable, so the state is a measurement and not a new constant, and pins each
gap kind independently. `test_capability_is_stable_across_grease` pins the
invariant the design rests on: GREASE permutes the extension *order* per
connection but never changes the *set*, so one assessment speaks for every
connection of that profile.

The overflow branch written during this work was removed: the start-up check
already refuses an overflowed parse, so the branch was unreachable. The test
caught it.

**Not changed.** `qn_profile_instance.support` still carries the coarse value
and is still read as an `UNSUPPORTED` guard in three places. The authoritative
answer is the assessment. Collapsing the two is a follow-up.
