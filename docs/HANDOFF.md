# Qanat Implementation Handoff

Section 0 was rewritten 2026-08-12, during the P0 session.
Everything below section 0 is history from earlier sessions and is kept for the
per-issue detail. **Read section 0 first; where it disagrees with a later
section, section 0 is current.**

## 0. Start here

### The current session: P0 remediation, 2026-08-12

Started from `c24e92a`. The working tree is now intentionally dirty and contains
the prior uncommitted work that must not be reset, cleaned, or restored.
`docs/REMEDIATION-P0.md` carries reproductions and evidence;
`docs/SCAN-PLAN.md` is the current architecture and schema migration contract.

**Closed, each with a reproduction that failed first:**

| Item | What it was |
| --- | --- |
| P0-1 | `task.next` was a boolean, so a satisfied `--limit` was indistinguishable from exhaustion, one claimed index per worker vanished from accounting, and a stop that did exactly what was asked exited 4 |
| P0-2 | An HTTP/2 trailer set `QN_HTTP_FACT_HEADERS` with no `:status`, overwriting a real 200 with 0 and erasing `edge.verified` |
| P0-6 | Objects carried no record of their flags, so `make` reused a plain build's objects for a sanitizer build and reported a non-sanitized binary as passing the sanitizer gate |

**Implemented and validated in the current dirty tree:** incremental ring-based
TUI input, transactional rendering,
capability-constrained immutable client profiles, stable range snapshots,
typed engine/ICMP/verifier/output failures, `qn_scan_plan`, all five scan modes,
four selection policies, independent candidate/finalist/output/concurrency
limits, bounded finalist batches, robust staged ranking, Scan Plan TUI/settings,
resource preflight, schema 6 export, `doctor`, and fingerprint list/show/diff.

The network-test boundary for this continuation is strict: do not run live
scans, loopback verifier tests, or socket-based engine tests. `make offline-test`
is the explicit allowlist; fake engine/verifier fault suites cover syscall
failure paths without opening a real network socket.

**Current-tree evidence:** the 14-suite x86-64 offline allowlist passes in
normal, strict, ASan/UBSan and TSan configurations; GCC `-fanalyzer` reports no
diagnostic; six fuzz targets pass 20,000 inputs each; and the offline PTY suite
passes split CSI, burst input, bracketed paste and resize. NDK r27.2 build
fingerprint `5191f72c5407395a` passed 16 offline suites on the connected
`23090RA98G`, including crypto ABI and differential tests; scalar-dispatch
differential also passed, and all 17 current AArch64 artifacts carry BTI and
PAC notes. Exact commands and output are in `docs/REMEDIATION-P0.md`.

**Post-update review, 2026-08-12.** The rewritten input decoder was re-probed
against the pre-rewrite evidence. Bursts, pastes, split escapes, split UTF-8 and
bracketed paste are correct. One defect survived and is now fixed:
`decode_csi()` matched the arrow and navigation letters only when
`seq_len == 1`, and every unmatched path fell through to
`QN_KEY_CHAR / U+FFFD`, so Ctrl+arrow, Shift+arrow, Alt+arrow and any
unrecognised CSI typed a stray printable character into the UI — including the
Scan Plan editor's Custom numeric fields. Parameters are now parsed properly,
a modifier no longer changes which key was seen, and a well-framed sequence
that is not a key we act on emits nothing. Pinned by
`tests/test_input.c::test_parameterised_csi`.

**Device re-validation, 2026-08-12**, build fingerprint `dd843e79ba6e208f`,
pushed to `/data/local/tmp/qanat-p0` and hashed on both sides first:

```
19/19 artifacts host and device SHA-256 identical
19/19 artifacts report aarch64 feature: BTI, PAC
18/18 device suites ok, including crypto ABI, crypto differential,
      scan_plan, scan_editor, input, engine_faults, verify_faults
qanat 1.0.0 (build dd843e79ba6e208f)
```

This run also includes `test_engine` and `test_verify`, which dial **loopback
only**; that is the allowance the working rules below have always given. No
public scan was run. Plan resolution was exercised on the handset and picks a
device-derived 82 MiB ceiling against the host's 256 MiB.

**New contracts other code must respect** are tabulated in
`docs/REMEDIATION-P0.md`; the two that bite hardest are that `qn_task.next`
returns an enum whose success value is 0, and that engine accounting is now
`claimed == completed + skipped + unattempted`.

### Where things stood before it

| | |
| --- | --- |
| Branch | `qn2-remediation` at `c24e92a`, pushed, working tree clean |
| Remote | `https://github.com/EntropyRoot/Qanat` (private) |
| `origin/main` | `bc80e5f`, an **unrelated older history**. Do not merge or force onto it without deciding that explicitly |
| Export folder | `../qanat-github`; **now 169 files, refreshed from the working tree 2026-08-12, builds standalone and passes 16/16** |
| Source size | 25,235 lines of `.c` / `.h` / `.S`, 13 test suites |

### What is now true, and verified

The architectural work is done. Parsers report facts; a pure classifier decides.

```
transport / TLS / HTTP / edge / flow / stability observations
  -> qn_observation                      include/qanat/observation.h
  -> qn_observation_classify()           pure: no I/O, no clock
  -> store / UI / export
```

`verdict` no longer means two things. `highest_rung_reached` and
`terminal_outcome` are separate fields, both present in the CSV, and
`qn_verify_verdict_str` reports the rung only when the outcome is success. A
record saying "successful edge" and "protocol failure" at once is no longer
expressible. HTTP/1 and HTTP/2 reach the classifier through one canonical
observation, so a policy difference between them cannot be written.

Gates, all green on this commit:

```
11/11 suites          strict            strict-test (GCC and Clang-safe)
GCC analyzer          ASan + UBSan      TSan
6 fuzz targets        24/24 OpenSSL interop
27/27 first-audit checks (scripts/check_first_audit.sh)
```

On the handset, this exact binary
(`sha256 9882cf73c64624e23d8817a7e4bb1809412e5c7b0e883aa6cf1e88ee287a2e64`):

```
5/5 stable-after-marker, colo FRA, score 8478-8998
JSON and CSV both written; CSV carries highest_rung_reached and terminal_outcome
```

That closes the gap found in the prior review: a scan is now tied to a named
binary hash rather than inferred from an older revision.

### The one lesson that cost the most

The first device run of this build showed **every candidate as `reset`**, which
is exactly the shape of the regression that broke this project twice before. It
was not a regression. Building `8c81896` with `git archive` and running it on
the same handset in the same minute produced the same resets: the network was
resetting handshakes. Once the path recovered, both builds worked.

**Never report a device result without an A/B against a known-good build on the
same device in the same conditions.** The handset's network and thermal state
move faster than the code does.

### What is left

Five QN2 items, all TUI, all untouched:

| Item | Sev | File | Invariant |
| --- | --- | --- | --- |
| QN2-041 | high | `src/ui/term.c` | Persistent input byte queue: two keys in one read yield two keys, and an escape sequence may span reads |
| QN2-045 | high | `src/ui/app.c` | One finalize pipeline: stop, join, drain until empty, phase finish, accounting, sort, export, destroy. `q` and `x` must not differ |
| QN2-043 | med | `src/ui/term.c` | Real terminal dimensions preserved; a too-small terminal says so instead of being clamped |
| QN2-044 | med | `src/ui/app.c` | Only explicitly requested formats are written |
| QN2-046 | low | `src/ui/app.c` | Each mode shows only its own statistics; use the engine's counter names and the discovery counters |

Beyond QN2, from the external review and not yet done:

- **Performance, the real bottleneck.** It is not crypto. At
  `verify_concurrency = 64` and `idle = 5000 ms` the verifier ceiling is about
  12.8 endpoints/s no matter how fast the network is; 16,384 finalists means at
  least ~21 minutes of pure holding. Separate the active-transfer pool from the
  stability-hold pool. Then banner timeout on open-but-silent ports, host-major
  discovery ordering, and opportunistic ICMP receive.
- **Fingerprint fidelity.** `include/qanat/profile.h` and `src/net/profile.c`
  now exist; finish the cross-layer story so a profile fixes H2 SETTINGS order,
  pseudo-header order, header order and User-Agent together with the TLS shape,
  under versioned names like `chrome-android-126`, with a full snapshot per
  profile pinned in CI.
- **QN2-009** stays partial: only the `MSG_NOSIGNAL` path was fixed; the other
  three syscall paths were verified by inspection and have no fault-injection
  test, because no syscall-interposition layer exists.
- **QN2-028** stays a documented deviation: opaque is the default, the chain is
  never decompressed, `--cert-strict` refuses instead.
- **QN2-035's merge is entry-granular.** Concurrent writers no longer clobber
  each other's addresses, but where both observed the same address only the
  fresher observation survives.
- **QN2-050 is unverified on hardware.** Thermal sysfs is SELinux-denied to the
  shell on this handset, so throttling is inert there either way.

### Suggested order next session

1. QN2-045 first. Export correctness is user-visible and it now has a clean
   place to live, since finalize can end at the classifier.
2. QN2-041, then 043, 044, 046.
3. Then the verifier pool split, which is the only change that will move total
   scan time by a large factor.

### Working rules that still apply

- Never reset, checkout, clean, restore, revert, or discard anything.
- Reproduce before patching **by building the old code**, not by reasoning about
  it. `git archive <sha> | tar -x -C /tmp/old` and build there; it does not
  disturb the tree.
- Distrust a test that passes. Six tests in this repository have asserted the
  defect rather than the fix. Replace a wrong oracle, never delete the test.
- If a stricter check starts rejecting real Cloudflare traffic, find out whether
  the traffic was valid and fix the parser. Do not add a broad bypass; that
  shortcut caused two regressions here and both were only caught on the device.
- Source comments: one line, under 90 characters, only for non-obvious
  invariants. Reasoning goes in `docs/`.
- Public scans need explicit authorization. Offline device suites, loopback,
  sanitizers, fuzz and interop are always allowed.
- Escapes get mangled through the shell layers. Anything with `\n`, `\r`, `\0`
  or quotes must be written with a file-writing tool, not a heredoc or `sed`,
  and verified afterwards.

### Commands

```bash
wsl.exe -d Ubuntu -- bash -c 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc BUILD=build-test LTO= test'
wsl.exe -d Ubuntu -- bash -c 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc strict && make CC=gcc strict-test && make CC=gcc analyze'
wsl.exe -d Ubuntu -- bash -c 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc sanitize-test && make CC=gcc tsan-test && make CC=gcc tls-test && make CC=gcc fuzz-smoke'
wsl.exe -d Ubuntu -- bash -c 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && sh scripts/check_first_audit.sh'
```

Android, NDK `27.2.12479018`, target `aarch64-linux-android30`, add
`-mbranch-protection=standard`. `adb` is not on PATH; export
`PATH="$PATH:/c/Users/will/AppData/Local/Android/Sdk/platform-tools"` and
`MSYS_NO_PATHCONV=1`, and `chmod 755` after every push.

Refresh the export folder from the committed tree:

```bash
cd /c/Users/will/Downloads/Qanat-main/Qanat && rm -rf ../qanat-export && mkdir -p ../qanat-export && git archive HEAD | tar -x -C ../qanat-export
```

## Current continuation: observation model and external defects 1..18

This section is the authoritative current handoff. Numbered sections below it
are retained as the historical QN2-001..051 handoff and contain stale
`master`/`cf7b1876` snapshot data where explicitly marked.

### Current repository state

| Field | Value |
| --- | --- |
| Branch | `qn2-remediation` |
| HEAD | `8c8189647cd6145492e3fb662e958df7446f5783` |
| Baseline tracked tree | clean |
| Current work | uncommitted by instruction |
| Tracked diff | `43 files changed, 2860 insertions(+), 916 deletions(-)` |
| New implementation files | 6 untracked headers/sources listed in the ledger |
| Device | `23090RA98G` / `zircon`, Android 13 SDK 33, AArch64, serial `AYCQ8DMVOVTCDMBI` |
| Host compiler | GCC 15.2.0, GNU Make 4.4.1 in WSL Ubuntu |
| Android compiler | NDK r27c Clang 18.0.3, `aarch64-linux-android30` |

Do not reset, clean, restore, checkout, revert, or discard this tree. Do not
commit or push unless explicitly requested. Public-network scans still require
explicit authorization; loopback and offline device tests do not.

### What is now true

- Parsers emit facts. `qn_observation_classify()` alone maps facts to
  `highest_rung_reached` plus `terminal_outcome`.
- HTTP/1 and HTTP/2 use one canonical `qn_http_event` and one edge-evidence
  policy.
- Application data cannot be parsed before the request's final wire byte; TTFB
  uses that byte's timestamp.
- All engine exits drain until empty and account before finish/sort/export.
- TLS 1.3 Certificate framing and protected-alert rules, TLS 1.2 ticket order,
  the H1/H2 defects, event-drop ownership, profile fidelity, verifier pool
  separation, banner semantics, discovery order, and ICMP draining are closed.
- Cross-layer profiles are `chrome-android-151`, `firefox-android-153`,
  `safari-ios-26`, and seeded `random`; prior versioned names remain aliases.
- Active transfer capacity defaults to 64; stability capacity defaults to 512.
  Holds release active slots immediately. FD-limited admission is visible as
  `capacity_limited`, never as a false stability success.

The complete fixed/partial/deviation/remaining/refuted matrix, pre-patch
counts, profile pins, and schema migration are in the authoritative first
section of `REMEDIATION-QN2.md`.

### Exact gate summary

| Command | Durable output |
| --- | --- |
| `make CC=gcc BUILD=build-test LTO= test` | 11/11 suites `ok` |
| `make CC=gcc strict` | application built, no warning |
| `make CC=gcc strict-test` | 11/11 suites `ok` |
| `make CC=gcc analyze` | application linked, 0 remaining diagnostics |
| `make CC=gcc sanitize-test` | 11/11 ASan+UBSan suites `ok` |
| `make CC=gcc tsan-test` | 11/11 TSan suites `ok` |
| `make CC=gcc tls-test` | 24/24 OpenSSL cases `ok` |
| `make CC=gcc menu-test` | `menu PTY tests: ok` |
| `make CC=gcc fuzz-smoke` | 6 x 20,000 random inputs `ok` |
| `sh scripts/check_first_audit.sh` | `27 ok, 0 failed` |
| NDK strict `all test-build` | application + 13 tests linked for API 30 |
| `llvm-readelf -n` over all device artifacts | 14/14 report `aarch64 feature: BTI, PAC` |
| all 13 tests in Termux home | every suite `ok`, including ABI and differential |

The device printed, in order:

```text
core tests: ok
crypto tests: ok
tls tests: ok
property tests: ok
engine tests: ok
verify tests: ok
export tests: ok
task tests: ok
outbuf tests: ok
screen tests: ok
discover tests: ok
crypto ABI tests: ok
crypto differential tests: ok
```

`qanat --version` printed `qanat 1.0.0`. The full
`fingerprint show safari-ios-17` output hashes to
`4aa603c3fe53ecd11df685c8d9d4532ad8b78c430bda6936c4867a36805ad36f`
on both x86 and the phone.

### Device artifacts and hashes

All files were first pushed to `/sdcard/Download/qanat-qn2`, streamed from that
staging directory into `/data/data/com.termux/files/home/qanat-qn2-device`
under the Termux UID, hashed, chmodded, and executed there.

| Artifact | SHA-256 |
| --- | --- |
| `qanat` | `cd5ee9cef1d1eeedf71d19c2c5a99bc481809db5c28fc36ad0d8c27b3779fac2` |
| `test_core` | `a40c5aeace5a34ce809600437f4b55056ea5a2b4ab83f0b5d98aedb7e10c854c` |
| `test_crypto` | `eefcb7ad6f57d54d27600882d06744e8d1d0f1110b91a8edde4b51634021296d` |
| `test_tls` | `4f0bff835e746fce52cd5795cd46edc4c634371262f7900a0a3316b6789d2057` |
| `test_props` | `c58de371988d4bd7627d4672d2270e46add21ddec382c2b7bb9ed957ba76a53e` |
| `test_engine` | `a7e27449bc3e559b8dac2236aaa2b5c16dcd417ec986b0c544601f05c1de59ca` |
| `test_verify` | `0b1b63d95ab4fa146f38eb6e38f000d0b8598087b19faf2f3e8582a7ea934138` |
| `test_export` | `7e6fca81d27286711ea0518b2baa66649a398c2c64348dc0670b298ebee496f7` |
| `test_task_cf` | `b5fb0370f0151228dbb5afd341d1e3a85db1797155ed42f1fb9b97c455b27399` |
| `test_outbuf` | `1422db5ee08f0ef55e38a41e0545648560c1fd127137cacb574e4634b1b77f96` |
| `test_screen` | `c5f7a6c23725f21698e1a4c1ad4e8856d935308ab6002f58aa80a1df938c3853` |
| `test_discover` | `c4e055ce42bdd44f342ae85ef8da0688d9fb26e70bf7f51a3247257c67725e7d` |
| `test_crypto_abi` | `e6f38821a7972cbacb4b8297842f8954547de389065a23aa1f68b5500b0637c0` |
| `test_crypto_diff` | `4ee99e49e09e2fbf10efa78db6df6a17c51cfe748d924b087da72c9f445603af` |

### Reproducible Android build

The Makefile target `test-build` builds every selected suite without executing
target binaries on the host. This is the command shape used here; the full
warning list is intentionally explicit:

```bash
env CC="/mnt/c/Users/will/AppData/Local/Android/Sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe --target=aarch64-linux-android30" \
make -j2 BUILD=build-android-qn2 LTO= \
  CFLAGS="-std=c11 -D_GNU_SOURCE -Iinclude -pthread -MMD -MP -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wcast-align -Wwrite-strings -Wredundant-decls -Wno-unused-parameter -Werror -Wconversion -Wsign-conversion -O2 -DNDEBUG -ffunction-sections -fdata-sections -mbranch-protection=standard" \
  LDFLAGS="-pthread -Wl,--gc-sections -O2 -mbranch-protection=standard" \
  all test-build
```

### Output compatibility

- JSON is schema 4. Result objects add authoritative
  `highest_rung_reached` and `terminal_outcome`; `verdict` remains a derived
  display string.
- CSV inserts the two authoritative fields after `verdict`.
- Event logs split classification/rung/terminal and record both verifier
  capacities.
- History remains schema 2 and requires no rewrite.

### File-purpose ledger for this continuation

| File | One-line purpose |
| --- | --- |
| `Makefile` | Link the new fact/profile/gate modules, add cross `test-build`, and include every AArch64 SHA-2 object. |
| `docs/ARCHITECTURE.md` | Record fact ownership, pure classification, finalization, and dual verifier pools. |
| `docs/HANDOFF.md` | Preserve exact current commands, evidence, artifacts, schema, and remaining authorization gap. |
| `docs/PERFORMANCE.md` | Replace the idle-slot ceiling with the active/hold capacity model without making an unmeasured speed claim. |
| `docs/REMEDIATION-QN2.md` | Record reproductions, issue disposition, regressions, gate matrix, and migration contract. |
| `docs/TLS.md` | Document split classification, protected alerts/cert framing, and versioned cross-layer profiles. |
| `include/qanat/engine.h` | Expose one engine-finalization/accounting contract and remove duplicate drop ownership. |
| `include/qanat/http1.h` | Define bounded HTTP/1 canonical-fact parser state. |
| `include/qanat/http2.h` | Define canonical H2 events and only state that enforces a parser invariant. |
| `include/qanat/observation.h` | Define the aggregate facts, canonical HTTP event, and pure classifier API. |
| `include/qanat/probe.h` | Preserve connect latency independently for open silent banners. |
| `include/qanat/profile.h` | Define versioned TLS+H2+HTTP client-profile shapes. |
| `include/qanat/qanat.h` | Replace the overloaded verdict enum with rung/outcome records and config fields. |
| `include/qanat/request_gate.h` | Define queued/flushed request state and wire-based elapsed-time rules. |
| `include/qanat/store.h` | Remove the unused dirty bit while retaining history schema 2. |
| `include/qanat/tls.h` | Expose versioned fingerprint/profile metadata and safe parse/string APIs. |
| `include/qanat/verify.h` | Carry observations/classifications and expose verifier capacity planning/status. |
| `scripts/test_tls_local.sh` | Exercise all three versioned fixed profiles across the OpenSSL matrix. |
| `src/core/stats.c` | Consume the split classification contract in aggregate statistics. |
| `src/core/store.c` | Remove dead dirty-state writes without changing the persisted schema. |
| `src/core/util.c` | Provide rung/outcome strings, profile defaults, and stability-capacity defaults. |
| `src/export.c` | Emit JSON schema 4 and authoritative rung/outcome CSV fields. |
| `src/main.c` | Add fingerprint inspection, stability CLI wiring, and unified headless finalization. |
| `src/net/certscan.h` | Implement bounded streaming TLS 1.3 Certificate framing. |
| `src/net/engine.c` | Fix drop ownership, silent-banner timing, saturating accounting, and finalization. |
| `src/net/http1.c` | Enforce conservative H1 grammar and emit canonical HTTP facts. |
| `src/net/http2.c` | Fix SETTINGS/103/GOAWAY/header-cap semantics and emit canonical HTTP facts. |
| `src/net/observation.c` | Centralize edge evidence and pure rung/outcome classification. |
| `src/net/probe_http.c` | Feed shallow HTTP observations without assigning policy/verdicts. |
| `src/net/profile.c` | Materialize fixed and randomized cross-layer request shapes. |
| `src/net/request_gate.c` | Enforce request flush gating and final-wire-byte TTFB origin. |
| `src/net/tls12.c` | Enforce NewSessionTicket framing and legal handshake order. |
| `src/net/tls13.c` | Use the certificate scanner and reject plaintext alerts after keys. |
| `src/net/tls_hello.c` | Build versioned/random TLS shapes and make GREASE initialization explicit. |
| `src/net/verify.c` | Orchestrate fact collection, request gating, dual pools, capacity evidence, and classification. |
| `src/task/task_cf.c` | Persist split results, apply one edge policy, and log both pool capacities. |
| `src/task/task_discover.c` | Schedule TCP port-major and drain ICMP replies throughout sending. |
| `src/ui/app.c` | Route completion, stop, quit, and interrupt through one drain/finish/export pipeline. |
| `src/ui/menu.c` | Expose stability concurrency and versioned profiles in the numbered workflow. |
| `tests/arm64/abi_probe.S` | Make the ABI trampoline BTI-compatible and preserve the linked PAC/BTI note. |
| `tests/bench_tls_verify.c` | Read classification from the new observation result in the local verifier bench. |
| `tests/test_core.c` | Regress H1/H2, canonical edge policy, and split-classification behaviour. |
| `tests/test_discover.c` | Pin port-major discovery scheduling alongside ICMP invariants. |
| `tests/test_engine.c` | Regress one-owner drops, saturation, final drains, and silent banners. |
| `tests/test_export.c` | Pin schema 4 and authoritative rung/outcome fields. |
| `tests/test_menu_pty.py` | Keep the numbered menu transcript aligned with the new setting. |
| `tests/test_outbuf.c` | Regress queued/flushed quarantine and wire-origin TTFB. |
| `tests/test_tls.c` | Regress certificate/alert/ticket rules and full profile snapshots. |
| `tests/test_verify.c` | Table-test classification and active/stability capacity planning. |

### Unresolved evidence and smallest next action

No public scan was run. Therefore this exact `cd5ee9...` application binary
has not been observed reaching `stable-after-marker`. With explicit user
authorization, run a low-limit device scan, retain its JSON/event log, and tie
both to this binary hash. Do not infer that result from an older revision's
scan. No performance speedup is claimed without a thermally credible A-B-A
measurement.

## 1. Read This First

- **Continue from the current dirty working tree.** The work is uncommitted by
  design.
- **Do not** `git reset`, `git clean`, `git restore`, `git checkout --`,
  `git revert`, or otherwise discard anything.
- **Preserve every pre-existing user change.** 45 tracked files are modified
  and 12 untracked paths exist; all of them are wanted.
- **Do not commit** unless the user explicitly asks.
- **Do not start the AArch64 assembly optimization work yet.** See section 11.
- The mandatory active scope is **QN2-001 through QN2-051** and nothing else.
- First-audit fixes are presumed complete. Do not re-open them unless a current
  regression directly blocks a QN2 item, and then say which.
- **Public-network tests require explicit user authorization.** Authorization
  from an older run does not carry forward.
- Loopback, offline device suites, sanitizer, fuzz, and OpenSSL interoperability
  tests are always allowed.

## 2. Repository Snapshot

| | |
| --- | --- |
| HEAD | `cf7b18767a8c8a1293197039a759ad62c8ea938a` |
| Branch | `master` |
| State | dirty: 45 modified, 12 untracked, 0 staged |
| Whole-tree diff | `45 files changed, 5176 insertions(+), 684 deletions(-)` |
| Remediation diff | run `git diff --stat -- . ':(exclude)docs/HANDOFF.md'` for the same, excluding this document |
| Source size | 27,479 lines of `.c`, `.h`, `.S` (was 24,342 at session start) |

### `git status --short`

```
 M Makefile
 M docs/HANDOFF.md
 M fuzz/fuzz_http1.c
 M include/qanat/cidr.h
 M include/qanat/crypto.h
 M include/qanat/engine.h
 M include/qanat/http1.h
 M include/qanat/http2.h
 M include/qanat/probe.h
 M include/qanat/qanat.h
 M include/qanat/store.h
 M include/qanat/task.h
 M include/qanat/timewheel.h
 M include/qanat/tls.h
 M include/qanat/util.h
 M include/qanat/verify.h
 M scripts/test_tls_local.sh
 M src/core/cidr.c
 M src/core/cpuinfo.c
 M src/core/netinfo.c
 M src/core/store.c
 M src/core/timewheel.c
 M src/core/util.c
 M src/crypto/aead.c
 M src/export.c
 M src/main.c
 M src/net/engine.c
 M src/net/http1.c
 M src/net/http2.c
 M src/net/probe_http.c
 M src/net/tls12.c
 M src/net/tls13.c
 M src/net/tls_int.h
 M src/net/verify.c
 M src/task/task_cf.c
 M src/task/task_discover.c
 M src/ui/app.c
 M src/ui/screen.c
 M tests/test_core.c
 M tests/test_crypto.c
 M tests/test_engine.c
 M tests/test_export.c
 M tests/test_props.c
 M tests/test_tls.c
 M tests/test_verify.c
?? docs/REMEDIATION-QN2.md
?? docs/evidence/
?? qanat-test-history.tsv.lock
?? scripts/check_first_audit.sh
?? src/net/certscan.h
?? src/net/flowmeter.h
?? src/net/hpack_huff.h
?? src/net/outbuf.h
?? tests/test_discover.c
?? tests/test_outbuf.c
?? tests/test_screen.c
?? tests/test_task_cf.c
```

`docs/evidence/` holds the pulled device artifact named in section 5.

### `git diff --stat -- . ':(exclude)docs/HANDOFF.md'`

This document is excluded because it changes as it is written; everything
below is the remediation itself.

```
 Makefile                  | 139 +++++++-
 fuzz/fuzz_http1.c         |   2 +-
 include/qanat/cidr.h      |  11 +
 include/qanat/crypto.h    |   2 +
 include/qanat/engine.h    |  61 +++-
 include/qanat/http1.h     |  11 +-
 include/qanat/http2.h     |  33 +-
 include/qanat/probe.h     |  21 +-
 include/qanat/qanat.h     |   4 +-
 include/qanat/store.h     |   8 +-
 include/qanat/task.h      |  15 +
 include/qanat/timewheel.h |   3 +-
 include/qanat/tls.h       |  35 ++
 include/qanat/util.h      |   6 +
 include/qanat/verify.h    |  25 +-
 scripts/test_tls_local.sh |  30 +-
 src/core/cidr.c           | 144 +++++++++
 src/core/cpuinfo.c        |  44 ++-
 src/core/netinfo.c        |  66 +++-
 src/core/store.c          | 236 +++++++++++---
 src/core/timewheel.c      |  52 ++-
 src/core/util.c           |  32 ++
 src/crypto/aead.c         |  40 ++-
 src/export.c              |  86 ++++-
 src/main.c                |  28 +-
 src/net/engine.c          | 226 ++++++++++---
 src/net/http1.c           | 119 ++++---
 src/net/http2.c           | 336 ++++++++++++++++---
 src/net/probe_http.c      | 170 ++++++++--
 src/net/tls12.c           | 158 ++++++++-
 src/net/tls13.c           |  67 +++-
 src/net/tls_int.h         |  10 +
 src/net/verify.c          | 173 +++++++---
 src/task/task_cf.c        |  40 +--
 src/task/task_discover.c  |  83 ++++-
 src/ui/app.c              |   1 +
 src/ui/screen.c           |  40 ++-
 tests/test_core.c         | 807 +++++++++++++++++++++++++++++++++++++++++++++-
 tests/test_crypto.c       |  41 +++
 tests/test_engine.c       | 215 ++++++++++++
 tests/test_export.c       | 102 ++++++
 tests/test_props.c        | 359 ++++++++++++++++++++-
 tests/test_tls.c          | 620 +++++++++++++++++++++++++++++++++++
 tests/test_verify.c       | 113 +++++++
 44 files changed, 4406 insertions(+), 408 deletions(-)
```

### Build environment

| | |
| --- | --- |
| Host | `MINGW64_NT-10.0-26200 mine 3.6.7-fb42d713.x86_64 x86_64 Msys` |
| Build VM | WSL2 Ubuntu, `Linux 6.6.114.1-microsoft-standard-WSL2 x86_64` |
| GCC | `gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0` |
| Clang in WSL | **absent.** `clang --version` produces nothing, and WSL has no network so it cannot be installed. |
| Make | `GNU Make 4.4.1` |
| NDK | `27.2.12479018`, `clang version 18.0.3` (`Android 12470979, based on r522817c`), host `x86_64-w64-windows-gnu` |
| `aarch64-linux-gnu-gcc` | absent in WSL |
| `qemu-aarch64` | absent in WSL |
| adb | `C:/Users/will/AppData/Local/Android/Sdk/platform-tools/adb.exe`, **not on PATH** |
| Device | `23090RA98G` (`zircon`), Android 13, SDK 33, serial `AYCQ8DMVOVTCDMBI` |
| Termux | installed on device (`com.termux`), **not reachable from `adb shell`**; its Clang was not used this session |

**Clang coverage this session came from the NDK cross-compiler, not from a
native Clang.** The old hand-off's claim of "Termux Clang 21.1.8" was not
re-verified and should not be relied on.

### Built artifacts still on disk

`build-android/` was rebuilt from the current tree on 2026-08-11 and
`test_core` / `test_tls` from it were run on the handset. Everything else on
disk predates later edits.

Other build products: `build-android/{test_core,test_crypto,test_engine,test_outbuf,test_props,test_tls,test_task_cf,bench_crypto}`,
plus WSL build trees `build-strict/`, `build-test/`, `build-android/`,
`build-sanitize/`, `build-tsan/`, `build-fuzz/`, and several `build-pre*/`
directories used for pre-patch reproductions.

**A built binary proves nothing about source correctness.** Rebuild before
drawing any conclusion from one.

## 3. Scope and Issue Accounting

### The count

**44 fixed, 1 partial (QN2-009), 1 documented-deviation (QN2-028),
5 remaining.** 44 + 1 + 1 + 5 = 51. Three of the 35 were already correct before the remediation
began and are recorded as such in the matrix.

Earlier self-reports in this project claimed 31 or 33 closed; both were
optimistic. The 2026-08-10 review downgraded five issues, and every one of
those downgrades was reproduced before being fixed — see section 5. Treat any
count in this document as claimed only where the matrix cites evidence.

### Matrix

Status vocabulary: `fixed`, `partial`, `documented-deviation`, `remaining`,
`blocked`, `already-fixed-before-this-session`.

| ID | Subsystem | Sev | Status | Implementation files | Regression tests | Verification evidence | Remaining concern |
| --- | --- | --- | --- | --- | --- | --- | --- |
| QN2-001 | verifier | crit | fixed | `src/net/verify.c`, `include/qanat/verify.h` | `test_failed_batch_does_not_abandon_the_rest`, `test_cancel_types_every_candidate` | pre-patch: `only 2 of 5 candidates were attempted (3 unattempted)` | none known |
| QN2-002 | timewheel | crit | fixed | `src/core/timewheel.c`, `include/qanat/timewheel.h` | `test_timewheel_revolution_jump`, `_multiple_revolutions`, `_clock_edges`, `_rearm_during_expiry` | pre-patch: `hid an overdue deadline` at 8192/8193/16384 ms | none known |
| QN2-003 | timewheel | high | fixed | `src/core/timewheel.c` | `test_timewheel_next_timeout_model`, `test_timewheel_wakeup_budget` | 1000 → 160 wakeups, 8 s deadline at 50 ms cap | cap-bound, not deadline-bound; by design |
| QN2-004 | http2 | crit | fixed | `src/net/http2.c`, `include/qanat/http2.h`, `src/net/verify.c` | `test_http2_unopened_streams` | pre-patch: DATA on stream 3 before any flow request returned OK and carried bytes | none known |
| QN2-005 | task_cf | crit | fixed | `src/task/task_cf.c`, `include/qanat/task.h` | `tests/test_task_cf.c` (whole suite) | pre-patch: `wrote 16385 records into a capacity of 16384` | ASan cannot see arena overflows; bounds check is the only defence |
| QN2-006 | output paths | high | fixed | none needed | CLI verification table in `REMEDIATION-QN2.md` | 6 collision cases refused, distinct paths accepted | pre-existing; hard link created after validation is undetectable |
| QN2-007 | engine | crit | fixed | `src/net/engine.c`, `include/qanat/engine.h` | `check_accounted`, `test_stop_accounts_for_everything` | pre-patch: `reserved 64 indices but only claimed 40` | stranded tails are counted, not requeued; deliberate |
| QN2-008 | engine/main | crit | fixed | `src/net/engine.c`, `src/main.c` | `test_stop_accounts_for_everything` (status transitions) | RUNNING → CANCELLED asserted | EBADF injection test needs the fault-injection layer, which does not exist |
| QN2-009 | verifier | crit | partial | `src/net/verify.c` | existing loopback suites | D patched (`send(MSG_NOSIGNAL)`); A, B, C verified already correct by inspection | no per-syscall fault-injection tests; A/B/C never independently exercised |
| QN2-010 | verifier | high | fixed | `src/net/outbuf.h` (new), `src/net/verify.c` | `tests/test_outbuf.c` buffer half | pre-patch: queue refused with 10 of 16 bytes free | none known |
| QN2-011 | discovery | crit | fixed | `src/task/task_discover.c`, `include/qanat/task.h` | `tests/test_discover.c` (new suite) | pre-patch: 69 failures; forged, replayed and duplicated replies all accepted | ICMP id is kernel-owned on a ping socket, so not checkable |
| QN2-012 | verifier | high | fixed | `src/net/verify.c`, `include/qanat/verify.h` | none directly; field split verified by inspection | — | trace and flow share `ttfb_us`; no `flow_headers_us` |
| QN2-013 | hpack | crit | already-fixed-before-this-session | `src/net/http2.c` | `test_http2_strict_hpack_and_credit_retry` | index 62 with table size 0 rejected | none known |
| QN2-014 | hpack | high | already-fixed-before-this-session | `src/net/http2.c` | `test_http2_strict_hpack_and_credit_retry` | size update = 1 rejected; consecutive updates now capped at 2 | none known |
| QN2-015 | hpack | crit | fixed | `src/net/hpack_huff.h` (new), `src/net/http2.c` | `test_hpack_huffman_vectors`, `test_http2_huffman_handling` | 8 RFC 7541 C.4/C.6 vectors; probe table in section 5 | none known |
| QN2-016 | http2 | high | fixed | `src/net/http2.c` | `test_http2_settings_validation` | `ENABLE_PUSH=2` rejected and not acknowledged | duplicate settings in one frame are last-wins, each still validated |
| QN2-017 | http2 | high | fixed | `src/net/http2.c` | `test_http2_response_head_rules`, `test_http2_unopened_streams` | DATA before head rejected; head needs exactly one `:status` | reachable only via non-Huffman names; see QN2-018 |
| QN2-018 | http2 | high | fixed | `src/net/http2.c` | `test_http2_response_head_rules`, `test_http2_huffman_handling` | probe cases A/B/C/E/G flip from accepted to `PROTOCOL` | none known |
| QN2-019 | http2 | high | fixed | `src/net/http2.c` | `test_http2_flow_after_trace_window`, `test_http2_strict_hpack_and_credit_retry` | 16 MiB flow after trace; windows never reach zero; 1-byte frame emits nothing | 16 KiB publication step is a fixed constant |
| QN2-020 | http1 | high | fixed | `src/net/http1.c` | `test_http1_transfer_encoding_order` | pre-patch: `chunked, gzip` framed as chunked | none known |
| QN2-021 | http1 | high | fixed | `src/net/http1.c` | `test_http1_transfer_encoding_order` | pre-patch: split field lines were last-wins | none known |
| QN2-022 | http1 | med | fixed | `src/net/http1.c` | `test_http1_switching_protocols` | pre-patch: 101 then 200 accepted, `responses == 1` | none known |
| QN2-023 | probe_http | med | fixed | `src/net/probe_http.c` | `test_http_status_line_strictness` | pre-patch: 6 malformed status lines accepted | none known |
| QN2-024 | probe_http/http1 | crit | fixed | `src/net/probe_http.c`, `src/net/http1.c`, `include/qanat/probe.h`, `include/qanat/http1.h` | `test_trace_marker_is_not_forgeable` | committed scanner was a 64-byte sliding substring window with no line concept | h2 body marker path still uses `http2.c`'s own `scan_edge`; not line-oriented |
| QN2-025 | tls12 | high | fixed | `src/net/tls12.c`, `src/net/tls13.c` | `test_tls12_sigalg_semantics` | pre-patch: 7 failures with only this hunk reverted | signature itself is still never verified, by design |
| QN2-026 | tls12 | high | fixed | `src/net/certscan.h` (new), `src/net/tls12.c`, `src/net/tls13.c` | `test_tls12_certificate_framing` | pre-patch: 27 failures; 6 new interop cases on a real 4096-bit chain | identity still needs the leaf inside the first 2 KiB |
| QN2-027 | tls13 | high | fixed | `src/net/tls13.c` | `test_tls13_key_update_is_typed` | pre-patch: both legal request bytes returned OK with the old key retained | a KeyUpdate-insisting peer now ends `unsupported` |
| QN2-028 | tls13 | high | documented-deviation | `src/net/tls13.c`, `include/qanat/tls.h`, `src/net/verify.c` | `test_tls13_compressed_certificate_framing` | both contracts asserted; `--cert-strict` refuses | chain is never decompressed; opaque is the default. See section 5 |
| QN2-029 | tls12 | med | fixed | `src/net/tls12.c` | `test_tls12_sequence_wrap` | pre-patch: sealed the wrapping record and reset the counter | unreachable at 2^64 records; closed by construction |
| QN2-030 | crypto | med | fixed | `src/crypto/aead.c`, `include/qanat/crypto.h` | `test_aead_invalid_id` | pre-patch: 5 `key_len == 0` assertions failed | none known |
| QN2-031 | cidr | high | already-fixed-before-this-session | `src/core/cidr.c` | `test_cidr_snapshot_loader` | probe: old loader rejected the NUL line already (`accepted=0 rejected=1`) | diagnosis improved only; `getline` not adopted, 160-byte line bound stands |
| QN2-032 | cidr | med | fixed | `src/core/cidr.c`, `include/qanat/cidr.h`, `src/task/task_cf.c`, `include/qanat/task.h` | `test_cidr_snapshot_loader` | probe: two passes disagreed (`file_lines=0` vs loader processing 1) | `cidr.c` now depends on SHA-256 |
| QN2-033 | store | high | fixed | `src/core/store.c`, `include/qanat/store.h`, `src/task/task_cf.c` | `test_store_schema` | v1 migrates; v3/headerless/v0 refused | separate `connect_us` / `ttfb_us` columns deferred to a v3 schema |
| QN2-034 | store | med | fixed | `src/core/util.c`, `src/task/task_cf.c` | `test_wall_clock_is_validated` | one validated read per finalize | the failure branch needs syscall interposition to exercise |
| QN2-035 | store | high | fixed | `src/core/store.c` | `test_store_concurrent_merge` | pre-patch: second writer erased the first's address | merge is entry-granular, not sample-additive |
| QN2-036 | store | med | fixed | `src/core/store.c` | `test_store_eviction_is_stale_aware` | pre-patch: stale 1-of-1 evicted a recent 32-of-40 | none known |
| QN2-037 | engine | high | fixed | `src/net/engine.c` | `test_tokens_track_attempts` | `384 claimed, 384 issued, 42 launch retries` | none known |
| QN2-038 | engine | med | fixed | `src/net/engine.c`, `include/qanat/engine.h`, `src/main.c` | `test_counters_separate_retries_from_outcomes` | partition asserted | TUI labels not re-worded; folded into QN2-046 |
| QN2-039 | verifier | high | fixed | `src/net/flowmeter.h` (new), `src/net/verify.c`, `include/qanat/verify.h` | `test_flow_report` | stall case asserts `kbps==0`, `partial_kbps==419`, `stall_us==9000000` | no end-to-end bulk transfer; needs a peer serving megabytes |
| QN2-040 | engine | med | fixed | `src/net/engine.c`, `include/qanat/engine.h`, `src/main.c`, `src/ui/app.c` | `test_concurrent_stats_readers` | pre-patch TSan: `data race src/net/engine.c:1381 in qn_engine_stats` | none known |
| QN2-041 | tui | high | remaining | `src/ui/term.c` | none | none | not started |
| QN2-042 | tui | crit | fixed | `src/ui/screen.c` | `tests/test_screen.c` (new suite) | pre-patch: 9 of 10 hostile strings reached a cell | input decoding (QN2-041) is separate |
| QN2-043 | tui | med | remaining | `src/ui/term.c` | none | none | not started |
| QN2-044 | tui | med | remaining | `src/ui/app.c` | none | none | not started |
| QN2-045 | tui | high | remaining | `src/ui/app.c` | none | none | not started |
| QN2-046 | tui | low | remaining | `src/ui/app.c` | none | none | not started; also owns the QN2-038 label rework |
| QN2-047 | export | crit | fixed | `src/export.c`, `src/net/probe_http.c`, `src/net/verify.c`, `src/core/util.c` | `test_export_neutralizes_hostile_fields`, `test_export_keeps_valid_utf8` | pre-patch: 9 failures | none known |
| QN2-048 | netinfo | med | fixed | `src/core/netinfo.c` | none directly | verified by inspection; device shows no default route in the main table | `/proc/net/route` is main-table only; policy tables need rtnetlink |
| QN2-049 | discovery | low | fixed | `src/task/task_discover.c`, `include/qanat/task.h` | none directly | denominator now counts both phases' probes | new counters are not surfaced in the TUI yet (QN2-046) |
| QN2-050 | cpuinfo | med | fixed | `src/core/cpuinfo.c`, `src/net/engine.c` | `test_thermal_zone_selection` | 13 CPU zone names accepted, 13 non-CPU rejected | thermal sysfs is SELinux-denied on the device, so unverified there |
| QN2-051 | build | med | fixed | `Makefile` | LTO matrix in `REMEDIATION-QN2.md` | 6 GCC invocations plus a Clang ThinLTO cross-build | probe cannot see a `--target` placed in `CFLAGS` |

Totals: **fixed 44** (4 of them already correct before the remediation began),
**partial 1** (QN2-009), **documented-deviation 1** (QN2-028),
**remaining 5**: QN2-041, 043, 044, 045, 046, all in the TUI.

## 4. Completed Work

Full per-issue narrative, including every pre-patch reproduction, is in
`docs/REMEDIATION-QN2.md`. Summary by subsystem.

### Typed observations and run status

`qanat.h` gained `QN_FAIL_CANCELLED`. `qn_verify_status` gained `cancelled` and
`unattempted`, so `attempted + unattempted == n` and
`completed + cancelled == attempted` hold. Every verifier output element is
typed at exit: finished, cut short, or never dialled. `qn_engine_status`
(IDLE/RUNNING/COMPLETE/CANCELLED/FATAL) is settled in `qn_engine_join` after
every worker has retired.
Files: `include/qanat/qanat.h`, `include/qanat/verify.h`,
`include/qanat/engine.h`, `src/net/verify.c`, `src/net/engine.c`, `src/main.c`.

### Engine lifecycle and accounting

`worker_retire()` terminates active probes, gives the pending job a typed
terminal event, and counts the stranded tail of a reserved claim chunk as both
claimed and unattempted. `qn_engine_accounted()` exposes
`claimed == completed + unattempted`. Token discipline split into
`tokens_ready()` / `tokens_debit()` so a token means an actual network attempt.
The single `errors` counter became `local_launch_failures`,
`syscall_failures`, `terminal_job_failures`, `protocol_failures`,
`events_dropped`, `unreach`, plus derived `network_failures`.
`qn_engine_stats` is a genuine `const` snapshot; sampling moved to
`qn_engine_rate_sample()` under `rate_lock` with an atomic EWMA.
Tests: `tests/test_engine.c`, five new cases.
Commands that passed: `make CC=gcc BUILD=build-test LTO= test`,
`make CC=gcc tsan-test`.

### Verifier syscall handling

`flush_out` uses `send(..., MSG_NOSIGNAL)` instead of `write()`. `epoll_ctl`
MOD failure handling, `epoll_wait` EINTR/fatal handling and read/send EINTR
retry were each verified already correct in the current tree and left alone.
The batch loop no longer treats an empty slot set as terminal while candidates
remain.

### Time wheel

`cursor` became the absolute `cursor_tick`; a jump of one or more revolutions
clamps to `now_tick - (QN_TW_SLOTS - 1)` so a 60-second jump costs no more than
an 8-second one. `qn_tw_next_timeout` scans only `cap / QN_TW_TICK_MS + 2`
slots and reads real `deadline_ms` values. `qn_tw_arm` takes the caller's clock.
Measured: 1000 → 160 wakeups for one silent 8 s deadline at a 50 ms cap.

### HTTP/1

Transfer-Encoding parsed as an ordered coding list accumulated across all field
lines; chunked framing only when chunked is final. 101 rejected outright. Status
line strictly validated. The body marker scanner became line-oriented and feeds
`qn_http_trace_parse`, a strict `key=value` parser. `Server: cloudflare` and
`CF-Ray` demoted to `QN_HTTP1_EV_WEAK_MARKER`.
**Compatibility change:** `qn_http_reply` gained `colo_verified`;
`qn_http1` replaced `edge_tail[16]`/`edge_tail_n` with
`line[QN_TRACE_LINE_MAX]`/`line_n`/`line_overflow`. `fuzz/fuzz_http1.c` was
updated for the new field.

### HTTP/2 and HPACK

Explicit per-stream state (IDLE/OPEN/HEADERS/CLOSED) with
`qn_h2_open_stream()` called when each request is written. Frames for unopened,
closed or server-initiated streams rejected. Response head requires exactly one
`:status` before any regular field. SETTINGS values range-checked.
WINDOW_UPDATE credit published a frame at a time.
**API change:** `qn_h2_rc` gained `QN_H2_UNSUPPORTED`; `qn_h2` gained stream
state, `peer_settings`, `goaway`.
**Known gap:** Huffman-coded names bypass the new checks. Section 5.

### TLS 1.2 sequencing

`tls12_step` walks `EXPECT_CERT → EXPECT_SERVER_KX → EXPECT_REQ_OR_DONE →
FLIGHT_DONE`. ServerKeyExchange requires complete signature framing.
ServerHelloDone must be empty. CertificateRequest legal only once and only in
position three. Sequence-number wrap refused.
Validated against nine real OpenSSL 1.2 handshakes.

### TLS 1.3 KeyUpdate policy

Option B from the audit: validate state, length and `request_update`, then
return `QN_TLS_RC_UNSUPPORTED`. Success is never returned while the old read
key is retained, which previously turned every later record into a decryption
failure the tool reported as interference.

### CompressedCertificate policy

Outer RFC 8879 framing validated against the **declared** message length. Sets
a new `cert_compressed` flag, never `saw_certificate`.
`on_certificate_verify` and `on_server_finished` accept
`saw_certificate || cert_compressed`. Exact contract in section 5.

### AEAD contract

`qn_aead_key_len` returns 0 for unknown ids. `qn_aead` gained `ready`, set last
and checked by seal and open, because `QN_AEAD_AES128GCM == 0` means a zeroed
context is otherwise a valid id.

### Test and fault-injection infrastructure

Three new suites: `tests/test_engine.c` (grew to 9 cases),
`tests/test_task_cf.c`, `tests/test_outbuf.c`. Two pure units extracted so the
audit's required cases became reachable: `src/net/outbuf.h` (send-side
compaction buffer) and `src/net/flowmeter.h` (flow rate and stall reporting).
Fault injection currently means `RLIMIT_NOFILE` squeezing in `test_engine.c`
and `test_verify.c` only. **There is no syscall-interposition layer**; Phase 11F
was not built.

### Residual risk carried by completed work

- `test_tokens_track_attempts` exercises real fd pressure on WSL (42 launch
  retries) but not on bionic, where loopback refuses synchronously and the
  squeeze never bites. The invariant is asserted on both; the pressure is not.
- `QN2-005`'s overflow is invisible to ASan because the arrays are
  suballocated from one arena mapping.

## 5. Independent Review Findings

> **All six findings in this section were resolved in the follow-up session of
> 2026-08-11.** Each entry below keeps the reproduction that proved the defect,
> followed by what closed it. Per-issue detail is in `REMEDIATION-QN2.md`.

Every finding below was **re-verified against the tree**, not carried over from
the review text.

### HPACK Huffman — QN2-015 and QN2-018 — RESOLVED 2026-08-11

A probe was compiled against the current `src/net/http2.c` and run. Result
(`rc: 0=OK 1=PROTOCOL 2=SPACE 3=UNSUPPORTED`):

```
A duplicate :status via Huffman name           rc=0 head=1 status=200
B forbidden connection header via Huffman      rc=0 head=1 status=200
C malformed Huffman name                       rc=0 head=1 status=200
D Huffman :status value (indexed name 8)       rc=3 head=0 status=0
E duplicate :status, both indexed              rc=1 head=0 status=200
F forbidden connection header, plain           rc=1 head=0 status=200
```

**All three reviewed adversarial cases still pass** (A, B, C accepted with a
valid response head), while their plain-text equivalents (E, F) are correctly
rejected. The mechanism is in `parse_hpack()`: a literal field with `idx == 0`
and a Huffman-coded name sets `scan->saw_regular` and `continue`s, so the
duplicate-`:status`, lowercase, forbidden-header and trailer checks never see
it.

This shape was chosen deliberately, and the reason is on record: making an
undecodable name fatal caused every real Cloudflare response to end as
`h2-hpack-huffman` / `unsupported`, verified on-device. The narrow version
restored function but left the bypass.

**Required final fix:** a bounded RFC 7541 Appendix B Huffman
decoder/validator for both names and values, then run the existing
pseudo-header, lowercase, duplication, trailer and forbidden-header checks on
the decoded name. Reject explicit EOS, validate end padding, reject overlong or
incomplete sequences, bound decoded output before writing.

**Blocker, since removed:** the Appendix B table (257 code/bit-length pairs)
was not in the repository and WSL has no network to fetch RFC 7541. The RFC was
fetched on the Windows host instead and the table extracted mechanically; see
`REMEDIATION-QN2.md` for the hash and the checks that validated it.
Original concern: Transcribing it from
memory risks a table that passes the two or three recallable vectors while
silently mis-decoding everything else — the same failure mode as the GHASH
reflection bug in this project's history. Obtain the RFC text, then implement
`src/net/hpack_huffman.c` and assert against the RFC 7541 C.4 and C.6 vectors
**before** wiring it in.

### Large TLS 1.2 Certificate — QN2-026 — RESOLVED 2026-08-11

Current `src/net/tls12.c`:

```c
if (qn_tls_cert_leaf(s->hs, s->hs_kept, false, &leaf, &leaflen)) {
    qn_tls_cert_identity(...);
} else if (s->hs_len == s->hs_kept) {
    return QN_TLS_RC_PROTO;
}
s->saw_certificate = true;
```

A Certificate larger than `QN_TLS_HS_BUF` (2048) has `hs_kept < hs_len`, so an
unparseable prefix falls through and **still sets `saw_certificate`**. This is
asserted as intended behaviour by `test_tls12_flight_order`'s last case.

It was made this way because the strict version broke real handshakes: a device
run showed `protocol-invalid` with `version=0x0000` for every candidate, since
real chains exceed the parse buffer. The OpenSSL matrix passed throughout
because its test certificate is small.

**Required final fix:** structurally validate the complete Certificate message
using bounded streaming state — walk the 3-byte chain length and each 3-byte
entry length as bytes arrive, keeping only a small cursor — rather than
requiring the whole message in `hs`. Then `saw_certificate` can mean the
framing was validated end to end regardless of size.

### CompressedCertificate — QN2-028 — CONTRACT NAMED 2026-08-11

| Property | Value |
| --- | --- |
| `outer_framing_valid` | **yes**: algorithm is 2 (brotli), `uncompressed_length` non-zero and ≤ `QN_TLS_CERT_MAX` (256 KiB), `compressed_length + 8 == hs_len` exactly |
| `cert_compressed` | **set** when the above holds |
| `certificate_parsed` | **no**. The chain is never decompressed |
| `identity_available` | **no**. `peer_cn` and `peer_issuer` stay empty |

An algorithm we never offered returns `QN_TLS_RC_UNSUPPORTED`.
`on_certificate_verify` and `on_server_finished` accept
`saw_certificate || cert_compressed`.

**This is outer framing validation only and must not be described as RFC 8879
certificate validation.** Full support means a bounded brotli decoder plus
inner Certificate parsing; neither exists.

### ServerKeyExchange SignatureAndHashAlgorithm — QN2-025 — RESOLVED 2026-08-11

Current `src/net/tls12.c`:

```c
if (!m[off] || !m[off + 1u])
    return QN_TLS_RC_PROTO; /* neither hash nor signature may be "none" */
```

It **only rejects zero bytes**. Any other pair is accepted, including values
not offered in the ClientHello and values incompatible with the negotiated
suite (for example an ECDSA signature algorithm on an `ECDHE_RSA` suite).

**Required:** validate the hash and signature identifiers against the set the
ClientHello offered, and against the key-exchange half of the negotiated suite.
`qn_tls12_suite()` already knows the suite; the offered list is in
`tls_hello.c`.

### Test harness overlap — FIXED 2026-08-11 (warning never reproduced)

`h2_frame()` in `tests/test_core.c` is called in a few places as
`h2_frame(wire, ..., wire + 9, len)`, so its `memcpy(out + 9, body, len)` copies
a region onto itself. Compiling every suite with
`-Werror -Wconversion -Wsign-conversion -Wrestrict -O2` under GCC 15.2
produced **no warning**. It may still fire on Clang or another GCC; if the next
session sees it, give `h2_frame` a separate payload buffer rather than
suppressing it.

### Strict-test target — ADDED 2026-08-11

`make strict` builds **only the application** (`$(BIN)`), not the test
binaries. The tests build with default `CFLAGS`, without `-Werror`,
`-Wconversion` or `-Wsign-conversion`.

They do, however, compile and run clean when forced. This exact command
succeeded today and all nine suites built and ran:

```bash
make CC=gcc BUILD=build-stricttest LTO= CFLAGS="-std=c11 -D_GNU_SOURCE -Iinclude -pthread -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wrestrict -Wno-unused-parameter -O2 -DNDEBUG" test
```

**Done:** `make strict-test` now wraps exactly that, plus `-Wrestrict`. All
nine suites build and run clean under it.

**Consequence for reporting:** do not say "all gates pass" on the strength of
`make strict`. That gate covers application code only.

### Live-device evidence — partially durable

What exists, verified today:

| Item | Value |
| --- | --- |
| Command | `./qanat --cf --headless --limit 3 --timeout 3000 --samples 2 --fingerprint chrome --event-log ev.log` |
| Working directory | `/data/local/tmp` on the device |
| git HEAD at run time | `cf7b1876` (tree dirty) |
| Dirty diff stat at run time | **not captured.** The binary predates the final `src/core/cidr.c` edit, so the run does not reflect the current tree |
| Binary SHA-256 | `68a3af60f20f6481e447b78c23591d5bac5a94c2c7f9a779b3733173d2f0db07`, identical for `build-android/qanat` and `/data/local/tmp/qanat` |
| Device model | `23090RA98G` (`zircon`), serial `AYCQ8DMVOVTCDMBI` |
| Android version | 13, SDK 33 |
| Termux version | **not recorded.** Termux is installed but was not used |
| Timestamp | 2026-08-10 22:48 local, from the on-device file mtime |
| SNI | `www.cloudflare.com` |
| Fingerprint | chrome (`fp=0` in the log header) |
| stdout / stderr | **not saved to a file.** Only in the session transcript |
| JSON / CSV | **not produced** |
| Durable artifact | `docs/evidence/device-2026-08-10-chrome-eventlog.tsv`, pulled from the device today |

The pulled event log contains three `stable-after-marker` results with
`colo=FRA`, `version=0x0304`, `suite=0x1301`, which is the evidence that the
compressed-certificate path completes end to end.

**Not claimed:** no reproducible artifact bundle, no stdout capture, no
structured output, no dirty-diff fingerprint at run time. A future device run
should write stdout, stderr, `--json` and `--csv` to files and record the
binary hash and `git diff --stat` alongside them.

## 6. Current Verification State

Legend: **[R]** rerun in the current tree · **[P]** passed earlier in the
session, not rerun since the last edit · **[U]** unavailable here · **[N]** not
run.

| Gate | Command | Result |
| --- | --- | --- |
| GCC strict application | `make CC=gcc strict` | **[R]** rc=0, no warnings |
| All suites | `make CC=gcc BUILD=build-test LTO= test` | **[R]** 10/10 pass |
| Strict **test** build | `make CC=gcc strict-test` | **[R]** 10/10 under `-Werror -Wconversion -Wsign-conversion -Wrestrict` |
| ASan + UBSan | `make CC=gcc sanitize-test` | **[R]** clean |
| TSan | `make CC=gcc tsan-test` | **[R]** 10/10, no races |
| Static analyzer | `make CC=gcc analyze` | **[R]** 0 warnings |
| Fuzz smoke | `make CC=gcc fuzz-smoke` | **[R]** 6/6 targets, 20000 inputs each |
| Fuzz (libFuzzer) | `make CC=clang fuzz` | **[U]** needs a native Clang |
| TLS interop | `make CC=gcc tls-test` | **[R]** 24/24, including 6 large-chain cases |
| PTY / TUI | `make CC=gcc menu-test` | **[R]** ok |
| AArch64 cross, application | NDK clang, section 8 | **[R]** rc=0, full strict warning set |
| AArch64 cross, `test_core` + `test_tls` | NDK clang, section 8 | **[R]** rc=0 |
| On-device suites | `adb shell ./test_core; ./test_tls` | **[R]** both `ok` on `23090RA98G`, Android 13 |
| LTO matrix, GCC | `LTO=auto\|off\|full\|thin\|banana\|<empty>` | **[R]** 6/6 behave as specified |
| LTO matrix, Clang | NDK probe + full ThinLTO cross-build | **[R]** probe yes for both, links |
| Native Clang | — | **[U]** absent in WSL, no network to install |
| AArch64 cross (glibc) | `aarch64-linux-gnu-gcc` | **[U]** toolchain absent |
| QEMU AArch64 | — | **[U]** absent |
| Live device scan | — | **[N]** needs explicit user authorization |

The on-device runs were **offline unit tests**, not scans: no packet left the
handset. A public-network scan still needs the user to ask for it.

## 7. Remaining Mandatory Work

Five issues are untouched, all in the TUI: QN2-041, 043, 044, 045, 046.
Everything else in the QN2 scope is fixed, partial with the gap stated, or a
documented deviation.

| Item | Sev | Source area | Intended invariant |
| --- | --- | --- | --- |
| QN2-041 | high | `src/ui/term.c` | A persistent byte queue with incremental decoding: two keys in one read yield two keys, and an escape sequence may span reads |
| QN2-045 | high | `src/ui/app.c` | Stop, join, drain all rings, account, mark status, finalize, export — in that order |
| QN2-043 | med | `src/ui/term.c` | Real terminal dimensions are preserved and a too-small terminal says so |
| QN2-044 | med | `src/ui/app.c` | Only explicitly requested formats are written |
| QN2-046 | low | `src/ui/app.c` | Each mode shows only its own statistics; re-word the QN2-038 counter labels and surface the QN2-049 discovery counters |

Order: 041 and 045 first, both high. QN2-045 must use `qn_engine_accounted()`
and `qn_engine_state()` from the engine work; QN2-046 must use the new engine
counter names and the new `icmp_attempted` / `icmp_replied` /
`tcp_attempted` / `tcp_completed` fields.

`tests/test_screen.c` links `src/ui/screen.c` alone, so `src/ui/term.c` can
join it without dragging in the app. `tests/test_discover.c` shows the pattern
for reaching file-static logic: compile the unit into the test.

### Limitations carried, not forgotten

- **QN2-009** stays partial: only the `MSG_NOSIGNAL` fix was applied; the other
  three syscall paths were verified correct by inspection but have no
  fault-injection test, because no syscall-interposition layer exists.
- **QN2-028** stays a documented deviation: opaque is the default, the chain is
  never decompressed, and `--cert-strict` refuses instead.
- **QN2-035's merge is entry-granular.** Concurrent writers no longer clobber
  each other's addresses, but where both observed the same address only the
  fresher observation survives.
- **QN2-033 did not add `connect_us` and `request_ttfb_us` columns.** The
  misnaming was the defect and is fixed; the columns are a v3 schema change.
- **QN2-048 sees the main routing table only.** Android's per-network default
  routes live in policy tables that need rtnetlink.
- **QN2-050 is unverified on hardware.** Thermal sysfs is SELinux-denied to the
  shell on the attached device, so throttling is inert there either way.
- **QN2-034's failure branch is unexercised.** Forcing `time()` to fail needs
  the same interposition layer QN2-009 wants.

## 8. Commands for the Next Session

None of these delete or discard anything.

**Baseline**

```bash
cd /c/Users/will/Downloads/Qanat-main/Qanat && git status --short && git diff --stat && git rev-parse HEAD
```

**Rebuild without touching user changes** (writes only into `build-*`)

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc BUILD=build-fresh LTO= all'
```

**All suites**

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc BUILD=build-test LTO= test'
```

**Strict application build**

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc strict'
```

**Strict test build** (no target yet; this is the working invocation)

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc BUILD=build-stricttest LTO= CFLAGS="-std=c11 -D_GNU_SOURCE -Iinclude -pthread -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wrestrict -Wno-unused-parameter -O2 -DNDEBUG" test'
```

**Sanitizers**

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc sanitize-test'
```

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc tsan-test'
```

**Static analyzer**

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc analyze'
```

**Fuzz smoke** (`QN_FUZZ_ITERS` sets the budget, default 20000)

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && QN_FUZZ_ITERS=50000 make CC=gcc fuzz-smoke'
```

**TLS interoperability against local `openssl s_server`**

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc tls-test'
```

**TUI PTY**

```bash
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/c/Users/will/Downloads/Qanat-main/Qanat && make CC=gcc menu-test'
```

**AArch64 / Android via NDK** (this is also the only Clang gate available)

```bash
cd /c/Users/will/Downloads/Qanat-main/Qanat && NDK=/c/Users/will/AppData/Local/Android/Sdk/ndk/27.2.12479018 && CC="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe" && mkdir -p build-android && "$CC" --target=aarch64-linux-android30 -std=c11 -D_GNU_SOURCE -Iinclude -O2 -pthread -DNDEBUG -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter -o build-android/qanat src/*.c src/core/*.c src/data/*.c src/net/*.c src/task/*.c src/ui/*.c src/crypto/*.c src/crypto/arm64/*.c src/crypto/arm64/*.S
```

**Device push and offline suites** (`adb` is not on PATH; `MSYS_NO_PATHCONV=1`
is required or Git Bash rewrites `/data/local/tmp`)

```bash
export PATH="$PATH:/c/Users/will/AppData/Local/Android/Sdk/platform-tools" && export MSYS_NO_PATHCONV=1 && cd /c/Users/will/Downloads/Qanat-main/Qanat && adb push build-android/qanat /data/local/tmp/ && adb shell 'cd /data/local/tmp && chmod 755 qanat && ./qanat --version'
```

`chmod 755` after every push: the executable bit does not survive, and the
failure looks like the program producing no output.

## 9. Continuation Reading Order

Required:

- `docs/HANDOFF.md` — this file
- `docs/REMEDIATION-QN2.md` — per-issue root cause, patch, pre-patch evidence
- `docs/REVIEW-2026-08-10.md` — the first audit and its outcomes
- `docs/ARCHITECTURE.md`
- `docs/TLS.md`

Also relevant:

- `docs/PERFORMANCE.md` — benchmark method; its numbers predate this session
- `docs/evidence/device-2026-08-10-chrome-eventlog.tsv` — the only durable
  artifact from a live scan; the 2026-08-11 device runs were offline unit tests
- `src/net/hpack_huff.h` — RFC 7541 Huffman tables and the bounded decoder
- `src/net/certscan.h` — the streaming TLS 1.2 Certificate framing cursor
- `src/net/outbuf.h`, `src/net/flowmeter.h` — the other two pure units,
  covered by `tests/test_outbuf.c`
- `tests/test_screen.c` — the terminal-injection suite, and the natural home
  for further UI unit tests
- `tests/test_engine.c` — accounting invariants and the `RLIMIT_NOFILE`
  squeeze helper, the closest thing to a fault-injection harness
- `tests/test_task_cf.c` — drives `cf_scan` through its public callback
- `tests/test_menu_pty.py` — PTY driver for the numeric launcher
- `CONTRIBUTING.md` — states the comment rule in section 10

## 10. Source Comment Style

**Mandatory project rule.**

- Every new or modified source comment is short and on **one line**.
- No paragraph comments, block-comment essays, audit narratives, issue
  histories or changelog text in `.c`, `.h` or `.S` files.
- Comment only for a non-obvious invariant, a protocol constraint, memory
  ordering, a bounded-memory rule, an ABI constraint, or a platform quirk.
- Detailed reasoning goes in `docs/HANDOFF.md`, `docs/REMEDIATION-QN2.md`, or
  the final report — never in source.
- Match the surrounding file's style.
- Remove verbose comments your own patches introduced before finishing.
- Preserve legally required licence and attribution comments.

This rule has been corrected repeatedly in this project's history. A patch that
adds an explanatory paragraph to a header will be sent back.

## 11. Assembly Status

- The independent AArch64 assembly-optimization prompt **has not been run.**
- Assembly work **must wait** until QN2 correctness is complete. Optimizing
  code whose protocol validation is still changing wastes the measurement.
- **No assembly benchmark baseline should be treated as final.** The figures in
  `PERFORMANCE.md` and in the previous hand-off were taken before this
  session's changes and before the current dirty tree existed.
- When it does start: take a fresh baseline at a stable checkpoint, on a cool
  handset, comparing scalar against assembly **in one session** with
  `QN_NO_ASM=1`, because the device throttles roughly 20% after repeated runs.
- Concerns already recorded, not to be expanded into implementation now:
  SHA-384 measures the same with and without assembly because there is no
  SHA-512 kernel; ChaCha20 is NEON but Poly1305 is scalar; a previously written
  single-block NEON ChaCha measured at parity with C and was removed.

## 12. Exact Next Action

**Start with QN2-041, then QN2-045, then 043, 044, 046.** Those five TUI issues
are all that remain in the QN2 scope; nothing else needs re-verifying first.

### First-audit regression pass, run 2026-08-11

`scripts/check_first_audit.sh` re-checks every outcome recorded in
`REVIEW-2026-08-10.md` against the current tree: **27 checks, 0 failures.** All
four blockers, all three high items, the four smaller items and all seven
removed constructs are intact. No first-audit fix was redesigned or reopened.

Two checks were wrong on their first run and were corrected, not the code:
`qn_aes_gcm_setkey` is declared in `src/crypto/aead_impl.h` rather than
`include/qanat/crypto.h`, and `exhausted` matched the word in a comment
rather than the removed struct field. Re-run the script after any change that
touches the engine, the CIDR loader or the entropy paths.

### Two habits worth keeping

- **Reproduce before patching, by building the old code rather than reasoning
  about it.** Copying one file, reverting a single hunk in the copy, and
  rebuilding the suite against it produced exact counts — 69, 27, 9, 9, 8, 7 —
  and more than once showed the defect differed from the issue text.
- **Distrust a test that passes.** Four tests in this repository asserted the
  defect rather than the fix, and one used input that was never valid. When a
  test defends surprising behaviour, check the input before trusting the
  oracle.
