# Second audit remediation, QN2-001 .. QN2-051

> **Authoritative continuation, 2026-08-11.** The section below records the
> observation-model and external-defect work based on `8c81896` on
> `qn2-remediation`. The older `cf7b1876`/`master` material remains below as
> historical evidence; it is not the current repository snapshot.

## Observation-model continuation and external defects 1..18

### Repository and preservation boundary

| Field | Recorded value |
| --- | --- |
| Starting HEAD | `8c8189647cd6145492e3fb662e958df7446f5783` |
| Branch | `qn2-remediation` |
| Starting tracked diff | none |
| Commit | none; the user did not request one |
| Public scan | not run; no explicit public-network authorization was given |

### Architectural contract now enforced

The verifier now has one directional fact pipeline:

```text
transport facts -> TLS facts -> canonical HTTP facts -> edge policy
                -> flow/stability facts -> pure classifier -> consumers
```

- `qn_observation` owns transport, TLS, canonical HTTP, edge, flow, stability,
  and terminal facts.
- HTTP/1 and HTTP/2 emit `qn_http_event`; neither parser knows what a
  Cloudflare marker means or writes a classification.
- `qn_observation_classify()` has no socket, clock, allocation, or I/O input.
- Classification is the pair `highest_rung_reached` plus `terminal_outcome`.
  A terminal failure cannot coexist with a displayed successful rung.
- The store, TUI, headless output, JSON, CSV, event log, task accounting, and
  export eligibility all derive their display label from the same pair.
- A repository search for `CF_V_` or `QN_VER_` returns no matches. A search for
  `.verdict`, `->verdict`, or a verdict assignment finds only a benchmark
  format string, not a parser mutation.

The classifier table in `test_ladder_rules` covers successful rungs and local,
peer, path, protocol, unsupported, reset, timeout, interference, and
inconclusive terminals. Canonical HTTP edge-policy tests feed both protocol
shapes through the same function.

### Reproduction evidence from the old implementation

The old implementation was compiled from copied pre-patch sources; the working
tree was not reset. These are the exact aggregate results recorded before the
replacement code was linked:

| Reproducer | Old result | Post-patch result |
| --- | --- | --- |
| core HTTP/classifier reproducer | exit 1, **12 failing checks** | `core tests: ok` |
| TLS sequencing/framing reproducer | exit 1, **10 failing checks** | `tls tests: ok` |
| fingerprint NULL-output subprocess | **SIGSEGV**, exit 139 | NULL rejected, suite passes |
| event-drop ownership reproducer | exit 1, **1 failing check**; observed double count | exactly one drop, suite passes |

The failing core checks covered malformed HTTP after a successful TLS rung,
the eleventh invalid H2 setting, 103 followed by 200, coalesced END_STREAM plus
GOAWAY, the advertised header cap, and the five HTTP/1 ambiguity cases. The TLS
checks covered the one-byte/empty/oversize/malformed TLS 1.3 Certificate
shapes, plaintext Alert after traffic keys, illegal TLS 1.2 NewSessionTicket
ordering, random shape, Safari pinning, and invalid fingerprint mapping. The
temporary raw reproducer logs were not added to the repository; the counts and
process result above are the durable record.

### External issue matrix

#### Fixed

| ID | Closure | Regression contract |
| --- | --- | --- |
| 1 | A pure classifier gives terminal failure precedence over any earlier successful rung. | `test_ladder_rules` |
| 2 | `qn_request_gate` distinguishes not queued, queued, and fully flushed; early app data is rejected/quarantined and TTFB starts at the final wire byte. | `test_request_gate_quarantines_until_wire_complete` |
| 3 | Headless and TUI natural completion, `x`, `q`, and interrupt share stop/join/drain/account/finish/export teardown. | `test_finalize_drains_after_join`, PTY suite |
| 4 | TLS 1.3 Certificate is streamed through context/list/entry/extensions framing, a cumulative cap, and a non-empty-entry rule. | `test_tls13_certificate_framing` |
| 5 | Plaintext Alert is rejected once TLS 1.3 read keys are live. | `test_tls13_rejects_plaintext_alert_after_keys` |
| 6 | TLS 1.2 NewSessionTicket is accepted only in its legal post-handshake sequence and its framing is checked. | `test_tls12_new_ticket_sequence` |
| 7 | Every H2 SETTINGS tuple is validated, not just the first ten. | `test_http2_settings_validation` |
| 8 | Informational heads remain provisional; a following final 200 owns the response head. | `test_http2_informational_then_final` |
| 9 | Stream facts are committed before connection GOAWAY state is reported. | `test_http2_end_stream_survives_coalesced_goaway` |
| 10 | H2 advertises the bounded 8 KiB header-list capacity it can parse. | `test_http2_advertises_parser_capacity` |
| 11 | The SPSC ring is the sole drop owner; accounting uses saturating `qn_engine_accounted()`. | `test_event_drop_has_one_owner`, `test_accounting_difference_saturates` |
| 12 | HTTP/1 rejects trailing TE commas, invalid chunk extensions, TE+CL, invalid field-name tokens, and multiple final responses. | `test_http1_rejects_ambiguous_framing` |
| 13 | Unused `qn_store.dirty` state was removed. | strict/analyzer build |
| 14 | Non-enforcing H2 fields were removed; retained state has a parser invariant or emitted fact. | core H2 suite |
| 15 | Versioned cross-layer profiles shape TLS, H2 settings/window/order, pseudo headers, regular headers, User-Agent, Accept, and HTTP/1. | `test_full_profile_snapshots`, `fingerprint show` |
| 16 | `random` materializes a randomized shape; Safari and every full profile are pinned; NULL/invalid fingerprint APIs fail explicitly. | `test_random_is_a_shape`, `test_fp_parse`, known snapshots |
| 17 | Active transfers and stability holds have independent capacities/counters; a hold releases the active slot immediately and FD pressure produces an explicit capacity-limited fact. | `test_stability_pool_plan` |
| 18 | Silent open banners remain open with connect latency; TCP discovery is port-major; ICMP drains after sends, during stalls, and at completion. | `test_silent_banner_preserves_open`, `test_tcp_sweep_is_port_major`, discovery suite |

#### Partial

None of defects 1..18 is partially patched. The throughput effect of defect
17 is deliberately **not claimed as measured**: the scheduling invariant is
tested, but an authorized, thermally controlled A-B-A public-route benchmark
was outside this run.

#### Documented deviations

None. Quarantining application bytes after request queueing but before the
final wire byte is one of the two behaviours explicitly permitted by defect 2.

#### Remaining

No code defect from 1..18 remains open. Definition-of-done item 4 remains
unverified for this revision: no authorized public Cloudflare scan was run, so
there is no current-revision `stable-after-marker` network observation. The
smallest next action is one explicitly authorized, low-limit device scan using
the exact staged binary hash recorded in `HANDOFF.md`.

#### Refuted

None. All 18 reports reproduced either directly or as part of the compiled old
source reproducer groups.

### Cross-layer fingerprint snapshots

The snapshot hash covers ClientHello bytes, JA3 string/hash, JA4, H2 SETTINGS,
connection window, pseudo-header order, regular-header order, H2 request bytes,
HTTP/1 request bytes, User-Agent, Accept, and Accept-Encoding.

| Profile | SHA-256 snapshot |
| --- | --- |
| `chrome-android-126` | `36aa28629dfb30f207a793aa0df565c0da3e2ec5db39e5f7b3d5a2d9c2f35bfd` |
| `firefox-android-127` | `d4b07677ca68f56f228cf2e4a2284447e12b0647986d05a10482613463634cba` |
| `safari-ios-17` | `811fe3d8fe9da50e2d948743c2acafae0b442218d72b140b498117d6195d2c5d` |
| seeded `random` | `9567d58ceafccf986e92af8b901cec6d95a74d6e362d8d1a3ce1f690614c6300` |

`qanat fingerprint show safari-ios-17 | sha256sum` produced
`4aa603c3fe53ecd11df685c8d9d4532ad8b78c430bda6936c4867a36805ad36f`
on both x86 and the staged AArch64 device binary.

### Current gate evidence

| Gate | Result |
| --- | --- |
| GCC normal | 11/11 suites pass |
| GCC strict application | builds with `-Werror -Wconversion -Wsign-conversion` |
| GCC strict tests | 11/11 suites pass |
| GCC analyzer | application links, 0 remaining diagnostics |
| ASan+UBSan | 11/11 suites pass |
| TSan | 11/11 suites pass |
| OpenSSL interop | 24/24 TLS 1.2/1.3/profile/large-chain cases pass |
| Menu PTY | `menu PTY tests: ok` |
| Fuzz smoke | 6 targets x 20,000 inputs, all pass |
| First-audit guard | 27 ok, 0 failed |
| NDK Clang strict cross-build | application plus 13 test binaries, API 30, rc=0 |
| ELF branch protection | all 14 AArch64 executables report `BTI, PAC` |
| Device offline | 13/13 suites pass, including crypto ABI and differential |

The analyzer initially reported `greases_from()` as potentially reading an
uninitialized nibble. The fixed array is now explicitly zero-initialized; the
complete analyzer rerun is green. The first AArch64 link also exposed two
Makefile-only defects: omitted `sha512_ce.S` and reduced SHA-2 test link sets
without accelerator objects. Both were repaired before any device claim.

### Output-schema migration

- JSON schema is **4**, raised from 3.
- Cloudflare result objects keep the derived display string `verdict` for
  readers, and add authoritative `highest_rung_reached` and
  `terminal_outcome` fields. Consumers must use the pair for logic.
- CSV adds the same two columns immediately after `verdict`; positional CSV
  readers must update their column mapping.
- Event-log rows now record derived classification, rung, and terminal
  separately, and the header records active/stability capacities.
- The history store remains `QN_STORE_SCHEMA=2`; no stored field changed
  meaning, so no history migration or rewrite is required.
- Schema-3 JSON readers must reject or explicitly adapt schema 4 rather than
  silently treating the derived display label as the old enum.

## Phase 0 baseline, recorded before any source change

| | |
| --- | --- |
| HEAD | `cf7b1876` on `master` |
| Working tree | clean, 0 modified, 0 untracked |
| Size | 24,342 lines of C, headers and assembly |
| Host | MSYS2 on Windows 11; builds run in WSL2 Ubuntu, `Linux 6.6.114.1` |
| Compiler | `gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0`, GNU Make 4.4.1 |
| Clang | **absent in WSL and not installable there (no network).** Clang gate runs on the handset under Termux, and cross via NDK r27c. |

The audit's snapshot hints (`3ac8afa`, 33 modified files, `tests/test_engine.c`
untracked) are stale: that work was committed in `832eadb` and `cf7b1876`.
There is no dirty user change to preserve.

### Commands discovered

| Purpose | Command |
| --- | --- |
| Normal build | `make CC=gcc` |
| Strict build | `make CC=gcc strict` |
| Tests | `make CC=gcc BUILD=build-test LTO= test` |
| ASan + UBSan | `make CC=gcc sanitize-test` |
| TSan | `make CC=gcc tsan-test` |
| Static analysis | `make CC=gcc analyze` |
| TLS interop | `make CC=gcc tls-test` |
| TUI PTY | `make CC=gcc menu-test` |
| Fuzz | `make CC=gcc fuzz-smoke`, `make CC=clang fuzz` |
| Everything | `make CC=gcc check` |

### Baseline results, before any change

| Gate | Result |
| --- | --- |
| `make CC=gcc strict` | rc=0 |
| `make CC=gcc BUILD=build-test LTO= test` | rc=0, 7/7 suites pass |
| `make CC=gcc menu-test` | rc=0 |
| `make CC=gcc tls-test` | rc=0, 18/18 cases |
| `make CC=gcc analyze` | rc=0, 0 warnings |

Suites passing at baseline: `test_core`, `test_crypto`, `test_tls`,
`test_props`, `test_engine`, `test_verify`, `test_export`.
Failing: none. Skipped: none.

Tests whose oracle is demonstrably wrong at baseline are recorded per issue
below as they are found; each is replaced rather than deleted.

## Issue matrix

Status values: `todo`, `in progress`, `fixed`, `blocked`.

| ID | Severity | Files | Status |
| --- | --- | --- | --- |
| QN2-001 | critical | `src/net/verify.c` | **fixed** |
| QN2-002 | critical | `src/core/timewheel.c` | **fixed** |
| QN2-003 | high | `src/core/timewheel.c` | **fixed** |
| QN2-004 | critical | `src/net/http2.c`, `src/net/verify.c` | **fixed** |
| QN2-005 | critical | `src/task/task_cf.c` | **fixed** |
| QN2-006 | high | `src/main.c`, `src/export.c`, `src/core/store.c` | **fixed** (pre-existing; verified) |
| QN2-007 | critical | `src/net/engine.c` | **fixed** |
| QN2-008 | critical | `src/net/engine.c`, `src/main.c` | **fixed** |
| QN2-009 | critical | `src/net/verify.c` | **fixed** (D patched; A,B,C already correct) |
| QN2-010 | high | `src/net/verify.c` | **fixed** |
| QN2-011 | critical | `src/task/task_discover.c` | **fixed** (nonce + consumption) |
| QN2-012 | high | `src/net/verify.c` | **fixed** |
| QN2-013 | critical | `src/net/http2.c` | **fixed** |
| QN2-014 | high | `src/net/http2.c` | **fixed** |
| QN2-015 | critical | `src/net/hpack_huff.h`, `src/net/http2.c` | **fixed** (full RFC 7541 decoder) |
| QN2-016 | high | `src/net/http2.c` | **fixed** |
| QN2-017 | high | `src/net/http2.c` | **fixed** |
| QN2-018 | high | `src/net/http2.c` | **fixed** |
| QN2-019 | high | `src/net/http2.c` | **fixed** |
| QN2-020 | high | `src/net/http1.c` | **fixed** |
| QN2-021 | high | `src/net/http1.c` | **fixed** |
| QN2-022 | medium | `src/net/http1.c` | **fixed** |
| QN2-023 | medium | `src/net/probe_http.c` | **fixed** |
| QN2-024 | critical | `src/net/probe_http.c` | **fixed** |
| QN2-025 | high | `src/net/tls12.c`, `src/net/tls13.c` | **fixed** (framing + semantics) |
| QN2-026 | high | `src/net/certscan.h`, `src/net/tls12.c` | **fixed** (streaming validator) |
| QN2-027 | high | `src/net/tls13.c` | **fixed** |
| QN2-028 | high | `src/net/tls13.c` | **documented-deviation** (opaque default, strict mode exists) |
| QN2-029 | medium | `src/net/tls12.c` | **fixed** |
| QN2-030 | medium | `src/crypto/aead.c` | **fixed** |
| QN2-031 | high | `src/core/cidr.c` | **fixed** (pre-existing; diagnosis improved) |
| QN2-032 | medium | `src/core/cidr.c` | **fixed** |
| QN2-033 | high | `src/core/store.c`, `src/task/task_cf.c` | **fixed** (naming + schema) |
| QN2-034 | medium | `src/core/util.c`, `src/task/task_cf.c` | **fixed** |
| QN2-035 | high | `src/core/store.c` | **fixed** (entry-granular merge) |
| QN2-036 | medium | `src/core/store.c` | **fixed** |
| QN2-037 | high | `src/net/engine.c` | **fixed** |
| QN2-038 | medium | `src/net/engine.c` | **fixed** |
| QN2-039 | high | `src/net/verify.c` | **fixed** |
| QN2-040 | medium | `src/net/engine.c` | **fixed** |
| QN2-041 | high | `src/ui/term.c` | todo |
| QN2-042 | critical | `src/ui/screen.c` | **fixed** |
| QN2-043 | medium | `src/ui/term.c` | todo |
| QN2-044 | medium | `src/ui/app.c` | todo |
| QN2-045 | high | `src/ui/app.c` | todo |
| QN2-046 | low | `src/ui/app.c` | todo |
| QN2-047 | critical | `src/export.c`, `src/net/probe_http.c`, `src/net/verify.c` | **fixed** |
| QN2-048 | medium | `src/core/netinfo.c` | **fixed** (metric + operstate) |
| QN2-049 | low | `src/task/task_discover.c` | **fixed** |
| QN2-050 | medium | `src/core/cpuinfo.c`, `src/net/engine.c` | **fixed** (unverified on device) |
| QN2-051 | medium | `Makefile` | **fixed** |

## Completed issues

### QN2-002 — time wheel misses expired deadlines after a full revolution

- **Files** `src/core/timewheel.c`, `include/qanat/timewheel.h`
- **Root cause** `cursor` was stored modulo `QN_TW_SLOTS`, so `want` and
  `cursor` collide after exactly one revolution and the sweep inspects a
  single slot. Zero elapsed revolutions and N elapsed revolutions are
  indistinguishable in that representation.
- **Invariant** every node whose `deadline_ms <= now_ms` is returned by the
  first `qn_tw_expire` at or after that time, whatever the clock jump.
- **Implementation** `cursor` became the absolute `cursor_tick`. A jump of a
  revolution or more clamps to `now_tick - (QN_TW_SLOTS - 1)`, so the sweep
  visits every slot exactly once and a 60-second jump costs no more than an
  8-second one. Re-arm inside the sweep provably lands past `now_tick`, so the
  loop terminates.
- **Test** `test_timewheel_revolution_jump`, `_multiple_revolutions`,
  `_clock_edges`, `_rearm_during_expiry` in `tests/test_props.c`.
- **Pre-patch evidence** jumps of 8192, 8193 and 16384 ms each printed
  `hid an overdue deadline`; `popped == N` failed for nodes spread over
  several revolutions.
- **Status** fixed. **Residual risk** none known; monotonic rollback is now an
  explicit no-op with a test.

### QN2-003 — `qn_tw_next_timeout` wakes workers every 8 ms

- **Files** `src/core/timewheel.c`
- **Root cause** the function returned `min(cap, QN_TW_TICK_MS)` whenever
  anything was armed, so the sleep hint never reflected the actual deadline.
- **Second defect found by the model test** returning a slot boundary would
  also sleep *past* a deadline closer than one tick. The oracle was kept and
  the implementation corrected rather than the assertion relaxed.
- **Implementation** the hint scans forward only `cap / QN_TW_TICK_MS + 2`
  slots, which is exactly the window a deadline within `cap` can round into,
  and reads the real `deadline_ms` values there. Empty window returns `cap`.
- **Test** `test_timewheel_next_timeout_model` compares against a reference
  linear-scan model over 400 pseudo-random rounds;
  `test_timewheel_wakeup_budget` pins the measurement.
- **Measurement** one silent connection, 8 s deadline, 50 ms cap:

  | | wakeups |
  | --- | --- |
  | before | 1000 |
  | after | 160 |

  The remaining 160 is the caller's own 50 ms safety cap, not the wheel.
- **Status** fixed. **Residual risk** a caller passing a very large `cap`
  scans at most `QN_TW_SLOTS` slots; bounded and measured.

### QN2-005 — CF scan capacity and callback boundary disagree

- **Files** `src/task/task_cf.c`, `include/qanat/task.h`
- **Root cause** allocation used `min(cf_limit, CF_DEFAULT_CAP)` while
  `cf_on_sweep` bounded writes with the raw `cfg->cf_limit`. The CLI clamps
  `--limit` to 16384, so only a direct API caller reaches it.
- **Implementation** `cf_scan.limit` is normalised once in `cf_scan_init` to
  `min(cf_limit, cap)`, and every boundary now uses `s->limit` with a hard
  `s->n >= s->cap` backstop. Memory safety no longer depends on the CLI.
- **Test** `tests/test_task_cf.c`, new suite, driven through the public task
  callback rather than the engine.
- **Pre-patch evidence** `wrote 16385 records into a capacity of 16384`, and
  the run would have continued to 21384.
- **Note** ASan does **not** trap this: the arrays are suballocated from one
  arena mapping, so the overflow silently corrupts `finalist`, `active`,
  `spr` and `rtt_baseline_us`. The bounds check is the only defence, which is
  why the test asserts on `s.n <= s.cap` directly.
- **Status** fixed. **Residual risk** other arena-backed arrays deserve the
  same audit; tracked under QN2-007 work.

### QN2-007 — pending and claimed jobs disappear during stop or fatal exit

- **Files** `src/net/engine.c`, `include/qanat/engine.h`
- **Root cause** worker exit terminated active probes only. `pending_job` and
  the unused tail of a reserved `QN_CLAIM_CHUNK` were dropped. The tail matters
  because indices come from a *shared* cursor: no other worker will ever draw
  them.
- **Invariant** `claimed == completed + unattempted`, where `claimed` is every
  index reserved from the cursor that lies inside the domain.
- **Implementation** `worker_retire()` terminates active probes, gives the
  pending job a typed terminal event (CANCELLED normally, ERROR/LOCAL under a
  fatal), and counts the unreserved tail as both claimed and unattempted.
  `qn_engine_accounted()` exposes the invariant.
- **Test** `check_accounted()` plus `test_stop_accounts_for_everything` in
  `tests/test_engine.c`, which compares against `e->cursor` directly.
- **Pre-patch evidence** `stop: reserved 64 indices but only claimed 40` —
  24 indices inside the domain vanished with no record.
- **Note** my first version of this test passed against the broken code,
  because it compared claimed against completed rather than against what the
  cursor had reserved. The oracle was corrected, not the assertion dropped.
- **Status** fixed. **Residual risk** requeueing the tail instead of counting
  it would recover the work; counting was chosen because pushing indices back
  onto a lock-free shared cursor is racy. Recorded as a deliberate trade.

### QN2-008 — fatal engine failure is not propagated to the task

- **Files** `src/net/engine.c`, `include/qanat/engine.h`, `src/main.c`
- **Implementation** explicit `qn_engine_status`
  (IDLE/RUNNING/COMPLETE/CANCELLED/FATAL) settled in `qn_engine_join` once
  every worker has retired, alongside the existing `fatal_errno` and
  `fatal_worker`. Headless already gated verification on `rc != 3`; it now also
  refuses to finalise when claimed work is unaccounted for, and reports
  unattempted candidates with the run status and a non-zero exit.
- **Test** `test_stop_accounts_for_everything` asserts the CANCELLED
  transition; `qn_engine_state` is checked RUNNING then CANCELLED.
- **Status** fixed for the status model and the headless path. **Remaining**
  the EBADF injection test and the TUI/headless agreement check need the
  fault-injection layer from Phase 11F; tracked with QN2-009.

### QN2-037 — rate tokens are consumed before a network launch exists

- **Files** `src/net/engine.c`
- **Root cause** `tokens_take()` debited before domain exhaustion, before
  `task->next()`, and before `probe_launch()`. A pending retry burned a fresh
  token on every attempt for the same logical job.
- **Implementation** split into `tokens_ready()` (refill and test) and
  `tokens_debit()`, called only after a socket reached the network.
- **Test** `test_tokens_track_attempts`.
- **Evidence** `tokens: 384 claimed, 384 issued, 42 launch retries` — 42 local
  failures cost nothing, and `issued == claimed` still holds.
- **Status** fixed. **Residual risk** none known.

### QN2-038 — one logical job counted as many unrelated errors

- **Files** `src/net/engine.c`, `include/qanat/engine.h`, `src/main.c`
- **Root cause** a single `errors` counter absorbed socket failures,
  `epoll_ctl` failures, ring-push failures, terminal job errors and
  `epoll_wait` failures.
- **Implementation** replaced with `local_launch_failures`,
  `syscall_failures`, `terminal_job_failures`, `protocol_failures`,
  `events_dropped`, `unreach`, plus derived `network_failures`.
- **Test** `test_counters_separate_retries_from_outcomes` asserts the
  partition `open + network_failures + terminal_job_failures + cancelled ==
  completed`.
- **Status** fixed. **Remaining** the TUI labels still read from the snapshot
  but have not been re-worded; folded into QN2-046 UI work.

### QN2-040 — `qn_engine_stats` casts away const and mutates state

- **Files** `src/net/engine.c`, `include/qanat/engine.h`, `src/main.c`,
  `src/ui/app.c`
- **Implementation** `qn_engine_stats` is a pure snapshot taking a real
  `const qn_engine *`. Rate sampling moved to `qn_engine_rate_sample()`, an
  explicitly mutating owner-thread call guarded by `rate_lock`, with
  `rate_ewma` atomic so readers never tear. `hl_progress` became non-const
  rather than hiding the mutation behind a cast.
- **Test** `test_concurrent_stats_readers` runs three reader threads against a
  live engine.
- **Pre-patch evidence**
  `SUMMARY: ThreadSanitizer: data race src/net/engine.c:1381 in qn_engine_stats`
- **Status** fixed; TSan clean after the patch.

### QN2-001 — deep verifier stops after the first failed batch

- **Files** `src/net/verify.c`, `include/qanat/verify.h`
- **Root cause** when every connection in the slot batch failed at *dial* time
  and retired, `live` reached zero while `next < n`. The `!live` branch treated
  that as terminal and broke out with `EIO`, abandoning the rest.
- **Implementation** `!live` is terminal only when `next >= n`; otherwise the
  loop refills. Progress is guaranteed because every failed dial advances both
  `next` and `done`.
- **Accounting** `qn_verify_status` gained `cancelled` and `unattempted`. At
  exit every candidate is typed: dialed-and-finished, dialed-and-cut-short
  (CANCELLED or LOCAL with the fatal errno), or never dialed. The invariants
  `attempted + unattempted == n` and `completed + cancelled == attempted` are
  asserted by the tests.
- **Test** `test_failed_batch_does_not_abandon_the_rest` (n=5, concurrency=2,
  unroutable addresses so the dial fails synchronously) and
  `test_cancel_types_every_candidate`.
- **Pre-patch evidence** `batch abandoned as infrastructure failure, errno 5`
  and `only 2 of 5 candidates were attempted (3 unattempted)`.
- **Note** the first version of this test used a closed loopback port, where
  connect() completes asynchronously and the `!live` path is never reached, so
  it passed against the broken code. The address was changed to reserved space
  to make the dial fail synchronously.
- **Status** fixed. **Residual risk** none known.

### QN2-009 — verifier ignores critical syscall failures

- **Files** `src/net/verify.c`
- **A, epoll_ctl MOD** already handled: `arm()` returns bool and every caller
  converts a failure into a typed local infrastructure failure. Verified by
  inspection, no change needed.
- **B, fatal epoll_wait** already handled: `EINTR` retries, anything else sets
  infrastructure failure and breaks. No busy-loop to deadline. No change.
- **C, EINTR on read/send** already handled in the read path and in
  `flush_out`. No change.
- **D, SIGPIPE** **was open.** `flush_out` used `write()`, so a peer closing
  mid-request could kill a headless process that never installs the TUI's
  handler. Changed to `send(..., MSG_NOSIGNAL)`, matching `engine.c` and
  `netinfo.c`.
- **Status** D fixed; A, B and C confirmed already correct in the current tree
  and recorded as such rather than re-patched. **Remaining** the per-syscall
  fault-injection tests need the Phase 11F layer; the SIGPIPE change is
  currently covered only by the existing loopback suites.

### QN2-010 — verifier output buffer is not a real sliding buffer

- **Files** `src/net/outbuf.h` (new), `src/net/verify.c`
- **Root cause** `queue()` tested `outlen + n > sizeof out` while a partial
  write left a consumed prefix at `[0, outoff)`. That capacity was real but
  unreachable, so the buffer reported "full" with room free and the request
  was lost.
- **Implementation** extracted into `qn_outbuf`, a compaction buffer with
  `queue`/`consume`/`head`/`pending`/`tail`/`commit`. `queue` compacts before
  measuring; `consume` clamps; `commit` clamps; the TLS record layer fills the
  tail in place through `qn_outbuf_tail`.
- **Why extract** the logic was `static` inside a 1100-line file that only
  runs against real sockets. As a header it is directly testable, which is
  what the audit's six required cases need.
- **Test** `tests/test_outbuf.c`, new suite: prefix reuse, one-byte writes,
  interleaved partial writes over 64 rounds with byte-order verification,
  exact capacity, overflow rejection, over-consume clamping, tail room.
- **Pre-patch evidence** three assertions failed, including
  `qn_outbuf_queue(&b, c, sizeof c)` returning false with 10 of 16 bytes free.
- **Status** fixed. **Residual risk** none known.

### QN2-004 — stream 3 data accepted before the flow request

- **Files** `src/net/http2.c`, `include/qanat/http2.h`, `src/net/verify.c`
- **Root cause** there was no notion of which streams existed. Any stream id
  could carry DATA, and those bytes became `flow_bytes` and therefore flow
  evidence.
- **Implementation** explicit per-stream state
  (IDLE/OPEN/HEADERS/CLOSED). `qn_h2_open_stream()` is called by the verifier
  at the moment each request is written, so stream 1 is legal only after the
  trace request and stream 3 only after the flow request. `begin_frame()`
  rejects DATA, HEADERS, CONTINUATION, RST_STREAM and PUSH_PROMISE on any
  stream that is not open, including server-initiated even streams.
- **Test** `test_http2_unopened_streams`, which includes the audit's exact
  reproducer.
- **Pre-patch evidence** `DATA stream 3` before any flow request returned
  `QN_H2_OK` and produced a stream event carrying its bytes; two assertions
  failed, plus RST on an unopened stream and DATA before a head.
- **Status** fixed.

### QN2-016 — invalid SETTINGS values are accepted

- **Files** `src/net/http2.c`
- **Root cause** length, ACK and multiple-of-six were checked, but the payload
  was never parsed, so no value was ever range-checked.
- **Implementation** `check_settings()` validates ENABLE_PUSH ∈ {0,1},
  INITIAL_WINDOW_SIZE ≤ 2^31−1 and MAX_FRAME_SIZE ∈ [16384, 16777215] before
  the ACK is emitted.
- **Test** `test_http2_settings_validation`, including the required
  `SETTINGS_ENABLE_PUSH = 2` reproducer, which must not be acknowledged.
- **Status** fixed. **Residual risk** duplicate settings within one frame are
  accepted last-wins; the values are still each validated.

### QN2-017 — stream 1 can finish without a response head

- **Files** `src/net/http2.c`
- **Implementation** `complete_hblock()` requires exactly one `:status` in the
  first header block of a stream before `head_done` is set, and DATA is
  rejected outright until then. END_STREAM closes the stream but cannot
  manufacture a head.
- **Test** `test_http2_response_head_rules` (no `:status`, two `:status`) and
  the DATA-before-head case in `test_http2_unopened_streams`.
- **Status** fixed.

### QN2-018 — pseudo-header ordering and duplication not enforced

- **Files** `src/net/http2.c`
- **Implementation** the header-block scan now rejects a second `:status`, any
  pseudo-header after a regular field, request pseudo-headers in a response
  (static indices 1..7), uppercase literal field names, the connection-specific
  fields (`connection`, `keep-alive`, `proxy-connection`,
  `transfer-encoding`, `upgrade`), and every pseudo-header in trailers.
- **Test** `test_http2_response_head_rules`, one case per rejected form.
- **Gap found and closed this session** every one of those rules was reachable
  only for *plain* names. A Huffman-coded name skipped the scan entirely, so
  the duplicate-`:status`, lowercase, forbidden-header and trailer rules were
  all bypassable by encoding the name. Closed by QN2-015's decoder; the
  reproduction table is in the QN2-015/018 evidence section below.
- **Status** fixed.

### QN2-013, QN2-014 — HPACK index and table-size bounds

- **Assessment** already correct in the current tree: indexed fields are
  bounded to `1..61`, literal name indices to `≤ 61`, dynamic-table size
  updates must be zero and must precede any field, and incremental indexing is
  rejected outright. Verified by inspection and by the pre-existing
  `test_http2_strict_hpack_and_credit_retry`, which covers the required
  "indexed field 62 with table size zero" and "size update = 1" reproducers.
- **Change made** at most two consecutive size updates are now allowed, per
  RFC 7541 4.2, instead of unlimited.
- **Status** fixed, mostly pre-existing; recorded rather than re-patched.

### QN2-015 — invalid HPACK Huffman input is not validated

- **Files** `src/net/hpack_huff.h` (new), `src/net/http2.c`, `Makefile`
- **What was wrong** three successive shapes, all wrong. Originally Huffman
  strings were silently skipped. The first remediation made any Huffman string
  in a position that must be understood return `QN_H2_UNSUPPORTED`, which
  aborted every real Cloudflare response on-device. The second narrowed that to
  Huffman `:status` *values* only, leaving Huffman **names** entirely
  unvalidated — the state this session found.
- **Blocker resolved** the RFC 7541 Appendix B table is no longer unobtainable.
  `https://www.rfc-editor.org/rfc/rfc7541.txt` was fetched on the Windows host
  (117,827 bytes, SHA-256
  `2239D7F8FB839B69AE2E928E685559B11376888269F131512197A0E3BACF7F7A`) and the
  table extracted mechanically rather than transcribed.
- **Table trusted only after it proved itself** the extractor asserts, for all
  257 rows, that the printed bit string matches both its hex value and its
  declared length; that the code is prefix-free; that per-length codes are
  consecutive and follow the canonical first-code recurrence; and that the
  **Kraft sum is exactly 1.0**. A single transcription error breaks either
  prefix-freeness or the Kraft sum, so this rules out the failure mode that
  blocked the previous session.
- **Implementation** `qn_huff_decode()` walks the input bit-serially against
  canonical `huff_count` / `huff_first_code` / `huff_first_index` / `huff_sym`
  tables. It rejects EOS inside a string (RFC 7541 5.2), padding of eight bits
  or more, and padding that is not an EOS prefix. Output is bounded by the
  caller's buffer and by `QN_HUFF_MAX_OUT`; a string longer than the buffer is
  still validated end to end and measured, so no field is skipped for being
  large. `has_upper` is tracked over the whole string, so RFC 9113 8.2.1
  lowercase enforcement holds at any length without unbounded storage.
- **Wiring** `hstr` now always holds plain bytes: `pull_hpack_string` decodes
  into a caller buffer (`QN_HPACK_NAME_MAX` 256, `QN_HPACK_VALUE_MAX` 32). All
  `huffman` special cases are gone from `eq_ascii_ci`, `name_is_lowercase` and
  `status_from_value`, and the bypass in `parse_hpack` is deleted. The dead
  `hblock_scan.unsupported` field and its branch in `complete_hblock` were
  removed with it.
- **Tests** `test_hpack_huffman_vectors` (all 8 RFC C.4/C.6 strings, five
  malformed inputs, truncation, validate-only, `has_upper`) and a rewritten
  `test_http2_huffman_handling`.
- **Status** fixed.

### QN2-015/018 — pre- and post-patch evidence

Probe over the real `qn_h2_feed` path, same binary shape before and after
(`rc: 0=OK 1=PROTOCOL 2=SPACE 3=UNSUPPORTED`):

| Case | Before | After | Wanted |
| --- | --- | --- | --- |
| A duplicate `:status` via Huffman name | `rc=0 head=1` | `rc=1 head=0` | reject |
| B forbidden `connection` via Huffman name | `rc=0 head=1` | `rc=1 head=0` | reject |
| C Huffman name containing EOS | `rc=0 head=1` | `rc=1 head=0` | reject |
| C2 Huffman name with non-EOS padding | `rc=0 head=1` | `rc=1 head=0` | reject |
| D Huffman `:status` value, RFC C.6.1 shape | `rc=3 head=0` | `rc=0 head=1 status=302` | accept |
| E uppercase name via Huffman | `rc=0 head=1` | `rc=1 head=0` | reject |
| F valid Huffman `cf-ray` name and value | `rc=0 head=1` | `rc=0 head=1` + `EV_EDGE` | accept |
| G pseudo-header in trailers via Huffman | `rc=0 head=1` | `rc=1 head=0` | reject |

Six wrong verdicts, one false rejection of legitimate traffic (D), and one lost
edge marker (F, whose `cf-ray` name was never read).

**The old test asserted the old defect.** `test_http2_huffman_handling`
previously required `QN_H2_UNSUPPORTED` for case D and acceptance for a block
whose "what Cloudflare actually sends" Huffman bytes (`11 22 33`) are not a
valid Huffman string at all — they decode to `2csb` followed by `011` padding,
which is not an EOS prefix. Both oracles were replaced, not deleted: the first
because an undecodable string is a protocol error rather than a limitation of
ours, the second because the input was never valid.

### QN2-019 — receive window cannot sustain the documented flow maximum

- **Files** `src/net/http2.c`
- **Assessment** connection and stream credit were already tracked separately
  (`conn_consumed` plus a per-stream `flow[]` array) and replenished, and the
  2^31−1 overflow guard was present. The real defect from the audit's list was
  the last one: **one WINDOW_UPDATE per DATA frame, however tiny**.
- **Implementation** credit is published once it is worth a frame
  (`H2_WINDOW_STEP` = 16 KiB), or immediately when the caller drains with an
  empty feed, or when a stream ends or is reset. A one-byte DATA frame now
  emits nothing; the credit is retained and published later.
- **Test** `test_http2_flow_after_trace_window` drives the full documented
  16 MiB maximum on stream 3 *after* the trace response has already consumed
  connection window, mirrors the peer's own window arithmetic, and asserts
  neither window ever reaches zero and no zero-increment update is emitted.
  `test_http2_strict_hpack_and_credit_retry` now asserts a one-byte frame
  produces no control output while a full frame does.
- **Status** fixed. **Residual risk** the 16 KiB step is a fixed constant; a
  peer advertising a much smaller initial window is unaffected because our own
  receive window is what is being replenished.

### QN2-012 — HTTP/2 TTFB measures the first control frame

- **Files** `src/net/verify.c`, `include/qanat/verify.h`
- **Root cause** `t_first` was set by `absorb_app()` on the first application
  byte after the handshake. Over h2 that byte is the peer's SETTINGS frame, so
  `ttfb_us` measured time-to-first-control-frame, not time-to-response.
- **Implementation** three separately named, explicitly stage-local fields:
  `app_first_us` (first application byte, the old meaning, kept and renamed),
  `ttfb_us` (request → response HEADERS), `trace_body_us` (request → first
  body byte). h2 sets `ttfb_us` only on a HEADERS event for stream 1; h1 sets
  it when the status line of response 1 parses.
- **Status** fixed. **Remaining** trace and flow responses share `ttfb_us`
  today because only stream 1 sets it; a separate `flow_headers_us` is not yet
  surfaced.

### QN2-039 — incomplete stalled flow published as ordinary throughput

- **Files** `src/net/flowmeter.h` (new), `src/net/verify.c`,
  `include/qanat/verify.h`
- **Root cause** `finish()` computed `kbps` from whatever had arrived whenever
  `t_flow` was set. A transfer that delivered half its bytes and then stalled
  for nine seconds was published as a plausible-looking low throughput.
- **Implementation** the rate computation moved into `qn_flow_report_of()`, a
  pure function over a sample. `kbps` is set **only** when
  `received >= requested`; otherwise `partial_kbps` carries the rate and
  `flow_stall_us` carries the time since the last byte that actually advanced.
  The result gained `flow_requested`, `flow_received`, `flow_completed`,
  `partial_kbps` and `flow_stall_us`.
- **Why a separate header** the logic only ran inside a socket state machine,
  so the audit's six required cases were unreachable from a test. As a pure
  unit they are all covered.
- **Test** `test_flow_report` in `tests/test_outbuf.c`: complete, exact size,
  overshoot, fast-start-then-stall (asserts `kbps == 0`, `partial_kbps == 419`,
  `stall_us == 9000000`), partial-then-reset, immediate timeout, and a span too
  short to divide by.
- **Status** fixed. **Remaining** end-to-end validation over a real bulk
  transfer needs a TLS peer that serves megabytes; that is a device task, not
  reachable from the offline suites.

### QN2-020, QN2-021 — Transfer-Encoding order and repeated fields

- **Files** `src/net/http1.c`
- **Root cause** `chunked = token_has(value, "chunked")` tested *membership*,
  and ran per field line so the last line won.
- **Implementation** `te_list` accumulates the coding list across every field
  line in the order received. Chunked framing applies only when chunked is the
  final coding; an empty element or a repeated `chunked` is malformed and
  rejected.
- **Test** `test_http1_transfer_encoding_order`: `gzip, chunked` frames,
  `chunked, gzip` does not, two field lines in both orders, `chunked, chunked`
  and `gzip,,chunked` rejected.
- **Pre-patch evidence** `chunked, gzip` produced `EV_DONE` with a decoded body
  of 5 bytes instead of 15 opaque ones; the split-field case likewise.
- **Status** fixed.

### QN2-022 — 101 Switching Protocols treated as ordinary informational

- **Files** `src/net/http1.c`
- **Implementation** 101 is rejected outright. We never send an `Upgrade`, so a
  switch is not a response to anything we asked for, and letting it reset the
  parser allowed a following 200 to stand in for it.
- **Test** `test_http1_switching_protocols`, which also confirms a genuine
  100 Continue followed by 200 still parses normally.
- **Pre-patch evidence** the 101-then-200 sequence returned OK with
  `responses == 1`.
- **Status** fixed.

### QN2-023 — shallow HTTP status-line parser

- **Files** `src/net/probe_http.c`
- **Implementation** version, single space, exactly three digits, range
  100..599, a legal separator after the code, and a real CRLF terminator
  within a bounded line length.
- **Test** `test_http_status_line_strictness`, ten rejected shapes plus the two
  legal ones.
- **Pre-patch evidence** six were accepted, including `HTTP/1.1 2000 OK`,
  `HTTP/1.1 099 OK`, `HTTP/1.1 600 OK`, `HTTP/1.1 200XOK` and an unterminated
  `HTTP/1.1 200`.
- **Status** fixed.

### QN2-024 — Cloudflare marker detection is substring-based and forgeable

- **Files** `src/net/probe_http.c`, `src/net/http1.c`, `include/qanat/probe.h`,
  `include/qanat/http1.h`
- **Root cause** two separate substring paths. `parse_trace_colo` required a
  line start but not a line *end*, and the streaming body scanner was a raw
  64-byte sliding window with no line concept at all: `colo=ABC` anywhere in
  any body raised the edge marker.
- **Implementation** `qn_http_trace_parse` is a strict `key=value` line parser
  — complete lines only, exact keys, three uppercase letters for a colo, the
  `ip` field parsed as an address, conflicting duplicate keys rejected, a
  bounded line length. The streaming scanner accumulates one line at a time
  and feeds it to the same parser, so chunk boundaries cannot change the
  answer. `Server: cloudflare` and `CF-Ray` became `QN_HTTP1_EV_WEAK_MARKER`,
  supporting evidence that no longer raises `EV_EDGE` on its own.
- **Test** `test_trace_marker_is_not_forgeable`: valid body, duplicate
  conflicting colo, identical duplicate, bad colo value, missing `=`, bad `ip`,
  an unterminated trailing line, an adversarial body containing
  `colo=ABC` in prose, a genuine trace body split at **every** byte boundary,
  and a `Server: cloudflare` header alone.
- **Pre-patch evidence** by inspection of the committed scanner, shown above:
  a raw sliding-window match with no line boundary. My first attempt to
  reconstruct the old behaviour placed the match inside the new line
  accumulator, which is *less* permissive than the original and therefore
  under-reproduced; the committed source settles it.
- **Status** fixed. **Residual risk** the documented limitation stands: this is
  marker evidence, not certificate identity.

### QN2-025 — TLS 1.2 ServerKeyExchange succeeds without signature framing

- **Files** `src/net/tls12.c`
- **Root cause** `on_server_kx` parsed ServerECDHParams and returned OK. The
  SignatureAndHashAlgorithm field, the signature length and the signature
  bytes were never looked at, so a message carrying only the ECDH parameters
  produced a usable key exchange.
- **Implementation** after the parameters: two bytes of signature algorithm
  (neither half may be zero), a two-byte length, exactly that many bytes, and
  nothing after. Cryptographic verification is still explicitly out of the
  trust model; this is framing only, and the code says so.
- **Test** `test_tls12_server_kx_signature_framing`: valid framing, params
  only, algorithm without length, eight truncation offsets, zero-length
  signature, trailing bytes.
- **Pre-patch evidence** eleven assertions failed; every truncation was
  accepted and `have_peer` was set.

**Second pass — semantics, not just framing.** The framing fix rejected only
zero bytes, so `0xFFFF`, an ECDSA algorithm on an `ECDHE_RSA` suite and an
algorithm the ClientHello never offered were all accepted.

- **Files** `src/net/tls12.c`, `src/net/tls13.c`, `include/qanat/tls.h`
- **Implementation** the offered `signature_algorithms` list is now retained in
  the session (`sigalgs` / `nsigalgs`, filled from `qn_hello_info` in
  `qn_tls_start`), because the random fingerprint's list is not a constant.
  `check_sigalg` resolves the codepoint to a key type — treating `0x08xx` as a
  whole SignatureScheme rather than a hash/signature pair, so `rsa_pss_rsae`,
  `rsa_pss_pss`, ed25519 and ed448 are classified correctly — then requires
  that it was offered and that it matches the key the negotiated suite fixes.
  EdDSA is accepted where ECDSA is expected, per RFC 8422 3.
- **Typed outcomes** undefined or impossible codepoints, unoffered algorithms
  and suite mismatches are all `PROTO`, because RFC 5246 7.4.3 makes each a
  protocol violation. `UNSUPPORTED` is reserved for a well-formed, offered,
  suite-compatible family this client does not model, currently only DSA.
- **Test** `test_tls12_sigalg_semantics`, thirteen cases plus an empty offered
  list.
- **Pre-patch evidence** rebuilding `test_tls` with only this hunk reverted
  gives seven failures: `ecdsa algorithm on an RSA suite`, `rsa algorithm on an
  ECDSA suite`, `undefined codepoint`, `undefined 0x08 scheme`, `well formed
  but never offered`, `dsa, well formed but never offered`, and the
  nothing-offered case.
- **Status** fixed. Validated against nine real OpenSSL 1.2 handshakes, which
  continue to pass, so the check does not reject what real servers choose.
- **Not claimed** the signature itself is still never verified. This is
  algorithm agreement, not cryptographic authentication.

### QN2-026 — TLS 1.2 handshake message order not enforced

- **Files** `src/net/tls12.c`, `src/net/tls_int.h`, `include/qanat/tls.h`
- **Root cause** every server-flight message was gated only on
  `st == WAIT_CERT`, so Certificate and ServerKeyExchange could repeat or
  arrive in either order, ServerHelloDone could carry a body, and a
  Certificate whose framing failed to parse was silently ignored.
- **Implementation** `tls12_step` walks
  `EXPECT_CERT → EXPECT_SERVER_KX → EXPECT_REQ_OR_DONE → FLIGHT_DONE`. The
  selected suites are all ECDHE, so both messages are mandatory and ordered.
  CertificateRequest is legal only in the third position and only once, and
  still yields a typed `UNSUPPORTED`. ServerHelloDone must have an empty body.
  A Certificate that does not parse is now `PROTO`, not a shrug.
- **Test** `test_tls12_flight_order`, six sequences.
- **Pre-patch evidence** ServerKeyExchange before Certificate, a bodied
  ServerHelloDone, a repeated CertificateRequest and an unparseable
  Certificate were all accepted.

**Second pass — the large-chain hole.** "A Certificate that does not parse is
now PROTO" held only for messages kept whole. `hs[]` is 2 KiB and real chains
are larger, so the code fell back to `else if (s->hs_len == s->hs_kept)` and set
`saw_certificate` for any large message, validated or not. The previous session
recorded this as a deliberate trade because the strict version had broken every
real handshake on-device.

- **Files** `src/net/certscan.h` (new), `src/net/tls13.c`, `src/net/tls12.c`,
  `src/net/tls_int.h`, `include/qanat/tls.h`
- **Why the trade was unnecessary** the bytes are never all present at once,
  but they do all pass through `hs_feed`, which already hashes every one of
  them into the transcript. Framing can therefore be checked as a stream.
- **Implementation** `qn_cert_scan` is a cursor — five counters and a three-byte
  accumulator — driven from `hs_feed` for a 1.2 Certificate. It walks the
  3-byte `certificate_list` length and each 3-byte entry length, requiring that
  the list consumes the message exactly (`list + 3 == hs_len`), that no entry is
  empty or overruns the list, that the message ends on an entry boundary, and
  that the whole message is within `QN_TLS_CERT_MAX`. `saw_certificate` is set
  only when `qn_cert_scan_done` holds. Identity extraction stays opportunistic
  on the retained prefix and no longer decides validity.
- **Memory** fixed at `sizeof(qn_cert_scan)`, independent of chain size.
- **Test** `test_tls12_certificate_framing`: valid under 2 KiB, valid over
  2 KiB, a three-certificate chain over 2 KiB, four framing corruptions, a
  zero-length entry, an empty list, a message too short to frame, trailing
  bytes, eight truncations, a stop one byte from the end, the size bound, and
  every chunking from 1 to 8 bytes plus 4095.
- **Pre-patch evidence** rebuilding `test_tls` with only this hunk reverted
  gives **27 failures**: every malformed large Certificate, every truncation and
  the trailing-byte case were accepted with `saw_certificate` set.
- **Real-chain evidence** `scripts/test_tls_local.sh` now also builds a test CA
  and serves a two-certificate 4096-bit chain, which exceeds `QN_TLS_HS_BUF`.
  Six new interop cases pass, TLS 1.2 and 1.3, reporting
  `cn=localhost issuer=Qanat Test CA` — so a real chain larger than the parse
  buffer is accepted and its leaf identity is still read.
- **Status** fixed. The deviation is retired.

### QN2-027 — TLS 1.3 KeyUpdate accepted without rekeying

- **Files** `src/net/tls13.c`
- **Root cause** `HS_KEY_UPDATE` returned OK in READY. The peer then switches
  keys while we keep the old read key, so every subsequent record fails to
  decrypt — which this tool reports as interference. A local limitation was
  manufacturing network evidence.
- **Implementation** option B from the audit: validate state, length and the
  `request_update` byte, then return a typed `QN_TLS_RC_UNSUPPORTED`. Success
  is never returned while the old key is retained.
- **Test** `test_tls13_key_update_is_typed`: both legal request bytes, an
  invalid one, a wrong length, and the wrong state.
- **Pre-patch evidence** four assertions failed; both legal forms returned OK.
- **Status** fixed. **Residual risk** a peer that insists on KeyUpdate now ends
  as `unsupported` rather than completing. That is the honest outcome for a
  client that cannot rekey; full support remains the alternative.

### QN2-028 — incomplete CompressedCertificate treated as certificate evidence

- **Files** `src/net/tls13.c`, `include/qanat/tls.h`
- **Root cause** the compressed branch checked five bytes and then set
  `saw_certificate = true`, claiming a certificate had been parsed when
  nothing had been.
- **Implementation** full RFC 8879 framing: algorithm, uncompressed length
  bounded by the parse buffer, a three-byte compressed length that must equal
  the remaining message exactly. An algorithm we never offered returns
  `UNSUPPORTED`. Valid framing sets a new `cert_compressed` flag, **not**
  `saw_certificate`, so no identity is claimed and `peer_cn` stays empty.
- **Found while fixing** `on_server_finished` and `on_certificate_verify` both
  gate on `saw_certificate`. Leaving them alone would have broken every real
  Cloudflare handshake under the chrome and safari profiles, which do compress
  — a path the OpenSSL matrix does not exercise. Both now accept
  `saw_certificate || cert_compressed`.
- **Test** `test_tls13_compressed_certificate_framing`: valid framing with no
  identity claimed, eight truncation offsets, compressed length off by one in
  both directions, zero and oversized uncompressed length, unoffered algorithm.
- **Pre-patch evidence** `!s.saw_certificate` and `s.cert_compressed` failed,
  and a message with a mismatched length was accepted.

**Second pass — naming the contract.** Validating outer framing is not
validating a CompressedCertificate, and the code had no way to say so to a
consumer: an empty `peer_cn` looked the same whether no certificate was seen or
one was seen and deliberately not read.

- **The mode is now named.** `qn_tls_cert_state` is `NONE`, `PARSED`, or
  `OPAQUE`. `OPAQUE` means the RFC 8879 outer framing was valid and nothing
  inside it was read, so an absent identity is by construction rather than by
  accident. `qn_tls_cert_status()` returns it and `qn_verify_result.cert_state`
  carries it out of the verifier.
- **A strict mode exists.** `qn_tls_config.cert_strict`, reachable as
  `--cert-strict`, validates the same outer framing and then returns
  `QN_TLS_RC_UNSUPPORTED` instead of continuing. Malformed framing is still
  `PROTO` in that mode, so the two rejections stay distinguishable.
- **Why opaque remains the default** Cloudflare compresses certificates under
  the chrome and safari profiles. Making refusal the default would end every
  such handshake as `unsupported` and destroy the tool's primary measurement.
  The device evidence for this path is real: three `stable-after-marker`
  results at `version=0x0304`.
- **Test** both contracts: opaque accepts and reports `QN_TLS_CERT_OPAQUE`,
  strict validates then refuses, strict still reports `PROTO` for bad framing,
  and `PARSED` is a distinct state.
- **Status** **documented-deviation.** The audit's preferred strict contract is
  implemented and selectable but is not the default, and the chain is still
  never decompressed. Full support needs a bounded brotli decoder plus inner
  Certificate parsing; neither exists. This must not be described as RFC 8879
  certificate validation.

### QN2-031 — fixed-size range loader splits one physical line

- **Assessment: already fixed in the current tree.** The loader detects an
  incomplete `fgets` read, consumes the rest of the physical line, counts it as
  exactly one rejection and reports `line-too-long`. `ferror` is checked. I
  reproduced the audit's scenario with a line containing an embedded NUL and
  the old loader **rejected** it — it did not accept a valid head and silently
  drop the tail:

  ```
  old loader ok=0 accepted=0 rejected=1 set.n=0 bad='line-too-long'
  ```

- **What was actually wrong** the diagnosis. An embedded NUL was reported as
  `line-too-long`, which sends the user looking at the wrong thing.
- **Change made** the snapshot loader (below) distinguishes them and reports
  `embedded-nul`.
- **Status** fixed, mostly pre-existing. Recorded as verified rather than
  claimed as new work. **Not done** `getline` was not adopted; the 160-byte
  line bound remains, now enforced against the in-memory snapshot. A longer
  bound is a one-line change if a real range file ever needs it.

### QN2-032 — two-pass range loading has TOCTOU behaviour

- **Files** `src/core/cidr.c`, `include/qanat/cidr.h`, `src/task/task_cf.c`,
  `include/qanat/task.h`
- **Root cause** `qn_cidr_file_lines()` opened and read the file to size the
  set, then `qn_cidr_set_load_file_af()` opened and read it again to fill it.
  Between the two the file could change, so the capacity could disagree with
  the content. The probe above shows the two passes already disagreeing on a
  NUL line: `file_lines=0` while the loader processed one.
- **Implementation** `qn_cidr_set_load_snapshot()` opens once, sizes from the
  file, reads it in a single pass into the arena, and does both the counting
  and the parsing from that one buffer. Capacity is therefore always exactly
  what the parsed bytes contain.
- **Manifest input hash** the report carries a SHA-256 of the exact bytes
  parsed plus their length, and `cf_scan` keeps them as `ranges_digest` and
  `ranges_bytes`, so a run can name its own input. This is the piece of
  Phase 11E that was reachable without the full manifest.
- **Bounds** the file is rejected above `QN_CIDR_FILE_MAX` (4 MiB) and if it
  is not seekable; both are reported, never silently truncated.
- **Test** `test_cidr_snapshot_loader`: clean file with digest and byte count,
  a changed file producing a different digest, a line at the buffer edge and
  one past it, no trailing newline, embedded NUL, CRLF, and a missing file.
- **Note** `cidr.c` now depends on SHA-256, so `test_core` links `sha2.c` and
  `rand.c`. That coupling is the price of the digest and is deliberate.
- **Status** fixed. **Residual risk** a file that grows between `ftell` and
  `fread` yields a consistent prefix, and the digest describes exactly that
  prefix, so the run still names what it parsed.

### QN2-029 — TLS 1.2 sequence number wrap is unchecked

- **Files** `src/net/tls12.c`
- **Root cause** `s->wr.seq++` and `s->rd.seq++` had no ceiling. The sequence
  number *is* the AEAD nonce for both the explicit-nonce and the XOR
  construction, so wrapping reuses a nonce under the same key.
- **Implementation** `qn_tls12_seal` returns -1 and `qn_tls12_open` returns
  `QN_TLS_RC_PROTO` when the counter is already `UINT64_MAX`.
- **Test** `test_tls12_sequence_wrap` covers `UINT64_MAX - 1` and `UINT64_MAX`.
- **Pre-patch evidence** three assertions failed; the pre-fix code sealed the
  wrapping record and reset the counter to zero.
- **Status** fixed. **Residual risk** unreachable in practice at 2^64 records,
  but it is a nonce-reuse class defect and is now closed by construction.

### QN2-030 — invalid AEAD enum returns a 32-byte key length

- **Files** `src/crypto/aead.c`, `include/qanat/crypto.h`
- **Root cause** `qn_aead_key_len` was a ternary defaulting to 32, and
  `qn_aead_init` assigned `a->id = id` *before* validating.
- **Extra defect found while fixing** `QN_AEAD_AES128GCM` is 0, so a zeroed
  context is a *valid* id and `qn_aead_seal` would dispatch AES-128-GCM over
  an all-zero key schedule. "Zeroed invalid state" was not achievable without
  a marker.
- **Implementation** explicit switch returning 0 for unknown ids; `qn_aead`
  gained `ready`, set last and checked by both `seal` and `open`; a failed
  init re-zeroes the context.
- **Test** `test_aead_invalid_id` covers -1, 3, 4, 99, `INT32_MAX`, the zeroed
  context, and all three valid ids.
- **Pre-patch evidence** five `qn_aead_key_len(id) == 0u` assertions failed.
- **Status** fixed. **Residual risk** none known.


### QN2-047 — export escaping is not a single validated path

- **Files** `src/export.c`, `src/net/probe_http.c`, `src/net/verify.c`,
  `src/core/util.c`, `include/qanat/util.h`
- **Root cause** `json_str` escaped `"`, `\` and C0 but passed DEL and any byte
  sequence through unchanged, so invalid UTF-8 from a hostile peer produced
  invalid JSON (RFC 8259 requires UTF-8). `csv_str` doubled quotes and
  neutralised leading formula characters but passed **every** control byte
  through, so a banner containing an ANSI sequence took effect in whatever
  terminal displayed the file.
- **Untrusted inputs** the port-scan `banner`, the `colo` read from the trace
  body, and `peer_cn` / `peer_issuer` read from the certificate. All three are
  chosen by the far end.
- **Implementation** one decoder, `utf8_next`, is now the only way a byte
  becomes output in either format. It rejects malformed, overlong, surrogate
  and out-of-range sequences. JSON escapes `"`, `\`, C0, DEL and C1, and emits
  `\ufffd` for anything undecodable, so the file is always valid JSON and valid
  UTF-8. CSV replaces every control scalar with a space, keeps quote doubling
  and formula neutralisation, and emits `?` for undecodable bytes.
- **Request-line injection** `qn_valid_field()` rejects any control character,
  space or DEL, and is enforced inside both request builders
  (`qn_http_build_get` and `h1_get`) rather than only at the CLI. A caller
  cannot split a request whatever it passes; `--sni` is separately validated by
  `qn_valid_hostname`.
- **Test** `test_export_neutralizes_hostile_fields` drives SGR, an OSC with a
  BEL terminator, DEL, an overlong sequence and a lone surrogate through both
  writers; `test_export_keeps_valid_utf8` proves two-, three- and four-byte
  scalars still pass through unchanged.
- **Pre-patch evidence** rebuilding `test_export` with only the two escapers
  reverted gives **9 failures**: raw DEL and raw invalid UTF-8 in the JSON, and
  raw ESC, BEL, DEL and invalid UTF-8 in the CSV.
- **Status** fixed.

### QN2-042 — untrusted text can emit terminal control sequences

- **Files** `src/ui/screen.c`, `tests/test_screen.c` (new), `Makefile`
- **Root cause** `qn_put` stored whatever code point it was given and
  `qn_screen_flush` re-encoded cells straight to the terminal, so a `0x1B` in a
  banner or colo became a real ESC on the wire. `utf8_next` also accepted
  overlong forms, lone surrogates and out-of-range scalars, each of which is a
  way to smuggle a byte past a naive filter.
- **Implementation** `safe_cell()` maps C0, DEL, C1, surrogates and
  out-of-range scalars to U+00B7 at the single point where a cell is written,
  so no path can bypass it. `utf8_next` now validates strictly: lead bytes are
  restricted to `C2..DF`, `E0..EF` and `F0..F4`, and the decoded scalar must be
  in range for its length and not a surrogate.
- **Deliberately not dropped** an invalid or control byte still occupies one
  cell. Dropping would shift the rest of the line and change the layout a
  caller computed.
- **Test** `tests/test_screen.c`, a new suite: ten hostile strings must leave no
  control code point in any cell, valid multi-byte UTF-8 must survive intact,
  and out-of-bounds writes must be dropped rather than wrap.
- **Pre-patch evidence** rebuilding the suite against the previous `screen.c`
  fails **9 of 10** hostile strings. The tenth, the overlong `C0 AF`, was worse
  than it looks: the old decoder accepted it and produced `/`, silently
  smuggling a character rather than a control code.
- **Status** fixed. **Remaining in QN2-041/043** input decoding and terminal
  dimensions are separate issues and are untouched.

### QN2-051 — LTO selection has no capability check

- **Files** `Makefile`
- **Root cause** the mode was chosen by grepping `$(CC) --version` for the
  string `clang`. Accepting `-flto=thin` is not the same as being able to link
  with it: the LLVMgold plugin can be missing, and that only shows at link
  time. A wrapper whose version string mentions clang would also have been
  given ThinLTO regardless of what it supports.
- **Implementation** `LTO` takes `auto` (default), `off`, `thin` or `full`.
  `LTO_PROBE` compiles **and links** a trivial program with the candidate
  flags, so the answer reflects the toolchain rather than its version banner.
  `auto` tries thin, then full, then falls back to off. An explicit `thin` or
  `full` that the toolchain cannot honour is a clear `$(error)`, not a compiler
  diagnostic several hundred lines later, and an unknown value names the four
  it accepts. The selected mode is printed with the build banner.
- **Compatibility** `LTO=` (empty) still means off, which is what every
  existing test target passes.
- **Matrix**

  | Invocation | Result |
  | --- | --- |
  | `make CC=gcc` | `built build-lto-auto/qanat (x86_64, lto=full)` |
  | `make CC=gcc LTO=off` | `lto=off` |
  | `make CC=gcc LTO=full` | `lto=full` |
  | `make CC=gcc LTO=thin` | `*** LTO=thin: gcc cannot compile and link with -flto=thin; use LTO=auto.  Stop.` |
  | `make CC=gcc LTO=banana` | `*** LTO must be auto, thin, full, or off; got "banana".  Stop.` |
  | `make CC=gcc LTO=` | `lto=off` |
  | NDK clang probe, `-flto=thin` | yes |
  | NDK clang probe, `-flto` | yes |
  | NDK clang full cross-build with `-flto=thin` | links, 354,736-byte `aarch64` binary |

- **Status** fixed. **Residual** the probe cannot see a `--target` that a
  caller puts in `CFLAGS` rather than in `CC`; in that case it answers
  conservatively and `auto` selects `off`, which is safe but under-detects.

### QN2-006 — output paths may collide, writes may not be transactional

- **Files** none. Verified present and correct.
- **Assessment** both halves were already implemented. `validate_options()` in
  `src/main.c` checks every output (`--json`, `--csv`, `--export-file`,
  `--event-log`, `--history`) against `--ranges` and against every other
  output, using `paths_alias()`: string equality, then `stat` device and inode,
  then `realpath` of the parent directory joined to the leaf, so a path that
  does not exist yet is still canonicalised. `output_open` / `output_finish` in
  `src/export.c` and `qn_store_save` in `src/core/store.c` both write through
  `mkstemp` in the destination directory, `fflush`, `fsync`, `fclose`,
  `rename`, then `fsync` of the parent directory, unlinking the temporary file
  on any failure.
- **Verification** run against `build-strict/qanat`:

  | Case | Result |
  | --- | --- |
  | `--json X --csv X` | `JSON, CSV, config, event-log, and history paths must be distinct` |
  | `--json X --csv <symlink to X>` | same refusal |
  | `--json same.txt --csv ./same.txt` | same refusal |
  | `--json X --history <symlink to X>` | same refusal |
  | `--ranges R --json R` | `an output path must not overwrite --ranges` |
  | distinct paths | accepted |

- **Status** fixed, pre-existing; recorded rather than re-patched.
- **Not covered** hard links between two names are caught by the inode
  comparison only when both already exist. A hard link created between
  validation and the write is not detected, and no filesystem offers a
  race-free way to do so from userspace.

### QN2-034 — wall-clock failure becomes a huge unsigned instant

- **Files** `src/core/util.c`, `include/qanat/util.h`, `src/task/task_cf.c`
- **Root cause** `(uint64_t)time(NULL)` with no check. A failed `time()`
  returns `(time_t)-1`, which casts to `18446744073709551615`; stored as
  `last_seen` that makes an entry look permanently fresh and poisons every
  later decay. `time(NULL)` was also called **once per finalist**, inside the
  record loop, rather than once per finalize, so different records in one batch
  could be dated from different instants.
- **Implementation** `qn_wall_now()` rejects `(time_t)-1`, non-positive values,
  and anything outside 2020-01-01..2100-01-01, then reports a `uint64_t`. It is
  read once per finalize. A clock we cannot trust means history is skipped for
  that batch rather than written with a fabricated instant, and confidence is
  left unset instead of computed against a bogus now.
- **Test** `test_wall_clock_is_validated`.
- **Status** fixed. **Not exercised** the failure branch itself: forcing
  `time()` to fail needs a syscall-interposition layer this project does not
  have. The defect is prevented by construction, not by a passing test.

### QN2-033 — handshake duration written under an RTT name, schema unversioned

- **Files** `src/core/store.c`, `include/qanat/store.h`, `src/task/task_cf.c`,
  `tests/test_props.c`
- **Root cause** `qn_store_observe(..., vr[i].handshake_us, now)` fed a full TLS
  handshake duration into a parameter named `rtt_us`, stored it in
  `rtt_med_us`, and wrote it under an `rtt_us` column heading. Anyone averaging
  that column would be averaging handshakes and calling them round trips.
  Separately the file declared `# qanat history v1`, but the loader skipped
  that line as a comment, so the version was decoration.
- **Implementation** the field, the parameter and the column are all
  `handshake_us`. `QN_STORE_SCHEMA` is 2 and `read_schema()` parses the version
  line: a version above what this build understands is refused, as is any data
  before a version line. **v1 migrates by being read unchanged**, because its
  `rtt_us` column always held a handshake duration — the fix is the name, not
  the value.
- **Test** `test_store_schema`: v3 refused, headerless refused, v0 refused, a v1
  file loads with `handshake_us == 91000`, and a file this build writes is a
  file this build reads.
- **Status** fixed. **Not done** the audit also asks for distinct `connect_us`
  and `request_ttfb_us` columns. `qn_verify_result` carries both, but adding
  them is a v3 schema change and belongs with whatever consumes them. The
  misnaming, which was the correctness defect, is closed.

### QN2-035 — concurrent writers lose each other's history

- **Files** `src/core/store.c`
- **Root cause** load and save were unsynchronised. Two Qanat processes sharing
  a `--history` file both loaded it, both observed, and both saved; the second
  `rename` replaced the first's file wholesale. Every address only the first
  process had seen was gone.
- **Implementation** `qn_store_save` takes an exclusive `flock` on
  `<history>.lock` — a separate file, so a concurrent *reader* of the history
  is never blocked — then reloads the history under the lock, merges, writes
  through the existing temp / fsync / rename / fsync sequence, and releases.
- **Merge rule** every address from either side survives. Where both hold one,
  the fresher `last_seen` wins, ties broken by greater `weight_q10`; `runs`
  takes the maximum; `oper_mask` is the union, because a path observed from
  either vantage point was really observed.
- **Deliberate limitation** the merge is entry-granular, not sample-additive.
  Where two writers both observed the same address, the loser's samples are not
  added to the winner's. Doing that correctly needs per-entry deltas since
  load, which the decayed-sum representation does not preserve. The failure
  mode the audit describes — a whole file clobbered — is closed; the residual
  is that one round of evidence for a shared address may be dropped.
- **Test** `test_store_concurrent_merge`: two stores that never saw each other
  both save and both addresses survive; then a same-address collision keeps the
  fresher observation and both path bits.
- **Status** fixed, with the limitation stated rather than hidden.

### QN2-036 — eviction ignores staleness

- **Files** `src/core/store.c`
- **Root cause** the victim was chosen by `score_q10 * 1024 / (weight_q10 + 1)`,
  a ratio frozen at whenever each entry was last written. A month-old
  one-of-one scores 1024; a recent thirty-two-of-forty scores about 819. The
  stale entry won and the well-supported recent one was evicted — exactly the
  audit's description.
- **Implementation** `standing()` decays both score and weight to *now* before
  ranking, then scales the resulting rate by the decayed weight, so an entry is
  ranked on how much evidence it still has as well as how good that evidence
  was. `slot_for` takes `now`, so eviction and observation share one instant.
- **Test** `test_store_eviction_is_stale_aware`: a capacity-2 store holding one
  month-old perfect sample and one recent well-sampled entry must evict the
  stale one when a third address arrives.
- **Pre-patch evidence** rebuilding `test_props` with QN2-033/035/036 reverted
  gives **8 failures**: three schema files accepted, the merge losing an
  address and its path bits, and eviction keeping the stale entry while
  discarding the recent one.
- **Status** fixed.

### QN2-011 — an ICMP reply is trusted without being bound to a probe

- **Files** `src/task/task_discover.c`, `include/qanat/task.h`,
  `tests/test_discover.c` (new), `Makefile`
- **Root cause** the echo payload was the compile-time constant
  `"qanat-probe-0000"`, identical in every run on every installation, so
  anyone able to send a packet could manufacture a host. Three further gaps:
  the accepted length was `>=` rather than `==`, so a longer packet with a
  valid checksum passed; the outstanding probe was never consumed, so one
  reply could be replayed indefinitely; and nothing bound a reply to the
  offset it claimed beyond the source address.
- **Not fixable from userspace** the ICMP identifier. On a `SOCK_DGRAM`
  `IPPROTO_ICMP` socket the kernel assigns and rewrites `id` and demultiplexes
  on it, so a userspace comparison would be checking the kernel's own value.
  Recorded rather than faked.
- **Implementation** `icmp_payload()` fills the 16-byte pad with a per-run
  64-bit nonce, the target offset, and a tag derived from both, so a probe for
  one offset cannot be replayed as another's. The nonce comes from
  `qn_random_secure()` — deliberately not the run seed, since a reproducible
  nonce is a guessable one — with a time and pid fallback. `valid_icmp_reply`
  requires an exact length and returns the answered offset;
  `accept_reply()` zeroes `icmp_sent_ns[off]`, so the second copy of a reply
  answers nothing.
- **Test** `tests/test_discover.c`, a new suite that compiles the unit in to
  reach the file-static validator: a reply for an unprobed offset, a
  successful reply, a consumed duplicate, a reply forged without the nonce, a
  cross-offset replay, a mismatched source address, wrong type, wrong code, a
  broken checksum, both wrong lengths, an out-of-span sequence, and payload
  distinctness across 64 offsets and across runs.
- **Pre-patch evidence** rebuilding the suite against the constant-marker
  validator gives **69 failures**. The distinct ones: a reply forged without
  the nonce is accepted; another offset's payload is accepted under this
  offset's sequence; a duplicate is counted twice (`icmp_replied` reaches 2,
  `icmp_rejected` stays 0); a reply one byte too long is accepted; and all 64
  offsets share one payload.
- **Status** fixed.

### QN2-049 — discovery progress mixes units

- **Files** `src/task/task_discover.c`, `include/qanat/task.h`
- **Root cause** `probed` counted ICMP sends *and* TCP connect results, while
  `total` was only `host_count * nports`, the TCP plan. With both phases
  enabled the numerator counted work the denominator never included, so
  progress overshot.
- **Implementation** `total` is now probes of both kinds: the TCP plan plus one
  ICMP probe per host when the ICMP phase will run, recomputed when the TCP
  host set is known. Distinct counters were added and are kept separate:
  `icmp_attempted`, `icmp_replied`, `icmp_rejected`, `icmp_found`,
  `icmp_unsent`, `tcp_attempted`, `tcp_completed`.
- **Status** fixed. **Not done** surfacing the new counters in the TUI; that
  belongs with QN2-046.

### QN2-048 — the default route is whichever appears first in the file

- **Files** `src/core/netinfo.c`
- **Root cause** the parser took the first row with destination `00000000` and
  the `UP` flag, then `break`. With more than one default route — a VPN
  alongside Wi-Fi, or Wi-Fi alongside cellular — the choice was file order.
- **Implementation** all default rows are read. The lowest metric wins, and at
  equal metric an interface whose `/sys/class/net/<if>/operstate` reads `up`
  beats one that does not. `iface_is_up()` returns 1, 0 or -1 so an unreadable
  operstate ranks between the two rather than being treated as down.
- **Honest limit** `/proc/net/route` exposes the **main table only**. Android
  keeps per-network default routes in policy tables, so on a handset this file
  can be empty of defaults entirely — verified: the attached device shows two
  non-default rows and no default at all. Selecting by table and scope needs
  rtnetlink, which is not implemented. The fix removes the file-order defect;
  it does not make Android's routing visible.
- **Status** fixed, with the scope limit stated.

### QN2-050 — thermal throttling reads whatever zone is hottest

- **Files** `src/core/cpuinfo.c`, `src/net/engine.c`, `include/qanat/engine.h`
- **Root cause** `qn_thermal_read()` took the maximum over every
  `thermal_zone*/temp` without ever reading `type`. On a phone the hottest
  zone is routinely the battery, charger, display or skin sensor, so scan
  concurrency was being cut on a measurement of something else entirely.
- **Implementation** `read_zone_type()` reads and lowercases `type`, and
  `cpu_thermal_zone()` accepts only recognised CPU/SoC substrings (`cpu`,
  `soc`, `tsens`, `apc`, `package`, `pkg`, `coretemp`, `gold`, `silver`,
  `prime`, `big`, `little`). When none matches the function returns 0, which
  `thermal_update` already treats as "no reading" — unavailable is reported
  rather than substituted.
- **Hysteresis** a new level must be produced by **two consecutive polls**
  before it is applied, so a reading wobbling across a band boundary cannot
  halve the window and restore it on the next poll.
- **Test** `test_thermal_zone_selection`: thirteen real CPU/SoC zone names must
  be accepted and thirteen real non-CPU names (`battery`, `charger`,
  `skin-therm`, `quiet-therm`, `gpu-usr`, `modem_tj`, `pm8350b_tz`, …) must be
  rejected.
- **Not verified on hardware** `/sys/class/thermal/thermal_zone*/type` is
  SELinux-restricted on the attached Android 13 device: the shell gets
  `Permission denied` for both `type` and `temp` on every zone. Thermal
  throttling is therefore inert on that handset, before and after this change,
  and the selection logic could only be tested against known zone names.
- **Status** fixed, unverified on hardware for the reason above.
