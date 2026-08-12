# Qanat scan-plan architecture

This note describes the production contract implemented by scan-plan version 1,
profile-instance version 1, score version 2, and JSON export schema 6. The
validated `qn_scan_plan` is the only resolved plan consumed by the CLI, TUI,
Cloudflare task, verifier, progress views, and exporter.

## Independent controls

Six values that used to be conflated are now independent:

1. scan mode controls traversal and stopping;
2. selection controls which unique address comes next;
3. candidate capacity bounds promising records retained after the cheap sweep;
4. finalist count controls the total robustly screened verification cohort;
5. output count controls only display and export cardinality;
6. scan, verification, and stability concurrency bound simultaneous work, not totals.

For example, `--finalists 1024 --verify-concurrency 32` verifies all 1,024
finalists in bounded batches. It never silently changes the finalist count to
32. `--output-top 20` similarly does not reduce the candidate or finalist set.

## Scan-mode contracts

| Mode | Attempt contract | Successful termination |
| --- | --- | --- |
| `full` | Every unique address in the normalized loaded range set exactly once | All planned addresses have terminal accounting |
| `coverage` | `ceil(total_unique * coverage / 100)` unique addresses | Exactly the fixed-point target has terminal accounting |
| `budget` | Exactly `min(address_budget, total_unique)` unique addresses | The address budget has terminal accounting |
| `reachable` | Continue until the requested number of successful candidates is retained | `QN_TASK_STOP_CONDITION`; in-flight work settles under normal accounting |
| `auto` | Deterministically resolves from range size, memory, FD limit, CPU count, and mobile policy | The resolved mode's contract |

Coverage is parsed as an integer millionth of 100 percent. Accepted text is
0.01 through 100 with no binary floating-point conversion. Checked arithmetic
computes the target with ceiling rounding, so a non-zero accepted percentage
never silently rounds a non-empty range to zero. Coverage 100 percent is
normalized to `full` and follows the identical traversal path.

The range loader takes one stable snapshot, rejects short reads, embedded NULs,
size overflow, metadata changes, and concurrent truncate or replacement. CIDRs
are normalized before planning. Overlaps and duplicates are removed, so `full`
means each unique address exactly once across every loaded prefix. Exported
range SHA-256, byte length, input prefix count, normalized prefix count, input
address count, unique count, and removed duplicate count bind a result to that
snapshot.

## Selection policies

- `uniform` is a seeded global permutation over the exact domain.
- `stratified` allocates proportional quotas while giving every stratum a share
  when the budget is large enough.
- `adaptive` remains duplicate-free but shifts later work toward productive
  blocks; it is explicitly non-representative.
- `hybrid` first guarantees stratified exploration, then uses adaptive
  exploitation. It is the default.

All policies consume addresses without replacement and use deterministic
tie-breaks for a fixed seed. Partial adaptive or hybrid results are labelled
"best observed among scanned addresses"; they are never described as the best
endpoint in the entire range.

## Validated resource plan

`qn_scan_plan_resolve()` validates all integer products and sums before any scan
starts. It rejects explicit values that exceed the memory ceiling, FD ceiling,
candidate domain, or platform bounds. Auto values may be reduced, with
`auto_adjusted` recorded in the plan. The preflight summary shows unique and
planned addresses, candidate capacity, finalists, output count, three
concurrency limits, verification batch size, memory components, and FD usage.

The current x86-64 GCC ABI measured by `qanat doctor` is:

| Allocation unit | Measured bytes | Lifetime and bound |
| --- | ---: | --- |
| `cf_record` | 208 | `candidate_capacity` records |
| Candidate auxiliary state | 44 per candidate | SPRT plus four `uint32_t` work arrays |
| Candidate fixed allocation | 49,152 | arena/page padding reserve |
| `qn_verify_result` batch entry | 660 | `verification_batch_size` entries |
| Verifier connection slot | 65,768 | active plus stability pool slots |

These sizes are reported at runtime because ABI padding can differ on AArch64.
The plan uses the running binary's `sizeof` values. Candidate bytes, verifier
bytes, the fixed working arena, and page-rounding overhead are checked
separately and then summed with overflow detection.

Finalist verification allocates one address batch and one result batch, not a
`qn_verify_result[all_finalists]` array. Batch size is bounded by
`max(32, 4 * verify_concurrency)` and the remaining finalist count, then checked
against the memory plan. The verifier's active and stability pools remain
independent and share an FD ceiling.

## Ranking pipeline

The Cloudflare pipeline is staged:

1. cheap TCP sweep;
2. streaming Top-K candidate retention;
3. cheap TLS screen;
4. diversified oversampled calibration cohort;
5. robust multi-sample finalist selection;
6. bounded deep TLS/HTTP verification;
7. deterministic final ranking and output Top-N.

The calibration cohort is normally four times the finalist count, with at least
32 extra candidates when available. Sweep minimum RTT samples are cleared
before robust calibration. Median, nearest-rank p90, loss, consecutive-sample
jitter, confidence, marker evidence, optional throughput, and stability feed
score version 2. One lucky minimum RTT cannot win against consistently better
evidence. Diversity selection prevents one noisy block from consuming the
whole finalist set, and address order is the final deterministic tie-break.

## Client profile and protocol honesty

A run instantiates exactly one immutable `qn_profile_instance` from profile,
seed, SNI, and certificate policy. Fingerprint preview, ClientHello wire bytes,
HTTP/2 settings and ordering, HTTP/1 shape, verifier, and export all consume that
instance. Random selection therefore creates one coherent persona rather than
independent cross-layer choices. GREASE is generated once under that policy.

Each built-in profile is capability-constrained. The ClientHello advertises
only implemented TLS versions, cipher suites, signature algorithms, groups,
key shares, and ALPN paths. Unsupported profile shapes fail profile
instantiation instead of emitting a plausible but false fingerprint.
`fingerprint show` serializes the same immutable instance and wire builder used
by the verifier, so equal profile, seed, and SNI produce equal preview bytes.

## Outcomes and accounting

`qn_run_outcome` is shared by engine finalization, ICMP discovery, verifier,
TUI, headless mode, and transactional output:

| Outcome | Exit code |
| --- | ---: |
| success | 0 |
| cancelled | 130 |
| incomplete | 4 |
| failed | 3 |

Invalid command syntax remains exit code 2 because no run was created.
`QN_TASK_STOP_CONDITION` is success, not incomplete. The engine invariant is
`claimed == completed + skipped + unattempted`; local terminal failures are
counted separately from peer/path outcomes and force a failed run. Verifier
accounting satisfies `attempted + unattempted == requested` and
`completed + cancelled == attempted`.

Output files are transactional: write, flush, `fsync`, and atomic rename must
all succeed before the new file commits. A short write or commit failure leaves
the prior destination intact and yields a non-success outcome.

## TUI contract

The Scan Plan page exposes presets and every independent setting without using
the CLI: scope, selection, candidate capacity, finalists including All,
output count, ranking, three concurrency controls, and memory budget. Custom
values are validated before they can become a runnable plan. The preflight
summary includes overlap removal and resource estimates.

Terminal input is a persistent ring plus an incremental state machine for
GROUND, ESC, CSI, SS3, UTF-8, and bracketed paste. A read appends bytes; decoding
one key never discards later bytes. Partial sequences survive the next poll,
standalone ESC uses a bounded ambiguity timeout, malformed UTF-8 makes progress,
and paste payload is emitted in order.

Rendering is transactional. A frame is built against the committed front
model, written completely through a short-write-aware output buffer, and only
then commits the new front model. A terminal too small for the minimum layout
shows a truthful small-terminal state. Signal handlers request shutdown; normal
cleanup restores termios, cursor, alternate screen, and signal dispositions on
every exit path.

## Schema 6 migration

Schema 6 adds `build_fingerprint`, `range_snapshot`, the resolved `scan_plan`,
full sweep and pipeline accounting, profile version/support, score version and
components, and candidate truncation/replacement counters. Consumers must:

1. reject or explicitly migrate unknown future schema versions;
2. use `scan_plan.planned_addresses` as the progress denominator for coverage
   and budget modes;
3. treat `result_scope` as authoritative for partial-scan wording;
4. use `terminal_outcome` and typed origin fields rather than inferring success
   from a non-empty result array;
5. display only the exported `output_results`, without treating it as the
   finalist or candidate count.
