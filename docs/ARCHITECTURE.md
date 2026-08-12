# Qanat Architecture

This document describes the implementation boundaries that matter when changing Qanat. It is not a marketing overview; it records ownership, concurrency, memory, and protocol invariants.

## Design Constraints

Qanat targets an unrooted Termux process on an Android ARM64 phone. The architecture assumes:

- raw SYN injection is unavailable;
- the process and carrier path have finite FD, socket, conntrack, and NAT budgets;
- CPUs may be divided into performance, middle, and efficiency clusters;
- the device can change frequency and scheduling policy under thermal pressure;
- cellular radio promotion can contaminate the first latency samples;
- terminal writes can become a measurable part of the workload;
- network input is untrusted and can be truncated, delayed, reordered across connections, or intentionally malformed.

These constraints favor bounded state, non-blocking I/O, explicit ownership, and adaptive pressure control over maximum instantaneous fan-out.

## Observation and Classification Boundary

Network code records facts; it does not assign a verdict. The only supported
direction is:

```text
transport -> TLS -> canonical HTTP -> edge evidence -> flow/stability
          -> pure classifier -> store/UI/export
```

`qn_observation` is the aggregate crossing that boundary. HTTP/1 and HTTP/2
both emit `qn_http_event`, so status, completion, body, header, and marker facts
reach one edge-evidence policy. Parsers cannot express transport-specific
marker policy and cannot mutate a result classification.

`qn_observation_classify()` is pure: its output depends only on the aggregate,
with no clock, socket, I/O, or allocation. The output has two axes:

- `highest_rung_reached`: none, TCP, TLS, HTTP, edge, flowing, or stable;
- `terminal_outcome`: success, dead, local-error, peer-rejected,
  protocol-invalid, unsupported, reset, timeout, cancelled, interference,
  inconclusive, or pending for an unfinished observation. Path remains a
  separate failure origin.

Consumers may render a derived classification string, but eligibility and
accounting use the pair. A terminal failure therefore cannot retain a
successful displayed rung by accident.

`qn_request_gate` separately records `request_queued`, latches
`request_fully_flushed` only when the output buffer is empty, quarantines
application bytes between those states, and timestamps TTFB from the final
byte placed on the wire.

## Process Model

The application has one UI/result owner thread, a configurable sweep-worker pool, and a temporary deep-verifier thread while the TUI is active.

The owner thread:

- owns task-level result arrays and state machines;
- drains each worker's result ring;
- advances scan phases;
- renders the TUI or prints headless output;
- writes JSON, CSV, history, and event logs;
- runs the deep verifier inline in headless mode, or starts, monitors, cancels, and joins it in the TUI.

Each worker owns:

- its socket slots and freelist;
- one `epoll` instance, or a `select()` compatibility loop;
- one O(1)-bucketed timeout wheel;
- one adaptive window and token bucket;
- one PRNG state;
- one SPSC result ring;
- its statistics counters.

Sweep workers never mutate task results. They publish fixed-size events and the owner applies them. During full Cloudflare verification, the temporary verifier has exclusive access to the Cloudflare record array; the UI reads only atomic progress until that thread publishes completion. This keeps synchronization away from the larger result structures without racing the renderer.

Every engine exit uses one finalization contract: optionally request stop, join
workers, drain every SPSC ring until empty, snapshot fatal/drop state, and
verify `claimed == completed + unattempted` with saturating arithmetic. Only
then may a task finish/sort and an export begin. Natural completion, TUI stop,
quit, and terminal interrupt do not have separate ownership rules.

## Work Distribution

Workers claim target indices in chunks of 64 through a shared atomic cursor. Chunking avoids a contended atomic operation for every socket while still allowing workers on different CPU clusters to progress independently.

The task callback maps an index to a concrete address, port, and probe stage. Port scans use a keyed Feistel permutation so ascending ports are not emitted as a burst. Cloudflare scanning uses an adaptive block scheduler instead of the permutation:

1. Flatten the supplied IPv4 prefixes into one logical address space.
2. Divide the space into 256-address blocks.
3. Keep a Beta posterior for observed success/failure in every block.
4. Sample a bounded subset of blocks and prefer the strongest posterior draw.
5. Claim a unique offset inside the selected block.
6. Fall back to a complete search when sampled blocks are exhausted.

The scheduler preserves complete coverage when a sweep is allowed to finish. Its purpose is to improve the time to useful candidates when responsive addresses are spatially clustered, not to invent reachability evidence.

## Socket Engine

The normal backend is Linux `epoll`; `select()` is a compatibility fallback.

Probe sockets are:

- non-blocking and close-on-exec;
- checked with `SO_ERROR` after connect readiness;
- configured with small send/receive buffers;
- closed abortively to avoid scanner-side `TIME_WAIT` accumulation;
- optionally launched with TCP Fast Open when the stage sends first and the kernel accepts it.

The engine reserves 128 file descriptors for the surrounding process. Automatic concurrency is bounded by `RLIMIT_NOFILE`, a hard ceiling of 4,096, and an automatic ceiling of 1,024. User-selected concurrency is still clamped to the safe FD budget.

### Adaptive Window

Every worker has an AIMD-style window. It starts conservatively and reacts to two different classes of pressure:

- local failures such as `EMFILE`, `ENOBUFS`, `ENOMEM`, or ephemeral-port pressure cause an immediate multiplicative reduction;
- network timeout ratio and RTT inflation are evaluated in batches and reduce the window at a controlled cadence.

Successful batches increase the window additively. After enough valid RTT samples, the deadline is retuned from the minimum observed RTT and an EWMA, bounded by a 120 ms floor and the user ceiling.

This controller cannot distinguish every silent firewall from congestion. On a host that drops most ports, it may deliberately reduce throughput. That trade-off favors sustained mobile stability and fewer false negatives over raw full-port-scan speed.

### Timeouts and Result Transport

Sockets are armed in a time wheel rather than a heap or one timer per descriptor. Worker-to-owner transport uses fixed-size SPSC rings. The producer reserves ring capacity for all in-flight probes before launching more work, so normal operation does not need to drop results.

## Mobile CPU and Thermal Policy

CPU topology is inferred from per-core frequency or capacity information in sysfs. Clusters are sorted fastest first. On heterogeneous systems, automatic I/O workers use the performance and middle clusters and omit the slowest cluster.

Affinity is best-effort because Android cpusets and vendor policy may reject or later override it. Failure to pin is not fatal.

One worker samples thermal zones every three seconds. The global thermal percentage reduces the effective socket window at configured temperature thresholds. Missing or restricted thermal files leave the window unchanged.

## Memory Model

The scanner uses validated plans, arenas, and fixed-size records for predictable memory behavior:

- socket slots and result rings are allocated once per engine;
- the engine working arena and the candidate arena are separately accounted;
- probe events and banners have fixed upper bounds;
- the deep verifier allocates one bounded connection state per finalist slot;
- candidate capacity, total finalists, output count, and all concurrency limits are independent;
- finalist results are verified in bounded batches rather than one array proportional to all finalists;
- no array proportional to every address in the complete Cloudflare IPv4 space is created.

The deep verifier is intentionally separate. A cheap sweep slot carries only a small probe buffer and classification state; a full TLS connection contains transcript hashes, key material, record buffers, HTTP parser state, and output queues. Using the same concurrency limit for both would waste memory and stress the phone.

The exact formulas and runtime-measured allocation sizes are documented in
[Scan-plan architecture](SCAN-PLAN.md).

## Cloudflare Pipeline

The Cloudflare task has two layers.

### Cheap Parallel Phases

1. **Reach:** duplicate-free TCP/443 traversal under the resolved selection policy.
2. **Handshake screen:** send a bounded browser-shaped ClientHello and classify the first TLS response.
3. **Calibrate:** sample an oversubscribed, block-diverse cohort and discard lucky sweep minima.
4. **Measure:** robustly sample and reduce the cohort to the configured total finalist count.

`full`, `coverage`, `budget`, `reachable`, and deterministic `auto` are distinct
stop policies. `--limit N` remains only as a deprecated compatibility mapping to
`--scan-mode reachable --reachable-target N`; omitting `--limit` with legacy
`--cf` preserves full traversal. Candidate retention remains streaming and
bounded at the plan's capacity. Reaching a reachable target publishes
`QN_TASK_STOP_CONDITION`, and already in-flight jobs settle through the normal
accounting contract without turning satisfied work into an incomplete run.

JSON schema 7 exports the stable range digest, resolved plan, candidate and
finalist counts, calibration cohort, accounting, profile version, score version,
and build fingerprint. Partial scans are labelled "best observed among scanned
addresses" and make no claim about unscanned addresses.

### Full Verification

The full pass is a bounded single-threaded `epoll` state machine with multiple sessions in flight. Headless mode runs it inline; the TUI gives it a temporary background thread:

1. connect to TCP/443;
2. complete supported TLS 1.3 or TLS 1.2;
3. verify record authentication and the peer `Finished` value;
4. negotiate HTTP/2 or HTTP/1.1 with ALPN;
5. request `/cdn-cgi/trace` over the same TLS connection;
6. detect Cloudflare headers or `colo=XXX` in the response;
7. optionally request a bounded flow sample;
8. optionally hold the connection for a late reset or close.

Active transfers and stability holds have independent capacities. The defaults
are 64 (`--verify-concurrency`) and 512 (`--stability-concurrency`). Entering a
hold releases the active token immediately, so new handshakes continue while
holds remain open. Both classes share one bounded connection allocation but
have independent counters and admission limits; the FD budget caps their sum.
If a completed transfer cannot enter the hold pool, the observation records
`capacity_limited` and never reports a false stability success.

Certificate identity is parsed for display but not authenticated. See [TLS](TLS.md).

## Ranking and History

Records carry bounded RTT samples, loss, minimum, median, nearest-rank p90, and a metric explicitly named `mean_consecutive_rtt_delta`. A two-sided distribution-free 90% interval for the population median is emitted only from five or more successful observations; smaller samples carry an explicit unavailable state. Sweep minima are not final ranking evidence. A diversified calibration cohort is robustly re-sampled before finalist selection. Score version 3 adds an ordered tunnel component to marker evidence, median/p90 latency, loss, jitter, stability, confidence, and optional throughput, with deterministic address tie-breaks. A passed tunnel outranks edge-only evidence, while untested and known-failed states remain distinct.

The history store applies exponential decay with a three-day half-life. It records a coarse local path tag derived from link type and address prefix, not an operator account or device identifier. Repeated recent observations and evidence on multiple path tags receive more confidence than an old single success.

The history table is intentionally small and linearly searched. Only the verified finalist set uses it; it is not a database for the full target space.

## Protocol Boundaries

The TLS, HTTP/1.1, and HTTP/2 code is a bounded measurement client:

- input and header storage have explicit caps;
- unsupported states fail closed for the measurement;
- HTTP/2 dynamic compression is not a general browser implementation;
- TLS supports only the suites and handshake shapes needed by the probe;
- no protocol component is intended as an application security library.

The profile instance fixes one cross-layer persona, while a connection seed
materializes fresh randoms, key shares, GREASE values, Chrome extension order,
and ECH padding. Seeded runs derive this input deterministically; ordinary runs
use fresh entropy. Chrome 151 and Firefox 153 shapes are pinned to sanitized
Android captures. Safari 26 is source/reference-derived and labelled as such.

The modern TLS path implements X25519MLKEM768, X25519, and P-256 key exchange,
including HelloRetryRequest transcript reconstruction. A full browser offer can
contain legacy branches outside the bounded executor; an unsupported server
selection is typed rather than silently treated as a successful profile match.

This narrow scope is an architectural feature. New protocol behavior should be added only when it improves a concrete measurement and comes with parser, state-machine, adversarial-peer, and fuzz coverage.

## TUI and Headless Parity

The TUI renders at a maximum cadence of roughly 33 ms per frame. A current and previous cell grid are compared, and only changed runs are written. The engine continues independently of rendering.

Headless mode is selected explicitly with `--headless` or automatically when standard input/output is not a TTY. New scan behavior must remain available without the TUI; rendering must never be the only way to retrieve a result.

The final Cloudflare verifier runs behind a cancellable TUI background boundary. Before ownership passes to that worker, the UI copies the preliminary records into a read-only display snapshot. While verification owns and mutates the live records, the renderer reads only the snapshot plus atomic progress; after join it switches back to the committed live array. Pressing `x`, `q`, or `Ctrl-C` signals cancellation, closes active verifier sockets, joins the owner, and retains preliminary sweep results. This ownership protocol avoids treating a data race as a rendering detail.

With no arguments and a real TTY, `main` enters a numeric launcher before the
TUI. Its Scan Plan page exposes scope, selection, candidate capacity, total
finalists, output count, ranking, independent concurrency controls, memory
budget, presets, persistence, and a resource preflight summary. Large full
traversals require explicit confirmation. Non-TTY execution bypasses the
launcher and preserves CLI/headless behavior.

JSON, CSV, history, and tunnel-template writers use temporary files in the destination directory, flush and sync complete content, then rename. A failed write removes the temporary file and leaves the old destination intact. The managed Cloudflare range updater similarly downloads into a locked, size-bounded temporary file, validates every prefix and the aggregate shape, and only then replaces the cache.

## Invariants for Contributors

- Keep sweep-result mutation on the owner thread; any background result owner must have an explicit exclusive-access boundary.
- Keep socket ownership inside the worker that created the descriptor.
- Do not allocate in per-event or per-packet hot paths.
- Preserve bounded parser and queue sizes.
- Treat timeout, refused, reset, malformed, and local-resource failures as different signals.
- Keep `--limit` only as the deprecated reachable-target compatibility alias.
- Keep Cloudflare bulk mode IPv4-only unless a finite, explicit IPv6 target model is introduced.
- Add deterministic tests before increasing protocol or concurrency complexity.
