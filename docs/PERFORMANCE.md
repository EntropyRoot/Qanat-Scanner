# Measurement and Performance Guide

Qanat is optimized for sustained work on an unrooted phone, but it does not promise one universal scan rate. On a real route, destination behavior often dominates CPU speed: a fast `RST` can complete immediately, while a silent firewall consumes the timeout and may trigger adaptive backoff.

This document explains how to tune and measure the engine without turning estimates into benchmark claims.

## What to Measure

Do not reduce every mode to one probes-per-second number. Record at least:

- total attempted and completed probes;
- elapsed wall time;
- observed completion rate after the warm-up period;
- open, refused, timeout, reset, and local-error counts;
- effective socket window and deadline;
- device temperature and thermal percentage;
- result-queue drops, which must remain zero;
- for Cloudflare verification: connect time, handshake time, TTFB, response protocol, bytes, flow rate, idle result, and verdict distribution.

The cheap Cloudflare sweep and full TLS verifier are different workloads. Report them separately when comparing changes.

## Reproducible Test Record

Every performance report should include:

| Field | Example |
| --- | --- |
| Device and SoC | phone model, Snapdragon/MediaTek part |
| Android and Termux | exact versions |
| Link | cellular/Wi-Fi/VPN and operator or lab path |
| Power state | charging, battery saver, screen state |
| Thermal state | starting and peak temperature |
| Revision | commit hash or source archive checksum |
| Build | exact `make` command and compiler version |
| Target | authorized host, CIDR, or range-file checksum |
| Command | complete Qanat invocation |
| Repetitions | warm-up plus at least five measured runs |
| Summary | median and spread, not only the best run |

Use the same range file, timeout, retry count, fingerprint, SNI, rate, and concurrency for both sides of an A/B comparison.

`--seed` fixes the Qanat target order and deterministic TLS randomness. It does not freeze the network: response arrival order changes the adaptive scheduler, so two live runs can still diverge.

`--samples N` is a sequential-test budget. An undecided finalist can consume up to `min(12, 2 × N)` rounds; clear positive or negative evidence can stop it earlier. Record the observed sample count rather than assuming it equals the option value.

## Reading the Main Bottlenecks

### Mostly Refused Ports

Closed ports that return `RST` complete quickly. CPU, socket setup, and the configured rate are likely to dominate. Increasing concurrency can help until the completion rate stops rising.

### Mostly Silent Ports

Each silent port occupies a slot until its deadline. The default retry adds another confirmation pass, and AIMD can reduce the window when timeout density is high. A full scan of a heavily filtered host is therefore intentionally cautious.

Only on a known low-latency authorized path should you consider a lower timeout and zero retries:

```bash
./build/qanat --ports 192.168.1.10 -p all \
  --timeout 400 --retries 0 --headless
```

### Local Resource Pressure

`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`, `EAGAIN`, and ephemeral-port pressure cause local backoff. Raising `--concurrency` beyond that point lowers throughput and can disturb the phone's entire connection path.

### Thermal Pressure

If the thermal percentage falls, the engine is intentionally reducing the window. Compare sustained middle-of-run performance, not the first few seconds. A cooler device with fewer workers can outperform a hotter device with a larger initial window.

### TUI Overhead

Use `--headless --quiet` for engine benchmarks. The TUI already performs damage tracking, but terminal I/O and the surrounding Java application remain outside the scanner's control.

## Tuning Order

Change one variable at a time:

1. Keep automatic workers, affinity, thermal control, and AIMD enabled.
2. Set a conservative `--rate` for a shared or cellular path.
3. Increase `--concurrency` in small steps while watching sustained completion rate, timeouts, and temperature.
4. Change `--workers` only if topology detection is clearly wrong on that vendor kernel.
5. Tune timeout from measured live RTT, with enough margin for route variance.
6. Reduce retries only when the cost of false negatives is understood.
7. Use `--no-adaptive`, `--no-thermal`, or `--no-affinity` only for controlled A/B diagnosis.

The default automatic concurrency is bounded by the FD limit and 1,024 slots. Explicit concurrency can reach 4,096 when the descriptor budget permits, but that is a safety ceiling, not a recommendation.

## Cloudflare Scan Strategy

`--limit N` retains N TCP-reachable candidates when the range contains enough responsive addresses. It does not cap scheduled addresses and cannot by itself be used as an exact-attempt benchmark. With JSON schema 4, use `sweep_scheduled` for addresses admitted by the scheduler, `sweep_completed` for terminal sweep events delivered to the task, and `reachable` for retained open candidates. On a healthy complete run, scheduled and completed should match; a mismatch accompanies a partial/infrastructure result and must not be hidden in a throughput number. Result logic should use `highest_rung_reached` plus `terminal_outcome`; `verdict` is a derived display string.

For a short operational search:

```bash
./build/qanat --cf --ranges cloudflare-v4.txt \
  --quick --limit 128 --rate 1000 --headless
```

For complete supplied-range traversal, omit `--limit`. The streaming Top-K structure bounds retained reachable candidates, not attempted addresses.

The adaptive block scheduler can improve time to first useful results when successes cluster by address region. It cannot guarantee an improvement on uniformly random or rapidly changing paths. Report both time to the first marker-confirmed result and total elapsed time when evaluating it.

## Deep Verification Cost

A full finalist session performs substantially more work than the screen phase:

- ephemeral X25519 and key schedule;
- TLS record authentication;
- a complete TLS 1.2 or 1.3 handshake;
- HTTP/2 or HTTP/1.1 parsing;
- optional payload transfer;
- optional idle hold.

`--verify-concurrency` controls active transfers and is separate from sweep
concurrency. `--stability-concurrency` independently caps idle holds. Their
defaults are 64 and 512. Entering the idle stage releases an active slot
immediately, so a five-second hold no longer blocks the next handshake.
Raising either limit increases memory, descriptor, NAT, and conntrack pressure.
`--quick` removes flow and idle stages but keeps the full handshake and trace
request.

The sweep's `--rate` token bucket does not govern the full verifier. Active
verification is bounded by `--verify-concurrency`, holds by
`--stability-concurrency`, and their sum by the process FD budget. If the hold
pool is full, the result records `capacity_limited`; it is not counted as
stable. The per-session deadline is clamped to at least 8,000 ms by the
Cloudflare task.

The old shared-slot design had a modeled ceiling of `64 / 5 s = 12.8`
endpoints/s during a five-second hold, independent of network speed. The new
pool planner regression proves a 64-active plus 512-hold plan under a 4,096-FD
budget and the expected reductions under smaller candidate and FD budgets.
That removes the structural ceiling; it is **not** a measured speedup. No
authorized, thermally controlled A-B-A public-route benchmark was run for this
revision.

A limited run sends every collected candidate, up to the limit, into full verification. Large `--limit` values can therefore make the verification phase much longer than the initial sweep. The TUI keeps rendering atomic progress during this background pass and allows cancellation with `x`; headless mode remains preferable for unattended large finalist sets.

RTT reporting uses minimum, median, nearest-rank p90, loss, and the mean absolute difference between consecutive successful observations. That last value is not RFC 3550 jitter and is named accordingly in JSON/CSV. The two-sided distribution-free 90% median interval is available only with at least five successful RTT observations. A fixed baseline calibrated from the first three successful measurement RTTs only decides whether sequential sampling needs more budget; it does not change a network verdict or historical confidence.

## ARM64 Crypto A/B Checks

On AArch64, Qanat dispatches to supported crypto extensions at runtime. The scalar fallback can be forced for a controlled local comparison:

```bash
QN_NO_ASM=1 ./build/qanat --cf --quick --limit 64 --headless
```

Do not compare two public-network runs and attribute the difference entirely to assembly. Use the repository's local crypto benchmark or loopback verifier in a dedicated validation session, pin comparable cores, and report temperature. The normal binary must remain correct with both runtime paths.

## What Not to Claim

- Do not derive a phone benchmark from `--rate`; it is only a start-rate ceiling.
- Do not multiply concurrency by reciprocal timeout and present the result as measured throughput.
- Do not compare a short responsive-port scan with a full silent-port scan.
- Do not call an x86 or emulated AArch64 result a phone result.
- Do not claim a speedup from static code inspection alone.
- Do not report the fastest run without the median and spread.

The defensible statement is narrow: Qanat contains mechanisms intended to preserve throughput under mobile constraints. Their effect must be measured on the target phone and route.
