# Qanat

[فارسی](README.fa.md)

Qanat is a rootless, high-throughput network connectivity analyzer written in C11 for Android devices running Termux, with optional hand-written AArch64 acceleration and complete scalar C fallbacks. It combines a mobile-aware TCP probe engine, single-host port scanning, local IPv4 discovery, path diagnostics, and a multi-stage Cloudflare IPv4 verifier in one dependency-free binary.

The project is designed around the limits that matter on a phone: small file-descriptor and conntrack budgets, heterogeneous ARM64 cores, cellular radio wake-up delay, thermal throttling, and expensive terminal rendering. It provides both an interactive TUI and a fully headless command-line interface.

**Qanat reports what the current device can observe on the current route.** Results can change with the operator, Wi-Fi network, VPN, location, congestion, and time. A result is not proof of nationwide reachability, blocking, or censorship.

## Capabilities

| Mode | Purpose |
| --- | --- |
| `--cf` | Sweep Cloudflare IPv4 prefixes, select promising regions adaptively, complete TLS, verify HTTPS edge markers, measure the path, and rank finalists |
| `--ports HOST` | Scan a custom set or all 65,535 TCP ports on one IPv4 or IPv6 host |
| `--discover [CIDR]` | Discover hosts on a local IPv4 prefix with an unprivileged ICMP attempt and TCP fallback |
| `--net` | Inspect interfaces, route, resolvers, public address, latency, DNS divergence, and captive-portal signals |

Core properties:

- **No root requirement:** scanning uses non-blocking TCP `connect()` and, where permitted, Linux ping sockets.
- **No third-party runtime dependency:** the executable uses C11, POSIX, and Linux interfaces only.
- **Two interfaces:** a damage-tracked terminal UI and a script-friendly headless mode use the same engine.
- **Bounded resources:** fixed probe slots, arenas, SPSC rings, a timeout wheel, and streaming Top-K selection avoid per-probe allocation.
- **Structured output:** JSON, CSV, an append-only verification log, and optional cross-run history are available.

## Why Qanat Is Mobile-Specific

Desktop scanners and mobile devices have different failure modes. Qanat treats those differences as part of the architecture:

- **FD and conntrack pressure:** the engine reserves descriptors for Termux, caps the automatic socket budget, and uses delay-aware AIMD to reduce the active window when timeouts, queueing delay, or local resource pressure increase.
- **big.LITTLE scheduling:** CPU clusters are detected from sysfs. I/O workers are placed across performance and middle clusters, with best-effort affinity when Android permits it.
- **Thermal throttling:** thermal-zone readings reduce the effective socket window before sustained heat causes a larger performance collapse.
- **Cellular radio state:** a short best-effort route warm-up runs before timed work unless `--no-warm` is selected.
- **TTY cost:** the TUI maintains a cell grid and repaints changed regions only. Headless mode avoids terminal rendering entirely.
- **Mobile ARM64 acceleration:** AArch64 builds include runtime-dispatched AES/PMULL, SHA-256, and NEON ChaCha20 assembly paths, with portable scalar fallbacks.

Qanat is not a raw-packet blaster. Its objective is **sustained, controlled measurement on an unrooted phone**, without overwhelming the device or its current network path.

## Architecture at a Glance

The cheap sweep path and the state-heavy verification path are deliberately separate:

```text
prefixes / ports
      |
      v
adaptive ordering or keyed permutation
      |
      v
pthread workers -> epoll/select -> non-blocking sockets -> timeout wheel
      |                                      |
      +---------- per-worker SPSC rings -----+
                                             |
                                             v
                                    owner / result thread
                                             |
                        +--------------------+--------------------+
                        |                    |                    |
                      TUI                headless             JSON/CSV

Cloudflare finalists -> bounded epoll verifier -> TLS 1.3/1.2
                     -> HTTP/2 or HTTP/1.1 -> trace/flow/idle checks
```

The Cloudflare sweep uses a Beta-Bernoulli block scheduler to spend early probes in productive address regions. A streaming Top-K heap keeps memory bounded during an unlimited sweep, and sequential sampling stops spending RTT probes once a finalist has enough evidence for a decision.

See [Architecture](docs/ARCHITECTURE.md), [Scan-plan architecture](docs/SCAN-PLAN.md), [Measurement and performance](docs/PERFORMANCE.md), and [TLS scope](docs/TLS.md) for the detailed design and trust boundaries.

## Install and Build on Termux

Run the following commands **one line at a time**:

```bash
pkg update -y
pkg install -y clang make git curl openssl
git clone https://github.com/EntropyRoot/Qanat-Scanner.git Qanat-Scanner
cd Qanat-Scanner
make NATIVE=1
make install
hash -r
qanat --version
qanat doctor
```

`NATIVE=1` enables `-mcpu=native` on an ARM64 phone. The release profile also uses `-O3`, section garbage collection, and ThinLTO with Clang.

The explicit clone destination and the following `cd` must match. `make
install` replaces the command in the Termux prefix; compiling alone does not
update an older `qanat` already found through `PATH`.

### Updating an Existing Checkout

Do not run `git clone` again when `~/Qanat-Scanner` already exists. Clone
creates a new checkout; it does not update the installed executable. Inspect
the existing tree, fast-forward it, rebuild, and install it:

```bash
cd "$HOME/Qanat-Scanner"
git status --short
git remote -v
git pull --ff-only
make NATIVE=1
make install
hash -r
qanat --version
```

Stop if `cd` fails, the remote is not the expected repository, the worktree has
changes you do not understand, or `git pull --ff-only` refuses. Do not delete
the old directory to hide one of those conditions. To diagnose a stale
launcher without changing anything, run `type -a qanat`, `qanat --version`, and
`ls -l "$PREFIX/bin/qanat"`.

Neither build nor installation requires root.

### Building from a Local Source Archive

Copy the ZIP into Termux storage, extract it, enter the extracted directory, and build:

```bash
pkg install -y clang make unzip
unzip Qanat-source.zip
cd Qanat-source
make NATIVE=1
./build/qanat --version
```

Adjust the archive and directory names to match the files you copied.

### If Termux Prints `Continue?` and Then `Abort`

Do not paste another command as an answer to the package-manager prompt. Use `-y` as shown above and wait for each command to finish. If repository selection or mirror access is the problem, run:

```bash
termux-info
termux-change-repo
pkg update -y
pkg install -y clang make git curl openssl
```

Choose a reachable main-repository mirror in `termux-change-repo`, then continue with the build commands. Keep the complete error output if the failure persists.

### Build Profiles

| Command | Purpose |
| --- | --- |
| `make` | Portable optimized release build |
| `make NATIVE=1` | On-device ARM64-tuned release build |
| `make strict` | Warning-clean build with `-Werror` and conversion checks |
| `make test` | Deterministic core, crypto, engine, verifier, export, TLS-parser, and property tests |
| `make offline-test` | Deterministic suite that never opens a real network socket |
| `make strict-offline-test` | Warning-clean execution of the offline allowlist |
| `make sanitize-offline-test` | Offline allowlist under ASan and UBSan |
| `make tsan-offline-test` | Offline allowlist under ThreadSanitizer where supported |
| `make menu-test` | Drive the numeric launcher through a real pseudo-terminal |
| `make tls-test` | Local TLS 1.2/1.3 handshake matrix against OpenSSL |
| `make analyze` | Build the complete application with GCC's path-sensitive analyzer |
| `make check` | Strict build, all suites, numeric-menu PTY tests, and the OpenSSL matrix |
| `make debug` | ASan/UBSan application build |
| `make sanitize-test` | Tests under ASan and UBSan |
| `make tsan-test` | Tests under ThreadSanitizer on a supported Linux toolchain |
| `make fuzz` | Build libFuzzer targets with Clang |

If ThinLTO is unavailable in a custom toolchain:

```bash
make NATIVE=1 LTO=
```

## Quick Start

The examples use `./build/qanat`. After `make install`, replace it with `qanat`.

### Numeric Launcher

Run the binary without arguments in a terminal:

```bash
./build/qanat
```

The numbered main menu offers `1) CDN analyzer`, `2) Host scanner`, and `3) LAN and network tools`. The CDN settings contain a dedicated **Scan Plan** page. From the TUI alone, users can select Auto, Full Range, Percentage, Fixed Address Budget, or Reachable Target; choose Uniform, Stratified, Adaptive, or Hybrid selection; set candidate capacity, total finalists including All Candidates, output Top-N, three independent concurrency limits, ranking, and memory budget; save the settings; and inspect the resolved range, memory, FD, candidate, finalist, and verification-batch plan before starting. A very large full traversal requires explicit confirmation.

On phone terminals 48 through 71 columns wide, Scan Plan uses a scrollable single-panel layout. Review then shows a compact Resource Plan containing the same validated totals, pipeline limits, concurrency, memory, and FD evidence as the wide two-panel layout. A terminal is rejected only when the usable body is smaller than 48x12; Qanat never invents a larger size.

The launcher is only used when standard input and output are terminals. Scripts, pipes, and redirected runs keep the existing headless CLI behavior.

### Inspect the Current Network

```bash
./build/qanat --net --headless
```

Save a machine-readable report:

```bash
./build/qanat --net --headless --json network.json
```

### Scan One Host

Scan common ports:

```bash
./build/qanat --ports example.com -p top --headless
```

Scan a custom list and range:

```bash
./build/qanat --ports 192.168.1.10 -p 22,80,443,8000-8100 --headless
```

Scan every TCP port from 1 through 65,535 on an authorized target:

```bash
./build/qanat --ports 192.168.1.10 -p all --headless --json ports.json
```

The port specification `-` is equivalent to `all`, and all ports are the default when `-p` is omitted.

Prefer IPv6 when resolving a single-host target:

```bash
./build/qanat --ports example.com --ipv6 -p 80,443 --headless
```

Only confirmed open ports are printed as rows. JSON also records scanned, refused, and filtered counters. A refusal proves that the host answered; a silent port remains uncertain until the configured confirmation passes finish.

### Why a Full Port Scan Can Take Time

The default timeout is 1,200 ms and the default retry count is one. A host that silently drops most ports therefore costs far more time than one that quickly returns `RST`. AIMD may also reduce concurrency when many timeouts look like path saturation. This is intentional false-negative resistance, not a raw SYN-scan speed model.

For a known low-latency LAN target, a more aggressive authorized scan can start with:

```bash
./build/qanat --ports 192.168.1.10 -p all \
  --timeout 400 --retries 0 --headless
```

Do not copy those settings blindly to a cellular or high-latency route.

## Cloudflare IPv4 Scanner

Bulk Cloudflare scanning is intentionally IPv4. Exhaustive IPv6-prefix scanning is not operationally meaningful; IPv6 remains available in the single-host port scanner.

### Refresh the Prefix List

The executable includes a snapshot for immediate use. Refresh the managed cache with:

```bash
./build/qanat --update-ranges
```

The updater permits HTTPS only, applies size and time limits, rejects malformed, IPv6, duplicate, overlapping, or unexpectedly small lists, and installs a fully validated temporary file atomically under `${XDG_CACHE_HOME:-$HOME/.cache}/qanat/cloudflare-v4.txt`. A later `--cf` run uses that valid cache automatically; `--ranges` still selects an explicit custom file.

Resolve and run an automatic plan:

```bash
./build/qanat scan cf --scan-mode auto --headless --json cf-results.json
```

The resolved plan is printed before the first probe. Traversal policy, address selection, candidate capacity, total finalists, output count, and concurrency are separate controls. Common plans are:

```bash
# Every unique address across every loaded range, exactly once.
./build/qanat scan cf --scan-mode full --headless

# Exactly ceil(10% of unique addresses), with hybrid selection.
./build/qanat scan cf --scan-mode coverage --coverage 10% \
  --selection hybrid --headless

# Exactly min(250000, total unique addresses) attempts.
./build/qanat scan cf --scan-mode budget --address-budget 250000 --headless

# Successful stop after 4096 reachable candidates are retained.
./build/qanat scan cf --scan-mode reachable --reachable-target 4096 --headless

# Large independent candidate and finalist plans.
./build/qanat scan cf --scan-mode coverage --coverage 10% \
  --candidate-cap 65536 --finalists 256 --verify-concurrency 32 \
  --output-top 100 --memory-budget 256MiB --headless

# Verify every retained candidate in bounded batches.
./build/qanat scan cf --scan-mode budget --address-budget 250000 \
  --candidate-cap 65536 --finalists all --verify-concurrency 32 \
  --output-top all --memory-budget 512MiB --headless
```

Coverage is parsed with fixed-point integers from 0.01% through 100%; 100% is exactly Full. Full mode normalizes overlapping prefixes and attempts each unique address once. Percentage and budget progress use planned addresses, while reachable mode shows both retained-target progress and actual coverage.

Hybrid is the default selection: guaranteed stratified exploration comes before adaptive exploitation. Uniform and Stratified are representative of their planned sample; Adaptive and Hybrid are not. Every partial result and export is labelled **“best observed among scanned addresses.”**

Candidate capacity is streaming storage for promising endpoints, not an address budget. Finalists are the total robustly screened endpoints entering deep verification, not verifier concurrency. `--finalists 1024 --verify-concurrency 32` is valid and processes all 1,024 in bounded batches. `--output-top` changes only display/export count.

Legacy `--cf` remains supported and, when no `--limit` is given, preserves its full-traversal intent. `--limit N` is deprecated and maps to `--scan-mode reachable --reachable-target N`; it no longer defines candidate, finalist, output, or concurrency capacity. Conflicting old and new scope options are rejected with a precise error.

### Deep Verification with History

Deep mode is the default. It completes TLS, requests `/cdn-cgi/trace` over HTTPS on the same port 443 connection, and holds the connection for the configured idle period:

```bash
./build/qanat scan cf \
  --ranges cloudflare-v4.txt \
  --sni www.cloudflare.com \
  --deep \
  --scan-mode reachable --reachable-target 128 \
  --candidate-cap 4096 --finalists 128 --output-top 20 \
  --samples 5 \
  --idle 5000 \
  --fingerprint chrome \
  --history qanat-history.tsv \
  --event-log qanat-events.tsv \
  --headless \
  --json cf-results.json
```

`--quick` still performs a full TLS handshake and HTTPS trace request; it disables the optional transfer and idle-hold stages.

The history file applies a three-day evidence half-life. Recent repeated confirmation, especially on more than one local path tag, receives more weight than an old single observation. `--seed` makes target ordering and handshake randomness reproducible, but network response order and adaptive scheduling still make live runs non-identical.

`--samples N` controls the sequential RTT budget rather than forcing exactly N probes. An undecided finalist can receive up to `min(12, 2 × N)` measurement rounds, while clear cases stop earlier. The full verifier uses a deadline of at least 8,000 ms even when the sweep timeout is lower.

### Optional Throughput Sample

Bulk transfer is opt-in and requires an SNI that serves the generated `/<path>` request. For Cloudflare's speed endpoint:

```bash
./build/qanat scan cf \
  --ranges cloudflare-v4.txt \
  --sni speed.cloudflare.com \
  --flow-bytes 262144 \
  --scan-mode reachable --reachable-target 64 \
  --candidate-cap 4096 --finalists 64 \
  --deep \
  --headless \
  --event-log qanat-events.tsv
```

`--flow-bytes` accepts 0 through 16 MiB. A throughput sample is a short application-layer observation, not a general line-speed benchmark.

### Verification Pipeline

1. **Sweep:** duplicate-free non-blocking TCP/443 traversal under the resolved selection policy.
2. **Retain:** a streaming oversampled Top-K keeps promising candidates within the configured capacity.
3. **Screen:** the exact capability-constrained ClientHello for the immutable run profile identifies supported TLS paths.
4. **Calibrate:** a block-diverse cohort larger than the finalist count is re-sampled so one lucky minimum RTT cannot win.
5. **Select:** robust median, p90, loss, jitter, stability, confidence, and deterministic tie-breaks select the configured total finalists.
6. **Verify:** finalists are processed in bounded batches; each deep verifier completes supported TLS, authenticates records and peer `Finished`, then requests `/cdn-cgi/trace` over HTTP/2 or HTTP/1.1.
7. **Rank:** marker evidence, robust latency, stability, confidence, and optional throughput feed versioned score components before output Top-N is applied.

The browser-shaped profiles are selected with:

```bash
--fingerprint chrome
--fingerprint firefox
--fingerprint safari
--fingerprint random
```

The fixed names are `chrome-android-151`, `firefox-android-153`, and
`safari-ios-26`; the short and previous versioned names remain aliases. One
immutable `qn_profile_instance` supplies the TLS/HTTP persona and a fresh wire
seed supplies per-connection GREASE, Chrome extension permutation, ECH padding,
randoms, and keys. Explicit seed plus connection index is reproducible.

Chrome 151 and Firefox 153 TLS and HTTP/1 fixtures were captured from the
connected Android phone through bounded localhost collectors. Safari 26 is
source/reference-derived because no iOS device was sampled. The browser offer
may include legacy branches outside Qanat's bounded executor; selecting one
returns typed `unsupported`. See the sanitized
[Android TLS fixture](docs/evidence/android-clienthello-2026-08-12.json),
[Android HTTP fixture](docs/evidence/android-http1-2026-08-12.json), and
[direct Cloudflare evidence](docs/evidence/cloudflare-tls-2026-08-12.json).

### Verdicts and Trust Boundary

| Verdict | What Qanat observed |
| --- | --- |
| `dead` | No usable TCP connection |
| `local-error` | A local syscall, descriptor, allocation, or event-loop failure prevented a network conclusion |
| `inconclusive` | Path or network state was insufficient for attribution, such as an unreachable route |
| `peer-rejected` | The peer explicitly refused, alerted, hung up, or closed before completing supported TLS |
| `unsupported` | The peer selected a valid protocol shape that this bounded client does not implement |
| `protocol-invalid` | The received TLS/protocol sequence was malformed, out of order, or failed record/Finished authentication |
| `reset-before-tls` | A reset occurred before a supported TLS handshake completed |
| `timeout-before-tls` | Connect or supported TLS handshake did not complete before its deadline |
| `interference-suspected` | Reserved for corroborated multi-signal evidence; a timeout or reset alone never earns it |
| `tcp` | TCP connected, but later verification did not complete |
| `handshake` | A complete supported TLS handshake finished and the peer `Finished` value matched |
| `cf-marker-observed` | Cloudflare application-layer markers were found over HTTPS on the same port 443 connection |
| `flowing-after-marker` | The requested bounded transfer completed after marker observation |
| `stable-after-marker` | The connection survived the configured idle hold after marker observation |

**The TLS client does not verify the certificate chain, hostname, dates, revocation, or CertificateVerify signature.** A valid `Finished` proves shared handshake keys, not Cloudflare identity and not the absence of interception. Treat `cf-marker-observed` or a higher marker-derived rung as the CDN observation. `stable-after-marker` is still only an idle-survival measurement.

Failure verdicts describe observations, not censorship or its cause. Firewall policy, server behavior, overload, CGNAT, route changes, packet loss, and active interference can produce similar symptoms. The separate `failure_origin`, `transport_result`, `tls_outcome`, `sys_errno`, and `reason` fields preserve the evidence used by the classifier.

Read [TLS scope](docs/TLS.md) before using these results for research or operational decisions.

### Optional End-to-End Tunnel Verification

Tunnel verification is off by default because it contacts the user's proxy
server and the public Internet. The numbered launcher exposes it under
`CDN Scanner -> Tunnel verification`, including hidden link input, a private
link-file path, Xray discovery/path selection, and an explicit Xray installer.
The installer is a separate confirmed network operation: on AArch64 it fetches
the official Android ARM64 release plus its `.dgst`, verifies SHA-256, and only
then installs the executable under `$PREFIX/bin` or `$HOME/.local/bin`.

For headless use, keep the credential out of the process list by using a mode
`0600` file and explicitly authorize traffic:

```sh
chmod 600 tunnel.link
qanat --cf --headless \
  --tunnel-target 5 --tunnel-concurrency 2 --tunnel-attempts 2 \
  --tunnel-link-file tunnel.link --xray auto --tunnel-confirm \
  --json results.json
```

Qanat substitutes only each candidate address. The original SNI, Host,
transport, path/service, ALPN, fingerprint and credential remain the user's
identity. It starts external Xray with a private temporary config, performs its
own SOCKS5 CONNECT, and sends `GET /cdn-cgi/trace` through Qanat's TLS stack.
Success requires HTTP 2xx plus `colo=`. Missing Xray is reported as
`binary-missing`; it is never an empty success or a scan failure.

The final order distinguishes `passed`, `untested`/`binary-missing`, and known
tunnel failures. The TUI and JSON/CSV exports include tunnel status, attempts,
TTFB, optional throughput and a bounded reason; credentials are never emitted.

### Using Confirmed CDN Candidates with Xray or sing-box

Qanat can emit a deliberately incomplete template after a Cloudflare scan:

```bash
./build/qanat scan cf \
  --sni tunnel.example.com \
  --quick --scan-mode reachable --reachable-target 128 \
  --candidate-cap 4096 --finalists 128 --headless \
  --export xray --export-file xray-template.json
```

The `list`, `xray`, and `singbox` exporters now include only records whose deep verification completed and whose verdict is `cf-marker-observed` or higher. A handshake-only, timeout, reset, unsupported, or preliminary result is never promoted into a tunnel template.

Without a tunnel link, Xray export remains an explicit `REPLACE_*` template.
When a link is configured, the same config builder used by live verification
emits the real transport and identity but replaces only the credential with
`<redacted>`. Runtime-only private configs are directly usable and are always
deleted after the child is reaped. These CDN candidates are not generic REALITY
destinations.

## Local IPv4 Discovery

Derive the active local prefix automatically:

```bash
./build/qanat --discover --headless
```

Or provide an explicit prefix:

```bash
./build/qanat --discover 192.168.1.0/24 --headless --json hosts.json
```

Discovery accepts `/16` through `/32`. Qanat first attempts an unprivileged ICMP echo socket. If the Android kernel or sandbox denies it, TCP probes against a small common-port set provide an ARP-less fallback without root.

## Interactive TUI

After the numeric launcher starts a mode, the TUI keeps navigation, progress, Scan Plan, resource preflight, and export controls available. The input decoder queues burst typing and paste bytes and incrementally handles split escape sequences, SS3, UTF-8, malformed input, and bracketed paste. Rendering commits its front model only after the complete frame is written; resize and small-terminal states do not forge a successful frame. Full Cloudflare TLS/HTTPS verification executes in bounded batches over an immutable finalist set. Pressing `x` produces a typed User Cancelled outcome and keeps settled preliminary evidence without racing the verifier.

```bash
./build/qanat --ports 192.168.1.10 -p top --tui
```

| Key | Action |
| --- | --- |
| `1` to `6`, `Tab` | Switch views |
| Arrow keys, `PgUp`, `PgDn`, `Home`, `End` | Navigate tables |
| `s` | Start the configured scan again |
| `x` | Stop the running scan |
| `e` | Export JSON and CSV |
| `q`, `Ctrl-C` | Quit |

When standard input or output is not a terminal, Qanat automatically uses headless mode.

## Engine Controls

Start with automatic settings. They inspect CPU topology and the current file-descriptor limit before allocating workers and sockets.

| Option | Effect |
| --- | --- |
| `-w, --workers N` | Worker count, 1 to 16 |
| `-c, --concurrency N` | Global in-flight ceiling, 32 to 4,096 |
| `-r, --rate N` | Maximum new starts per second in the parallel sweep engine |
| `-t, --timeout MS` | Per-stage deadline ceiling, 50 to 60,000 ms |
| `--retries N` | Zero to three confirmation passes for silent ports |
| `--verify-concurrency N` | Full TLS sessions in flight, 1 to 256 |
| `--stability-concurrency N` | Completed sessions held for stability independently of active TLS sessions |
| `--select` | Force the POSIX `select()` compatibility backend |
| `--no-adaptive` | Hold the probe window fixed |
| `--no-affinity` | Disable cluster-aware thread pinning |
| `--no-warm` | Skip cellular route warm-up |
| `--no-thermal` | Disable thermal window reduction |

`epoll` is the normal Android backend. The `select()` fallback is intended for compatibility and diagnostics and is constrained by `FD_SETSIZE`.

`--workers`, `--concurrency`, `--rate`, and AIMD govern the cheap parallel engine. Full TLS verification uses its own event loop and is bounded by `--verify-concurrency`; stability holds use `--stability-concurrency`. Neither value changes the total finalist count.

## Output and Reproducibility

- **Headless text:** compact rows suitable for pipes and shell tools.
- **JSON schema 7:** schema 6 fields plus the bounded tunnel plan and accounting, per-record tunnel status/TTFB/throughput/reason, and score version 3. Readers of schema 6 should initialize tunnel state to `untested`; readers must still reject unknown future schemas.
- **CSV:** spreadsheet-friendly result tables; banner formula prefixes are neutralized.
- **Tunnel templates:** marker-confirmed candidates only, with conspicuous credential/path placeholders.
- **Event log:** append-only detailed finalist observations, including TLS version, cipher, connect/handshake/TTFB timing, flow, idle hold, and certificate display fields.
- **History:** decayed cross-run evidence keyed by address and a privacy-preserving local path tag.

Exit status:

| Code | Meaning |
| ---: | --- |
| `0` | The requested operation completed and requested exports were written |
| `2` | Invalid command-line arguments |
| `3` | Failed run: initialization, engine/verifier infrastructure, or unrecoverable output failure |
| `4` | Incomplete run or requested transactional output not fully committed |
| `130` | Cancelled by the user |

Performance claims should include the exact command, device/SoC, Android and Termux versions, link type, target set, timeout, retries, rate, concurrency, temperature state, and multiple runs. Qanat intentionally ships no universal probes-per-second claim; network silence and policy dominate wall time on real phones.

## Limitations

- Rootless `connect()` scanning creates complete TCP connections. It is less stealthy and can be slower than a privileged raw SYN scanner.
- Port-scan and sweep RTT are TCP-connect measurements, not ICMP RTT or complete page-load latency.
- Certificate identity is displayed for diagnostics only and is not authenticated.
- The HTTP/2 and TLS implementations are bounded measurement clients, not general-purpose protocol libraries.
- Custom cryptographic code has not been independently audited and must not be reused to protect application data.
- The TUI runs full Cloudflare verification in a cancellable background worker, keeps rendering progress, and preserves preliminary results if the user cancels with `x`.
- Affinity, CPU frequency, ping sockets, and thermal data are best-effort on vendor Android kernels.
- VPNs, mobile radio state, CGNAT, traffic shaping, and route changes directly affect results.
- Cloudflare bulk scanning and local discovery are IPv4-only. IPv6 is supported by the single-host port scanner.
- Service names and banners are hints, not protocol authentication.

## Quality Gates

The repository contains nineteen host suites, including seventeen offline-only suites, cryptographic known-answer vectors, TLS 1.2/1.3 loopback interoperability tests against OpenSSL, adversarial loopback peers for transport and SOCKS5 failures, pseudo-terminal coverage for the numeric launcher, a whole-application GCC analyzer gate, sanitizer profiles, ThreadSanitizer coverage for the lock-free engine, seven parser/session fuzz targets, an AArch64 cross-build with crypto differential and ABI suites, and Android NDK/bionic builds at API 24 and 30.

These checks improve confidence but do not replace real-device validation or an independent cryptographic/security audit. See [Contributing](CONTRIBUTING.md) for the expected validation matrix.

## Responsible Use

Only scan systems and networks you own or are explicitly authorized to test. Start conservatively on shared, cellular, and production networks. Cloudflare anycast addresses are shared infrastructure; avoid unnecessary repeated scans and follow applicable provider policies and local law.

## Project Layout

```text
include/qanat/       Internal public interfaces
src/core/            Arena, topology, CIDR, scheduling, statistics, history
src/crypto/          Scalar primitives and runtime-dispatched ARM64 assembly
src/net/             Probe engine, TLS, HTTP/1.1, HTTP/2, deep verifier
src/task/            Port, Cloudflare, and discovery state machines
src/ui/              Terminal control, damage renderer, TUI widgets
src/data/            Service names and embedded Cloudflare IPv4 snapshot
tests/               Unit, vector, interoperability, and property tests
fuzz/                Bounded parser and TLS-session fuzz harnesses
scripts/             Local validation helpers
docs/                Architecture, performance, and TLS trust boundaries
```

## Security and Contributing

- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [TLS scope and limitations](docs/TLS.md)

## License

Qanat is released under the MIT License. See [LICENSE](LICENSE).
