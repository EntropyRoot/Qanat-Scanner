# End-to-end tunnel verification

## Decision

Qanat uses the preferred architecture: an optional external Xray executable and
a SOCKS5 client owned by Qanat. Nothing is linked into the application and the
default build has no new compile-time dependency. Xray is discovered only when
the user explicitly enables the tunnel stage. A missing executable is a typed
skip and can never be reported as a successful empty run.

This boundary keeps protocol churn in Xray while Qanat retains control of the
measurement. The TLS session inside the proxy, HTTP parser, Cloudflare marker
oracle, time source, retry budget, cancellation and accounting all remain Qanat
code. The default scan path never starts a child and never sends tunnel traffic.

Current Xray accepts `wsSettings`, `grpcSettings` and `xhttpSettings` in
`streamSettings`. Qanat emits only this bounded subset. Unsupported link fields
are rejected before a scan begins instead of being guessed or silently dropped.

## Data and secret boundary

The parsed link is a bounded value object. It contains the credential and is
owned by the run configuration; it is never copied into a record, diagnostic,
event, history entry, result schema or error string. Parser errors contain only
a typed reason and a field name from a fixed internal table.

One config builder owns both persistent Xray export structure and the live
configuration. It has an explicit secret policy:

- live mode requires a parsed link and places its credential in the private
  temporary configuration;
- persistent export never receives the credential and emits a redacted slot;
- template mode is used only when no link was supplied.

This policy resolves two otherwise incompatible requirements: a live config
must contain the credential, while a credential must never be written to an
export. The directly exercised artifact is the live private config, not a
persistent secret-bearing export. All non-secret fields in persistent export,
including path, SNI, host, transport and candidate address, come from the same
builder and are therefore identical to the live form.

## Candidate identity

Only the outbound server address changes per candidate. Port, SNI, Host,
transport, flow and every credential field retain the identity in the original
link. When the replacement address is an IP literal, the TLS settings include a
deduplicated `verifyPeerCertByName` value made from Host and SNI. It is omitted
for a DNS replacement address and for non-TLS links.

The inner measurement connects through SOCKS5 to `www.cloudflare.com:443`,
performs TLS with Qanat's selected fingerprint profile, and requests
`/cdn-cgi/trace`. Success requires both a 2xx response and a `colo=` marker.
TTFB is latched at the first HTTP response byte. The schema keeps a bounded
throughput field, but the scan stage currently leaves it unavailable: the trace
origin is a correctness oracle, not a bulk-download endpoint. The internal
runner can request a bounded sample only when a dedicated endpoint is supplied.

## Stage and ranking contract

The stage runs after deep verification and is independently bounded by target,
concurrency and per-candidate attempt count. Its default target is zero. Every
selected candidate transitions exactly once from queued to one terminal state:
passed, failed or skipped. Attempts are internal to that single accounting
unit. The invariant is:

`queued = passed + failed + skipped`

Tunnel state is separate from edge evidence. Ranking compares three ordered
classes before the existing score: tunnel passed, tunnel not tested, tunnel
failed. This guarantees that a proven proxy ranks above an edge-only candidate
without equating an untested candidate with a known tunnel failure. The score
component and score version make the policy visible in every export.

## Child and file lifecycle

For each active candidate Qanat reserves a loopback port with an atomic sequence
and a real bind. The reservation stays open while the private config is built
and checked. It is released immediately before Xray starts, and readiness is
proved by the SOCKS protocol itself. Another process can race in that unavoidable
bind-to-exec interval because Xray has no socket-activation interface; such a
race is detected as a startup or SOCKS failure and retried on a newly bound
port. It can never become a false tunnel success.

The config file is created with `O_EXCL`, mode `0600` and close-on-exec. Every
exit path unlinks it. Child standard streams go to `/dev/null`; inherited file
descriptors are closed. Children have a hard deadline, receive `SIGTERM` first,
then `SIGKILL`, and are always reaped. Cancellation bypasses the grace interval
and immediately tears down the verifier and child.

## Installation boundary

The numeric menu contains discovery, custom-path and install/update actions.
Installation is a separate explicit network operation with its own confirmation
and destination preview; enabling a scan never installs software. The installer
downloads the official Android ARM64 release and its digest, verifies SHA-256,
then renames the verified executable onto only the selected Xray path. Missing download or
archive tools is a typed install failure and does not alter Qanat or scan state.

Tests replace both Xray and SOCKS peers with loopback-only fixtures. No test or
fuzz target resolves or contacts a public address.

## Version and migration contract

This feature raises scan-plan/settings version to 2, score version to 3 and
JSON export schema to 7. A schema-6 migration initializes tunnel state to
`untested`, numeric tunnel measurements to zero, and never compares the old
score directly with version-3 results. Settings version 1 did not authorize
tunnel traffic and therefore migrates with the stage disabled.

## Outcome vocabulary

Every queued candidate terminates exactly once as `passed`, `binary-missing`,
`config-invalid`, `start-failed`, `socks-failed`, `probe-failed`, `no-marker`,
or `cancelled`. Run-level `incomplete` means the requested measurements did not
all prove a tunnel; it is never converted into a peer success.
