# Tunnel verification remediation

## Scope and decision

Qanat now has an optional final scan stage that proves a selected endpoint can
carry the user's proxy protocol. The implementation follows the external-Xray
design: Qanat starts a user-selected Xray executable at run time, drives its
loopback SOCKS5 inbound with Qanat's own client, then performs Qanat's normal
TLS and HTTP verification through that tunnel. No Xray library is linked and
the default build and default scan remain unchanged.

The stage is disabled until the user explicitly enables it. Before its first
run, both the proxy destination and the bounded candidate count are displayed
for confirmation. Installation is a separate confirmed menu action; selecting
a scan can never download software.

The detailed ownership, lifecycle and secret contracts are documented in
[TUNNEL-VERIFICATION.md](TUNNEL-VERIFICATION.md).

## Pre-patch reproduction

The unmodified `c24e92a` source was built in a separate archive before any
patch was applied. Reversing the old export oracle produced this failure:

```text
FAIL tests/test_export.c:155: strstr(body, "REPLACE_UUID") == NULL
export tests: 1 failure(s)
```

The original test required `REPLACE_UUID`, so it encoded the defect as the
expected result. The replacement tests require real link-derived, redacted
configuration data and reject placeholder leakage whenever a link is present.

## End-to-end contract

1. A bounded parser converts VLESS, Trojan or VMess input into one typed value.
2. The candidate IP replaces only `address`; server identity and credentials
   remain those of the link.
3. One builder emits both persistent redacted export and private live config.
4. A private `0600` temporary file is handed to a reaped Xray child.
5. Qanat performs SOCKS5 CONNECT, TLS and `GET /cdn-cgi/trace` itself.
6. Only a 2xx response containing `colo=` is a tunnel pass.
7. Every queued candidate reaches exactly one terminal accounting state.
8. Score version 3 orders tunnel pass, untested and tunnel failure separately.

## Findings and fixes

| Finding | Reproduction | Root cause | Fix | Evidence |
|---|---|---|---|---|
| Export was a template, not a usable configuration | Reverse the placeholder assertion in the old export suite | Export had a separate hard-coded builder | One policy-aware builder now owns live, redacted and template output | Exact config snapshots and export tests |
| Link grammar accepted ambiguous input | Feed duplicate fields, malformed percent escapes, invalid UTF-8 and non-canonical base64 | Decoding and semantic validation were not centralized | Bounded typed parser with duplicate detection and canonical decoding | Parser unit matrix and dedicated fuzz target |
| VMess accepted missing or loose version values | Omit `v`, use a non-number scalar or a version other than 2 | Generic scalar parsing did not enforce the VMess schema | Canonical JSON scalar parsing and mandatory numeric version 2 | Negative VMess parser cases |
| Trojan without `security` became plaintext | Parse a normal Trojan URI with no explicit security query | Generic defaults were applied across protocols | Trojan defaults to TLS while explicit supported values remain honored | Trojan default regression test |
| Retry count could exceed the promised bound | Configure more than two attempts | UI and runtime bounds had drifted | One-to-two attempt validation in CLI, editor, menu and runtime | Runtime rejects three attempts |
| PATH discovery did not control child execution | Select `auto` with a fake Xray available only through PATH | Discovery returned a resolved path but execution used the unresolved setting | Runtime copies the resolved executable into the effective child config | PATH-only fake-Xray regression test |
| Invalid runtime input left stale result fields | Pass invalid input with a non-zeroed result object | Only state and reason were overwritten | Result is initialized before any validation branch | Invalid-argument lifecycle test |
| Reserved-port errors could report the wrong cause | Force bind failure and allow cleanup to change `errno` | `close()` ran before the error was preserved | Preserve and restore the bind error across cleanup | Failure-path runtime tests |
| Installer cleanup could use uninitialized paths | Fail before all temporary names were constructed | Cleanup assumed every path buffer was initialized | Zero initialization and conditional unlink for every artifact | Strict analyzer and installer failure tests |
| Stage counters survived a reused scan context | Re-run a context after a partial tunnel stage | Tunnel counters were not reset at stage entry | Reset before selection and enforce the terminal sum invariant | Reuse and exact-accounting tests |
| Cancellation coverage skipped the active-child path | Keep cancellation set during setup iterations | The old test never progressed beyond early config rejection | Clear cancellation for pressure loops and cancel a stubborn child from a thread | Deadline, reap and no-zombie lifecycle test |
| Tunnel headers created an include cycle | Compile the ClientHello test as a narrow translation unit | Tunnel outcome types depended on the observation header | Tunnel uses an opaque forward declaration at the boundary | Independent ClientHello compilation and strict build |
| First-audit rejected the now-live P-256 path | Run `scripts/check_first_audit.sh` after adding complete browser key exchanges | The old oracle equated every P-256 symbol with previously removed dead code | Gate now proves linkage, TLS 1.2/1.3 consumption, peer validation and KAT coverage | First-audit passes the stronger five-part contract |
| Argument-free CLI was rejected as a tunnel request | Run the binary with redirected standard streams and no arguments | Default `xray_path="auto"` was indistinguishable from an explicit `--xray auto` | `NULL` means no option; discovery already treats it as automatic at the point of use | Existing redirected-stream PTY regression returns usage again |
| TLS session fuzz repeated unrelated key generation per input | Run the 20,000-input smoke target under sanitizers | Deterministic ClientHello setup, including ML-KEM and P-256, ran before every hostile record | Prepare one deterministic pre-record session and clone it before every input | Input count and parser state coverage remain unchanged while the gate is bounded |

## Configuration and schema migration

| Contract | Old | New | Migration rule |
|---|---:|---:|---|
| Settings / scan plan | 1 | 2 | Tunnel target remains zero and therefore unauthorized |
| Score | 2 | 3 | Old scores are never compared directly with version-3 scores |
| JSON result | 6 | 7 | Tunnel state becomes `untested`; measurements become unavailable |

Schema 7 records tunnel outcome, TTFB, bounded throughput, attempts and a
fixed non-secret failure reason for every result. It also records independent
queued, passed, failed and skipped totals. Credentials never enter a result,
event, history record, diagnostic string or persistent redacted export.

## Example workflow

The user supplies a link through the private link-file option and enables a
bounded final stage:

```text
qanat cf --ranges ranges.txt --tunnel-link-file private-link.txt \
  --tunnel-target 3 --tunnel-concurrency 2 --tunnel-attempts 2 \
  --xray auto --export json --output results.json
```

The confirmation screen shows the original proxy destination and that three
candidates will send real tunnel traffic. The credential is not displayed.
After confirmation, an illustrative final table is:

| Rank | Candidate | Edge evidence | Tunnel | Tunnel TTFB | Score class |
|---:|---|---|---|---:|---|
| 1 | `203.0.113.10` | verified marker | passed | 184 ms | proven tunnel |
| 2 | `203.0.113.11` | verified marker | untested | unavailable | edge only |
| 3 | `203.0.113.12` | verified marker | no-marker | unavailable | known failure |

The addresses are documentation-only ranges. A passed tunnel always ranks
above an edge-only candidate, while an untested candidate remains distinct
from a known tunnel failure.

## Validation matrix

The final source is gated by the following commands. Test fixtures bind only
to loopback and do not resolve or contact public hosts.

```text
make CC=gcc BUILD=build-x LTO= test
make CC=gcc strict
make CC=gcc strict-test
make CC=gcc analyze
make CC=gcc sanitize-test
make CC=gcc tsan-test
make CC=gcc fuzz-smoke
sh scripts/check_first_audit.sh
CC=gcc sh scripts/check_build_config.sh
make CC=gcc menu-test
make CC=gcc tls-test
make CC=gcc tunnel-local-test
```

The normal build executes nineteen host suites. The tunnel-local fixture uses
a fake Xray process and fake SOCKS5 peers to cover success, fragmented reads,
unexpected authentication, short replies, CONNECT failure, mid-stream close,
oversized response, deadline and cancellation. The fuzz smoke matrix includes
seven targets at 20,000 inputs each.

## Remaining risks

- No user endpoint was contacted during automated validation. A real tunnel
  pass is intentionally evidence that only an authorized user run can create.
- Xray's configuration surface can change. Unsupported future link fields fail
  closed until the bounded builder is updated and snapshot-tested.
- Xray does not accept an inherited listening socket. Qanat closes its reserved
  socket immediately before exec; a bind race is detected and retried, but
  cannot be eliminated without Xray socket activation.
- The Android installer supports the official ARM64 package. Other operating
  systems use discovery or a custom executable path.
- The installer verifies the release digest from the same distribution channel;
  the digest is not a separately pinned or signed trust root.
- Trace TTFB is implemented. Throughput remains unavailable unless a dedicated
  bounded bulk endpoint is configured, because `/cdn-cgi/trace` is not a valid
  throughput sample.
