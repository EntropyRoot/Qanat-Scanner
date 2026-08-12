# Security Policy

## Supported Version

Security fixes are applied to the latest revision on the default branch. Reports should identify the exact revision and build configuration used to reproduce the issue.

## Reporting a Vulnerability

Do not publish exploitable details in a public issue. Use the repository's private vulnerability-reporting channel and include:

- affected commit or source archive checksum;
- compiler, flags, architecture, Android/Linux, and Termux details;
- the smallest reliable reproduction;
- expected and observed behavior;
- impact and whether malformed network input is required;
- sanitizer, debugger, or packet-capture evidence when available.

Memory corruption, integer overflow, parser state confusion, authentication-check bypass, terminal escape injection, JSON/CSV/log injection, descriptor exhaustion, unbounded allocation, cross-thread races, unsafe signal handling, and sandbox escape are in scope.

## Important TLS Boundary

Qanat contains a custom bounded TLS measurement client. It **does not authenticate certificates or endpoint identity** and must not be used to protect application data. Missing certificate verification is a documented product boundary, not a report by itself. A memory-safety flaw, record-authentication bypass, incorrect `Finished` acceptance, or discrepancy from the documented boundary is in scope.

Read [TLS scope and trust boundary](docs/TLS.md) for the precise guarantees.

## Scanner Safety

Qanat is designed to run without elevated privileges and should remain unprivileged. Only scan systems and networks for which you have explicit authorization. A security report must not depend on probing unrelated third-party infrastructure.

Use local fixtures, loopback adversarial peers, or an owned lab target whenever possible. Remove addresses, credentials, subscriber identifiers, and unrelated packet contents before sharing diagnostic material.
