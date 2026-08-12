# TLS Scope and Trust Boundary

Qanat's TLS implementation is a **measurement client**, not a security library. It exists so the scanner can observe whether a path carries a complete encrypted exchange without adding a runtime dependency.

**Do not reuse this code to protect credentials, user data, control traffic, or application sessions. Use a maintained TLS library for those jobs.**

## What the Client Implements

The bounded client supports the handshake shapes Qanat needs:

- TLS 1.3 with AES-128-GCM-SHA256, AES-256-GCM-SHA384, and ChaCha20-Poly1305-SHA256;
- TLS 1.2 ECDHE with AES-GCM or ChaCha20-Poly1305 and RSA or ECDSA authentication framing;
- X25519 ephemeral key agreement;
- ALPN negotiation for `h2` and `http/1.1`;
- versioned Chrome Android, Firefox Android, Safari iOS, and randomized
  ClientHello profiles;
- JA3 and JA4 calculation over the emitted ClientHello;
- authenticated record encryption/decryption;
- transcript hashing, key derivation, and peer `Finished` verification;
- leaf-certificate subject and issuer extraction for display only.

Unsupported protocol states are rejected for the measurement rather than partially emulated. HelloRetryRequest is currently reported as unsupported, and only the offered key-exchange and AEAD families are accepted.

## What Is Not Authenticated

Qanat does not verify:

- the certificate chain or trust anchor;
- hostname or SNI coverage;
- certificate validity dates or revocation;
- the TLS 1.3 `CertificateVerify` signature;
- the TLS 1.2 `ServerKeyExchange` signature;
- whether the displayed certificate belongs to Cloudflare;
- whether an interception endpoint terminated the connection.

Certificate messages and signatures are checked only enough to preserve bounded framing and handshake order. Subject and issuer text is diagnostic metadata, not verified identity.

## What `Finished` Proves

The peer `Finished` value is computed from the derived handshake secret and the transcript. A match proves that the endpoint completing this handshake derived the same ephemeral secrets and authenticated the same transcript.

It does **not** prove who that endpoint is. A proxy or interception device that terminates TLS with its own key material and certificate can produce a valid `Finished` value. Certificate and handshake-signature verification are what would bind the exchange to an authenticated identity, and Qanat deliberately does not perform them.

Cloudflare identity is therefore a separate application-layer observation: Qanat requests `/cdn-cgi/trace` on the same TLS connection and looks for bounded Cloudflare response markers such as `colo=XXX` or relevant headers.

## Observation and Classification

TLS and HTTP parsers produce facts and never assign a verdict. Both HTTP
transports feed one canonical HTTP observation and one edge-evidence policy.
The pure classifier returns two independent fields:

| Axis | Values and meaning |
| --- | --- |
| `highest_rung_reached` | `none`, `tcp`, `handshake`, `http`, `cf-marker-observed`, `flowing-after-marker`, or `stable-after-marker` |
| `terminal_outcome` | `success`, `dead`, `local-error`, `peer-rejected`, `protocol-invalid`, `unsupported`, `reset`, `timeout`, `cancelled`, `interference-suspected`, `inconclusive`, or `pending` while unfinished; path is a separate failure origin |

A non-success terminal takes precedence in the derived display string. Thus a
valid TLS handshake followed by malformed HTTP is recorded as a protocol
failure with the reached rung retained only as diagnostic history; it cannot
be displayed or exported as a successful handshake/edge result.

The classifier preserves local, peer, path, protocol, and unsupported origins
separately. These labels describe observations, not their ultimate cause.
Active interference, an incompatible server, packet loss, overload, a
middlebox, or a route change can still produce superficially similar behaviour.

`stable-after-marker` is an idle-survival observation. Its ordering records
that a marker was observed first; it is not independently authenticated
identity. Tunnel-template export additionally requires a completed
verification, a successful terminal, and `cf-marker-observed` or a higher
marker-derived rung. Handshake-only and preliminary records are excluded.

After TLS 1.3 read keys are live, plaintext Alert records are invalid; alerts
must be carried inside authenticated application-data records. TLS 1.3
Certificate messages are streamed through request-context, list, entry, and
extension lengths with a cumulative cap and at least one entry. TLS 1.2
NewSessionTicket is accepted only in the legal post-handshake sequence.

## Randomness

Normal ephemeral material is requested through the Linux `getrandom` system call, with `/dev/urandom` as a fallback. If both fail, the scanner has a last-resort process PRNG so a measurement can still terminate; that path is not suitable for secrecy.

When `--seed` is supplied, Qanat deliberately uses reproducible PRNG output for the handshake. This helps audit probe ordering and output, but it removes cryptographic unpredictability. That is acceptable only because the connection protects no application secret.

## Cryptographic Implementation

The repository contains scalar C implementations of SHA-2, HMAC, HKDF, the TLS 1.2 PRF, X25519, AES-GCM, ChaCha20-Poly1305, and MD5 for JA3 only. AArch64 builds can dispatch at runtime to hand-written AES/PMULL, SHA-256, and NEON ChaCha20 paths.

The code uses constant-shape comparison for authentication tags and wipes selected temporary secrets, but it is not hardened as a general cryptographic library:

- scalar AES uses table lookups;
- timing and cache side channels are outside the measurement threat model;
- field arithmetic and assembly have not received an independent audit;
- lifecycle, key isolation, and misuse resistance are intentionally narrower than a production TLS library.

## HTTP Scope After TLS

The post-handshake client supports the bounded pieces required for trace and flow measurement:

- HTTP/1.1 status/header parsing, fixed-length, chunked, and EOF bodies;
- HTTP/2 framing, SETTINGS/PING acknowledgement, bounded HPACK fields, DATA, and stream termination;
- response marker scanning across input-buffer boundaries.

It is not a browser or general proxy stack. Bounded HPACK static/dynamic fields
and RFC Huffman strings are supported, but arbitrary browser cache behaviour
is not. The trace body remains the primary edge marker.

## Validation Defined by the Repository

The source tree defines:

- known-answer tests for SHA-2, HMAC, HKDF, TLS key derivation, AES-GCM, ChaCha20-Poly1305, and X25519;
- ClientHello shape and JA3/JA4 checks;
- malformed and out-of-order ServerHello tests;
- a local OpenSSL TLS 1.2/1.3 handshake matrix across supported cipher families and browser profiles;
- an adversarial loopback peer for refused, reset, silence, non-TLS, early-EOF, and byte-drip behavior;
- ASan, UBSan, and TSan profiles;
- fuzz targets for TLS classification/session and HTTP parsers;
- AArch64 strict cross-build plus native-device core, TLS, verifier, ABI, and
  crypto-differential checks.

These are valuable engineering controls. They do not amount to an independent security audit, and their presence does not prove that every platform or network path has been exercised.

## Cross-layer fingerprint contract, 2026-08-11

The current implementation instantiates one immutable `qn_profile_instance`
per run from profile, seed, SNI, and certificate policy. Fingerprint preview,
wire ClientHello, verifier, H2/H1 request builders, and export all consume that
same instance. Random mode therefore creates one coherent cross-layer persona,
and GREASE is materialized once rather than re-randomized by each consumer.

Every built-in profile is capability-constrained. A ClientHello advertises only
TLS versions, cipher suites, signature algorithms, groups, key shares, ALPN
paths, and retry behavior that this bounded client implements. A requested
shape that cannot be completed is reported unsupported instead of serialized as
a plausible fingerprint. For identical profile, seed, and SNI,
`fingerprint show` and the verifier call the same ClientHello wire builder.

`qn_client_profile` is not a TLS-only label. One versioned profile controls the
ClientHello, H2 SETTINGS order/values, connection window, pseudo-header order,
regular-header order, User-Agent, Accept, Accept-Encoding, and HTTP/1 request.
The fixed names are `chrome-android-126`, `firefox-android-127`, and
`safari-ios-17`; aliases remain accepted for compatibility. `random`
materializes a seeded randomized TLS and HTTP/H2 shape rather than selecting a
fixed profile.

`qanat fingerprint show PROFILE` prints the ClientHello hex, JA3 string/hash,
JA4, H2 settings/window/order, H2 request hex, HTTP/1 request hex, and header
values. CI pins a SHA-256 snapshot over all of those fields for each fixed
profile and seeded random. Safari's JA3/JA4 and full cross-layer shape are now
part of the oracle. Invalid enums stringify as `invalid`, and parsers reject a
NULL output pointer.

## Historical fingerprint review, earlier 2026-08-11 pass

### A wrong fingerprint was indistinguishable from a right one

Every capacity limit on the fingerprint path failed silently. `note_cipher`,
`note_ext`, `note_group`, `note_sigalg` and the EC point-format recorder all
dropped a value once their array was full, and `sb_putc` dropped a character
once its buffer was full. Either produces a JA3 or JA4 string that is a prefix
of the truth, hashes cleanly, and looks like a legitimate fingerprint. For a
tool whose purpose is to present a specific ClientHello, emitting the wrong
fingerprint is worse than emitting none.

Two of those limits were reachable rather than theoretical:

- The JA3 string at the declared caps needs **551 bytes**; every caller passed
  `ja3str[512]`. Forty ciphers at five digits plus separators is 239 bytes on
  its own.
- `qn_tls_ja4` sorted the cipher list through `tmp[QN_HELLO_MAX_EXTS]`, which
  is 32, while `nciphers` may reach `QN_HELLO_MAX_CIPHERS`, which is 40. Eight
  ciphers would have been dropped from the hash input.

Neither fired with the three profiles present at that earlier point, which is
exactly why they would
have survived until a profile changed and then produced a plausible wrong
answer.

**Fix.** `qn_hello_info` gained an `overflow` flag that every recorder sets
instead of dropping quietly. `sb` tracks truncation. `qn_tls_ja3` and
`qn_tls_ja4` now return `bool` and yield an empty string rather than a digest
over a truncated input. `QN_JA3_STR_MAX` is 640, sized for every list at its
cap, and the callers use it. The JA4 scratch list is sized for the longer of
the two lists. `qn_verify_fingerprint` reports a preview only when both
fingerprints are real, since one of two is a half-truth.

### A test that checked half of what it claimed

`test_profiles_differ` wrote the JA3 hash into `seen[n]` and then immediately
overwrote it with the JA4 string. The JA3 call was dead: only JA4 was ever
compared. It now keeps both and asserts that each separates the profiles.

### Unchanged on purpose

The published JA3 and JA4 values for Chrome and Firefox remained an oracle for
that work. The continuation above adds Safari and full cross-layer pins for all
fixed profiles plus seeded random, closing the gap described by this historical
note.
