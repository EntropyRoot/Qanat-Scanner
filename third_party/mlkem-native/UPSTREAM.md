# mlkem-native snapshot

- Upstream: `https://github.com/pq-code-package/mlkem-native`
- Commit: `69d24e37b8a04c6050ec55bc84a4228d7051bb4b`
- Imported: 2026-08-12
- License choice used by Qanat: MIT; see `LICENSE`

Qanat vendors the portable single-compilation-unit source for ML-KEM-768.
Native assembly backends are deliberately not imported: the scalar C path is
the correctness baseline on every supported target. `src/crypto/mlkem.c`
namespaces the upstream symbols, disables the randomized convenience API, and
feeds entropy through Qanat's existing RNG boundary.

The TLS hybrid group uses the RFC 10024 layout:

```text
client share = ML-KEM-768 public key (1184) || X25519 public key (32)
server share = ML-KEM-768 ciphertext (1088) || X25519 public key (32)
secret       = ML-KEM-768 shared secret (32) || X25519 shared secret (32)
```
