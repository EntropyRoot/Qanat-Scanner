# micro-ecc snapshot

- Upstream: `https://github.com/kmackay/micro-ecc`
- Commit: `541b3a78026420a3e369c4c9281c396b5e531113`
- Imported: 2026-08-12
- License: BSD-2-Clause; see `LICENSE.txt`

Qanat builds only the portable secp256r1 path. Other curves and optional
assembly paths are disabled in `src/crypto/p256.c`.
