# Contributing to Qanat

Contributions should preserve Qanat's rootless Android operation, bounded-memory behavior, headless/TUI parity, and explicit measurement semantics.

## Development Setup

On Termux:

```bash
pkg update -y
pkg install -y clang make git openssl
git clone https://github.com/EntropyRoot/Qanat-Scanner.git Qanat-Scanner
cd Qanat-Scanner
make NATIVE=1
make install
```

For an existing checkout, inspect `git status --short` and use `git pull
--ff-only`; do not clone again over another directory and then build a stale
checkout.

Current Linux systems are supported for development and CI. Portable scalar paths allow x86-64 testing, but any performance claim for Android must also be measured on at least one real ARM64 phone.

## Required Validation

Before submitting a change, run the checks relevant to it. The complete local gate is:

```bash
make strict
make test
make tls-test
make sanitize-test
```

`make tls-test` requires the `openssl` command. Confirm that the script did not report `SKIP` before treating it as handshake validation.

For concurrency or lock-free changes, also run on a toolchain that supports TSan:

```bash
make tsan-test
make tsan
TSAN_OPTIONS=halt_on_error=1 ./build-tsan-app/qanat \
  --ports 127.0.0.1 -p 1-2000 \
  --headless --quiet --no-warm --no-affinity --no-thermal \
  --timeout 100 --retries 0
```

For parser, TLS, CIDR, or framing changes:

```bash
make fuzz
make fuzz-smoke
```

Do not call a change validated if the relevant command was skipped, unavailable, or only compiled without running.

## Real-Device Performance Work

Performance changes intended for Android must include:

- device model and SoC;
- Android, Termux, and compiler versions;
- exact source revision and build command;
- link type and authorized target workload;
- complete Qanat command;
- starting and peak temperature;
- multiple runs with median and spread;
- result counts and queue-drop status.

Compare like with like. A responsive localhost port set is not evidence for a silent cellular sweep. See [Measurement and performance](docs/PERFORMANCE.md).

## Code and Ownership Rules

- Use C11 and existing POSIX/Linux primitives. Do not add a third-party runtime dependency without a compelling architecture review.
- Keep allocations, logging, and formatting out of socket and parser hot paths.
- Preserve per-worker socket ownership and owner-thread sweep-result mutation. The deep verifier may own Cloudflare records only while the renderer is fenced to atomic progress.
- Treat file, CLI, terminal, certificate, banner, and network input as untrusted.
- Check sizes before arithmetic and before every bounded copy or append.
- **Comments are one line.** Not a paragraph, not a block. Write one only for
  an invariant, a protocol constraint, a memory-ordering requirement, or
  non-obvious mobile behaviour. If a comment needs several lines to explain
  what the code does, the code is wrong; fix the code. Reasoning that will not
  fit belongs in the commit message or in `docs/`, not above the function.
- Preserve scalar fallbacks when changing ARM64 assembly or dispatch.
- Preserve headless behavior whenever the TUI changes.
- Do not silently change verdict meaning, `--limit` semantics, output schema, or history format.
- Add deterministic tests for data structures, state transitions, and malformed input.

## Protocol Changes

Qanat implements bounded measurement clients, not general TLS or HTTP libraries. A protocol addition should state:

1. which real measurement it enables;
2. its input and memory bounds;
3. the unsupported states and failure behavior;
4. the new deterministic, adversarial, and fuzz coverage;
5. whether it changes a verdict or identity claim.

Read [TLS scope](docs/TLS.md) before changing handshake or certificate behavior.

## Pull Requests

Keep each change focused. The description should include:

- the concrete problem;
- the chosen trade-off;
- affected invariants and public behavior;
- validation actually performed;
- measurements, if performance is claimed;
- limitations or follow-up work that remains.

Network-dependent testing must use systems you own or are authorized to probe. Do not make a test depend on unrelated public infrastructure.
