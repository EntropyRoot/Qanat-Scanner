# AArch64 crypto annotated disassembly

Date: 2026-08-11

Baseline commit: `1fe9d8d83a65ea7f58b286e24c581d1587c8d34a`

Current binary: `build-arm64-api24-final/test_crypto_diff`

Current SHA-256: `e533e00c9e1570a325e3b4e0a5a48cc2fe801827f2f8e0574540cc86d6fe1624`

## Reproduce

```powershell
$bin = 'build-arm64-api24-final/test_crypto_diff'
$objdump = "$env:LOCALAPPDATA\Android\Sdk\ndk\27.2.12479018\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-objdump.exe"
$nm = "$env:LOCALAPPDATA\Android\Sdk\ndk\27.2.12479018\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-nm.exe"
& $nm --print-size --size-sort $bin
& $objdump -d --disassemble-symbols=qn_aes_ctr_ce $bin
```

Repeat the last command for every symbol listed below. The inspected binary was
built by NDK r27c Clang/LLD 18.0.3 for AArch64 Android API 24 with `-O3`,
`-march=armv8-a`, strict warnings, and section garbage collection.

## Size, frame, and preservation summary

Sizes come from `llvm-nm --print-size`. A dash means the entry did not exist at
the baseline commit.

| Symbol | Baseline bytes | Current bytes | Maximum frame | Nonvolatile handling |
|---|---:|---:|---:|---|
| `qn_aes_encrypt_ce` | 228 | 228 | 0 | uses caller-saved vectors only |
| `qn_aes_ctr_ce` | 940 | 944 | 16-byte tail scratch | `v31` replaces ABI-breaking `v8` |
| `qn_aes_gcm_encrypt_ghash_ce` | - | 1,588 | 80 | saves/restores `d8-d15` |
| `qn_ghash_ce` | 148 | 508 | 0 | reduction scratch moved to `v16` |
| `qn_ghash_gcm_ce` | - | 1,356 | 16-byte transient blocks | caller-saved registers only |
| `qn_sha256_blocks_ce` | 488 | 488 | 0 | caller-saved registers only |
| `qn_chacha20_1x_neon` | - | 384 | 64-byte keystream | avoids `v8-v15` |
| `qn_chacha20_4x_neon` | 1,000 | 1,028 | 0, was 272 | avoids `v8-v15` |
| `qn_poly1305_blocks_aarch64` | - | 316 | 32 | saves/restores `x19-x20` |
| `qn_wipe` | 20 | 28 | 16 | saves/restores `x19` and LR |

SHA-512 is C rather than assembly, but it was inspected because stack pressure was
an explicit target. `sha512_block` changed from 432 to 464 bytes of code while its
frame fell from 720 bytes (`0x50 + 0x280`) to 224 bytes (`0xe0`).

## `qn_aes_encrypt_ce`

The entry is frameless. Round keys and state remain in `v0` and `v16-v30`, all
caller-saved. The only conditional branch selects the public 10-round or 14-round
schedule.

```text
0000000000009dc0 <qn_aes_encrypt_ce>:
    ... ld1     { v16.16b, v17.16b, v18.16b, v19.16b }, [x0], #64
    ... rev32   v16.16b, v16.16b
    ... cmp     w1, #0xa
    ... aese    v0.16b, v16.16b
    ... aesmc   v0.16b, v0.16b
    ... st1     { v0.16b }, [x3]
    ... ret
```

Review: no stack, no nonvolatile register, no table lookup, no secret branch.
Input/output may be unaligned because `ld1/st1` are used. Exact in-place operation
passes differential tests.

## `qn_aes_ctr_ce`

The zero-length return occurs before key loads. Four counters are encrypted in
parallel. The previous fourth input load into `v8` is now in caller-saved `v31`.

```text
00000000000093d0 <qn_aes_ctr_ce>:
    93d0: cbz     x5, 0x977c
    ...   aese    v0.16b, v16.16b
    ...   aesmc   v0.16b, v0.16b
    9668: ld1     { v5.16b, v6.16b, v7.16b }, [x3], #48
    966c: ld1     { v31.16b }, [x3], #16
    967c: eor     v3.16b, v3.16b, v31.16b
    9740: sub     sp, sp, #0x10
    ...   ldrb/strb                         ; public short tail only
    976c: add     sp, sp, #0x10
    977c: ret
```

Review: the only frame is 16-byte aligned and exists only while copying the final
public tail. The round-count branch is key-size dependent, not key-value
dependent. Counter increments and tail bounds are public. No read occurs beyond
the requested input length.

## `qn_aes_gcm_encrypt_ghash_ce`

This coarse entry has eight register arguments. A zero length returns before the
frame. The live GHASH powers and accumulator use `v8-v15`, so the AAPCS64-required
low halves are preserved explicitly.

```text
0000000000009780 <qn_aes_gcm_encrypt_ghash_ce>:
    9780: cbz     x6, 0x9db0
    9784: sub     sp, sp, #0x50
    9788: stp     d8, d9, [sp]
    978c: stp     d10, d11, [sp, #0x10]
    9790: stp     d12, d13, [sp, #0x20]
    9794: stp     d14, d15, [sp, #0x30]
    ...   aese/aesmc                       ; four counters
    ...   st1     { v0.16b-v3.16b }, [x5]  ; produced ciphertext
    ...   rbit                             ; GCM polynomial representation
    ...   pmull/pmull2                     ; H4/H3/H2/H schedule
    ...   ldp     d8, d9, [sp]
    ...   ldp     d14, d15, [sp, #0x30]
    ...   add     sp, sp, #0x50
    9db0: ret
```

Review: 80 is a multiple of 16. Every framed path reaches all four restores. The
partial block uses the final 16 bytes of this frame, writes only requested output,
zero-pads only the local authentication block, and does not reread ciphertext.
Branches depend on public length and AES round count.

## `qn_ghash_ce`

The four-block schedule loads H through H4 once, combines four 256-bit products,
and reduces once. `v16` is caller-saved and replaces the old ABI-breaking `v8`
scratch.

```text
0000000000009eb0 <qn_ghash_ce>:
    ... ld1     { v17.16b }, [x1], #16     ; H
    ... ld1     { v20.16b }, [x1]          ; H4
    ... rbit    v17.16b, v17.16b
    ... cmp     x3, #0x4
    ... pmull   v3.1q, v2.1d, v20.1d
    ... pmull2  v4.1q, v2.2d, v20.2d
    ... ext     v16.16b, v6.16b, v31.16b, #8
    ... pmull   v16.1q, v16.1d, v30.1d
    ... rbit    v0.16b, v0.16b
    ... st1     { v0.16b }, [x0]
    ... ret
```

Review: frameless, no `v8-v15`, no `x19-x29`, and no data-dependent address.
The block-count loop is public. Differential tests cover initial accumulators,
unaligned data, H powers, zero blocks, tails handled by C, and one MiB inputs.

## `qn_ghash_gcm_ce`

The coarse entry keeps H powers and the accumulator live across both GCM streams.
Its only frames are 16-byte temporary blocks for partial AAD, partial ciphertext,
and the public length encoding; each is released before the next stage.

```text
000000000000a0b0 <qn_ghash_gcm_ce>:
    ... movi    v0.16b, #0
    ... ld1/rbit v17-v20                   ; H through H4
    ... cmp     x3, #0x40                  ; public AAD groups
    ... cmp     x5, #0x40                  ; public CT groups
    ... sub     sp, sp, #0x10
    ... stp     xzr, xzr, [sp]             ; zero-padded partial
    ... add     sp, sp, #0x10
    ... lsl/rev x8, x6, #3                 ; encoded AAD bit length
    ... lsl/rev x9, x7, #3                 ; encoded CT bit length
    ... st1     { v0.16b }, [x0]
    ... ret
```

Review: all frame transitions retain 16-byte alignment. Byte-copy loops use only
public residual lengths. No call is made while a temporary frame is live. C checks
that the bit lengths and GCM counter range are representable before entry.

## `qn_sha256_blocks_ce`

The existing entry was unchanged at 488 bytes but was included in the ABI and
differential harness. It returns before touching state for zero blocks.

```text
000000000000a600 <qn_sha256_blocks_ce>:
    ... cbz       x2, return
    ... ld1       { v4.16b-v7.16b }, [x1], #64
    ... rev32     v4.16b, v4.16b
    ... sha256h   q0, q1, v17.4s
    ... sha256h2  q1, q18, v17.4s
    ... sha256su0 v4.4s, v5.4s
    ... sha256su1 v4.4s, v6.4s, v7.4s
    ... st1       { v0.4s, v1.4s }, [x0]
    ... ret
```

Review: frameless, caller-saved vectors only, fixed 64-round schedule, and a
public block-count loop. The SHA2 feature gate is separate from AES and PMULL.

## `qn_chacha20_1x_neon`

The one-lane entry stores one 64-byte keystream block, not secret state needed
across calls. It avoids all nonvolatile vector registers.

```text
000000000000a7f0 <qn_chacha20_1x_neon>:
    ... cbz     x5, return
    ... sub     sp, sp, #0x40
    ... mov     w7, #0xa
    ... add/eor/rev32/shl/sri               ; fixed 20 rounds
    ... st1     { v0.16b-v3.16b }, [sp]
    ... csel    x8, x5, #64, lo             ; public bytes this block
    ... ldrb/strb                           ; public residual tail
    ... add     sp, sp, #0x40
    ... ret
```

Review: 64-byte aligned frame, fixed round branch, linear public input/output,
and no secret lookup. It passes all differential tests but is force-only because
it is slower than scalar on the measured phone.

## `qn_chacha20_4x_neon`

The old entry allocated 272 bytes and used `v8-v15`. The current entry is
frameless and uses `v0-v7` plus `v16-v31`. Feed-forward inputs are reconstructed
from sigma, key, base counter plus lane offsets, and nonce.

```text
000000000000a970 <qn_chacha20_4x_neon>:
    a970: cbz     x5, 0xad70
    ...   ld1     { v30.4s, v31.4s }, [x0]  ; key
    ...   dup/add v20.4s, w1, v29.4s        ; four public counters
    ...   mov     w7, #0xa
    ...   add/eor/rev32/shl/sri              ; fixed 20 rounds
    abc4: dup     v24.4s, v28.s[0]           ; feed-forward rebuild
    ...   trn1/trn2                          ; block-major transpose
    ...   ld1/eor/st1                        ; four 64-byte blocks
    ad68: subs    x5, x5, #1
    ad6c: b.ne    0xa988
    ad70: ret
```

Review: no stack access, no nonvolatile register, no secret branch or lookup.
The caller validates the total counter range before dispatch. One group ending at
`UINT32_MAX` is covered explicitly. Exact in-place and offsets 0 through 15 pass.

## `qn_poly1305_blocks_aarch64`

The entry operates directly on the existing 3x44-bit `r` and `h` fields. Static C
offset assertions bind the layout to offsets 0 and 24.

```text
000000000000ad80 <qn_poly1305_blocks_aarch64>:
    ad80: cbz     x2, 0xaeb8
    ad84: sub     sp, sp, #0x20
    ad88: stp     x19, x20, [sp]
    ...   ldp     x15, x19, [x16], #16
    ...   extr    x20, x19, x15, #44
    ...   mul     x9, x0, x4
    ...   umulh   x10, x0, x4
    ...   adds/adc                           ; 128-bit product accumulation
    ...   extr    x19, x10, x9, #44         ; carry extraction
    ...   subs    x17, x17, #1
    ...   stp/str h0, h1, h2
    aeb0: ldp     x19, x20, [sp]
    aeb4: add     sp, sp, #0x20
    aeb8: ret
```

Review: 32-byte aligned frame and exact restore of both nonvolatile registers.
The loop count is the public number of complete blocks. Multiplication, carries,
and reduction have no conditional branch or indexed table. The C wrapper
normalizes the public full-block flag to zero or one before shifting it into the
implicit high bit.

## `qn_wipe` and rolling SHA-512

The generated wipe contains an actual `memset` call followed by the compiler
barrier represented by the retained ordering. It is not optimized out.

```text
0000000000009278 <qn_wipe>:
    9278: stp     x30, x19, [sp, #-0x10]!
    927c: mov     x2, x1
    9280: mov     w1, wzr
    9288: bl      memset@plt
    928c: ldp     x30, x19, [sp], #0x10
    9290: ret
```

The rolling SHA-512 schedule is visible as a 224-byte frame and modulo-16 indexed
loads instead of a 640-byte `w[80]` allocation:

```text
00000000000099b4 <sha512_block>:
    99b4: sub     sp, sp, #0xe0
    ...   str     x11, [sp, x8]              ; initial w[0..15]
    ...   and     x24, x3, #0xf              ; rolling slot
    ...   ldr     x22, [x5, x22, lsl #3]
    ...   str     x22, [x5, x24]
    ...   bl      qn_wipe                    ; wipe 128 schedule bytes
    ...   add     sp, sp, #0xe0
    ...   ret
```

## Constant-time branch and memory audit

| Symbol | Conditional inputs | Memory pattern | Tail policy | Result |
|---|---|---|---|---|
| AES block | public round count | fixed keys/state | none | accepted |
| AES CTR | public round count and length | linear input/output | bounded byte loop | accepted |
| fused AES-GCM | public round count and length | linear input/output, fixed H powers | local zero-pad | accepted |
| GHASH blocks | public block count | linear blocks, fixed H powers | caller supplies full blocks | accepted |
| coarse GHASH | public AAD/CT lengths | linear AAD/CT | local zero-pad | accepted |
| SHA-256 | public block count | linear blocks and fixed constants | none | accepted |
| ChaCha20 1x | fixed rounds and public length | linear input/output | bounded byte loop | accepted |
| ChaCha20 4x | fixed rounds and public groups | linear 256-byte groups | handled by C/scalar | accepted |
| Poly1305 | public block count | linear blocks, fixed state offsets | C handles partial final block | accepted |

No reviewed assembly instruction indexes memory with key, plaintext, ciphertext,
authentication state, or scalar bits. No reviewed conditional branch depends on
those values. This static review is paired with ABI and differential execution;
it does not replace external audit or formal verification.
