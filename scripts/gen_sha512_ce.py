"""Emits sha512_ce.S. Round constants come from src/crypto/sha2.c and the round
schedule from its own recurrence, so nothing is transcribed by hand."""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SRC = os.path.join(ROOT, "src/crypto/sha2.c")
OUT = os.path.join(ROOT, "src/crypto/arm64/sha512_ce.S")

# --- constants -------------------------------------------------------------
text = open(SRC, encoding="utf-8").read()
i = text.index("static const uint64_t K512[80]")
body = text[text.index("{", i) + 1: text.index("};", i)]
K = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{16})", body)]
assert len(K) == 80, len(K)

# Spot-check the first and last against FIPS 180-4.
assert K[0] == 0x428a2f98d728ae22, hex(K[0])
assert K[79] == 0x6c44198c4a475817, hex(K[79])

# --- round schedule --------------------------------------------------------
# Five rotating state registers; the permutation repeats every five pairs.
PERM = [(0, 1, 2, 3, 4),
        (3, 0, 4, 2, 1),
        (2, 3, 1, 4, 0),
        (4, 2, 0, 1, 3),
        (1, 4, 3, 0, 2)]

# Eight schedule vectors hold sixteen words; the taps repeat every eight pairs.
def sched(n):
    return (16 + n % 8, 16 + (n + 1) % 8, 16 + (n + 7) % 8,
            16 + (n + 4) % 8, 16 + (n + 5) % 8)

rounds = []
for n in range(40):
    i0, i1, i2, i3, i4 = PERM[n % 5]
    s0, s1, s2, s3, s4 = sched(n)
    do_sched = 1 if n < 32 else 0
    if n % 4 == 0:
        rounds.append("    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64")
    rounds.append("    DR      %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d"
                  % (i0, i1, i2, i3, i4, s0, s1, s2, s3, s4, 24 + n % 4, do_sched))

# --- emit ------------------------------------------------------------------
out = []
w = out.append

w("/* SHA-512 compression on the ARMv8.2 SHA-512 instructions. */")
w("")
w("#if defined(__aarch64__)")
w("")
w('#include "abi.h"')
w("")
w("    .arch   armv8.2-a+sha3")
w("    QN_GNU_PROPERTY")
w("")
w("    .text")
w("")
w("/* Two rounds. v0..v4 rotate the state, v16..v23 hold the sixteen words. */")
w("/* v5 is dead once the accumulate is done, so the schedule tap reuses it. */")
w(".macro  DR  i0, i1, i2, i3, i4, in0, in1, in2, in3, in4, rc, sched")
w("    add     v5.2d, v\\rc\\().2d, v\\in0\\().2d")
w("    ext     v6.16b, v\\i2\\().16b, v\\i3\\().16b, #8")
w("    ext     v5.16b, v5.16b, v5.16b, #8")
w("    ext     v7.16b, v\\i1\\().16b, v\\i2\\().16b, #8")
w("    add     v\\i3\\().2d, v\\i3\\().2d, v5.2d")
w("  .if \\sched")
w("    ext     v5.16b, v\\in3\\().16b, v\\in4\\().16b, #8")
w("    sha512su0   v\\in0\\().2d, v\\in1\\().2d")
w("  .endif")
w("    sha512h q\\i3, q6, v7.2d")
w("  .if \\sched")
w("    sha512su1   v\\in0\\().2d, v\\in2\\().2d, v5.2d")
w("  .endif")
w("    add     v\\i4\\().2d, v\\i1\\().2d, v\\i3\\().2d")
w("    sha512h2    q\\i3, q\\i1, v\\i0\\().2d")
w(".endm")
w("")
w("/* void qn_sha512_blocks_ce(uint64_t state[8], const uint8_t *data, size_t blocks) */")
w("    .global qn_sha512_blocks_ce")
w("    .type   qn_sha512_blocks_ce, %function")
w("    .align  4")
w("qn_sha512_blocks_ce:")
w("    QN_BTI_C")
w("    cbz     x2, .Lsha512_ret")
w("    adrp    x3, .LK512")
w("    add     x3, x3, :lo12:.LK512")
w("    ld1     {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]")
w("")
w(".Lsha512_block:")
w("    mov     x4, x3")
w("    ld1     {v16.2d, v17.2d, v18.2d, v19.2d}, [x1], #64")
w("    ld1     {v20.2d, v21.2d, v22.2d, v23.2d}, [x1], #64")
for r in range(16, 24):
    w("    rev64   v%d.16b, v%d.16b" % (r, r))
w("    mov     v28.16b, v0.16b")
w("    mov     v29.16b, v1.16b")
w("    mov     v30.16b, v2.16b")
w("    mov     v31.16b, v3.16b")
w("")
out.extend(rounds)
w("")
w("    add     v0.2d, v0.2d, v28.2d")
w("    add     v1.2d, v1.2d, v29.2d")
w("    add     v2.2d, v2.2d, v30.2d")
w("    add     v3.2d, v3.2d, v31.2d")
w("    subs    x2, x2, #1")
w("    b.ne    .Lsha512_block")
w("")
w("    st1     {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]")
w(".Lsha512_ret:")
w("    ret")
w("    .size   qn_sha512_blocks_ce, .-qn_sha512_blocks_ce")
w("")
w("    .section .rodata")
w("    .align  4")
w(".LK512:")
for n in range(0, 80, 2):
    w("    .quad   0x%016x, 0x%016x" % (K[n], K[n + 1]))
w("")
w('    .section .note.GNU-stack,"",%progbits')
w("")
w("#endif /* __aarch64__ */")

open(OUT, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
print("wrote sha512_ce.S: %d constants, %d round pairs" % (len(K), len(rounds)))
