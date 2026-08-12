/* SHA-256 compression on the AArch64 crypto extensions. */

#if defined(__aarch64__)

#include "abi.h"

    .arch   armv8-a+crypto
    QN_GNU_PROPERTY

    .text

/* Four rounds; the update makes \w the words needed four groups later. */
.macro  G   w, wa, wb, wc, sched
    ld1         {v16.4s}, [x5], #16
    add         v17.4s, \w\().4s, v16.4s
    mov         v18.16b, v0.16b
    sha256h     q0, q1, v17.4s
    sha256h2    q1, q18, v17.4s
  .if \sched
    sha256su0   \w\().4s, \wa\().4s
    sha256su1   \w\().4s, \wb\().4s, \wc\().4s
  .endif
.endm

/* void qn_sha256_blocks_ce(uint32_t state[8], const uint8_t *data, size_t blocks) */
    .global qn_sha256_blocks_ce
    .type   qn_sha256_blocks_ce, %function
    .align  4
qn_sha256_blocks_ce:
    QN_BTI_C
    cbz     x2, .Lsha_ret
    adrp    x4, .LK256
    add     x4, x4, :lo12:.LK256
    ld1     {v0.4s, v1.4s}, [x0]

.Lsha_block:
    mov     x5, x4
    ld1     {v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #64
    rev32   v4.16b, v4.16b
    rev32   v5.16b, v5.16b
    rev32   v6.16b, v6.16b
    rev32   v7.16b, v7.16b
    mov     v2.16b, v0.16b
    mov     v3.16b, v1.16b

    G   v4, v5, v6, v7, 1
    G   v5, v6, v7, v4, 1
    G   v6, v7, v4, v5, 1
    G   v7, v4, v5, v6, 1
    G   v4, v5, v6, v7, 1
    G   v5, v6, v7, v4, 1
    G   v6, v7, v4, v5, 1
    G   v7, v4, v5, v6, 1
    G   v4, v5, v6, v7, 1
    G   v5, v6, v7, v4, 1
    G   v6, v7, v4, v5, 1
    G   v7, v4, v5, v6, 1
    G   v4, v5, v6, v7, 0
    G   v5, v6, v7, v4, 0
    G   v6, v7, v4, v5, 0
    G   v7, v4, v5, v6, 0

    add     v0.4s, v0.4s, v2.4s
    add     v1.4s, v1.4s, v3.4s
    subs    x2, x2, #1
    b.ne    .Lsha_block

    st1     {v0.4s, v1.4s}, [x0]
.Lsha_ret:
    ret
    .size   qn_sha256_blocks_ce, .-qn_sha256_blocks_ce

    .section .rodata
    .align  4
.LK256:
    .word   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

    .section .note.GNU-stack,"",%progbits

#endif /* __aarch64__ */
