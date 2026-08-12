/* SHA-512 compression on the ARMv8.2 SHA-512 instructions. */

#if defined(__aarch64__)

#include "abi.h"

    .arch   armv8.2-a+sha3
    QN_GNU_PROPERTY

    .text

/* Two rounds. v0..v4 rotate the state, v16..v23 hold the sixteen words. */
/* v5 is dead once the accumulate is done, so the schedule tap reuses it. */
.macro  DR  i0, i1, i2, i3, i4, in0, in1, in2, in3, in4, rc, sched
    add     v5.2d, v\rc\().2d, v\in0\().2d
    ext     v6.16b, v\i2\().16b, v\i3\().16b, #8
    ext     v5.16b, v5.16b, v5.16b, #8
    ext     v7.16b, v\i1\().16b, v\i2\().16b, #8
    add     v\i3\().2d, v\i3\().2d, v5.2d
  .if \sched
    ext     v5.16b, v\in3\().16b, v\in4\().16b, #8
    sha512su0   v\in0\().2d, v\in1\().2d
  .endif
    sha512h q\i3, q6, v7.2d
  .if \sched
    sha512su1   v\in0\().2d, v\in2\().2d, v5.2d
  .endif
    add     v\i4\().2d, v\i1\().2d, v\i3\().2d
    sha512h2    q\i3, q\i1, v\i0\().2d
.endm

/* void qn_sha512_blocks_ce(uint64_t state[8], const uint8_t *data, size_t blocks) */
    .global qn_sha512_blocks_ce
    .type   qn_sha512_blocks_ce, %function
    .align  4
qn_sha512_blocks_ce:
    QN_BTI_C
    cbz     x2, .Lsha512_ret
    adrp    x3, .LK512
    add     x3, x3, :lo12:.LK512
    ld1     {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]

.Lsha512_block:
    mov     x4, x3
    ld1     {v16.2d, v17.2d, v18.2d, v19.2d}, [x1], #64
    ld1     {v20.2d, v21.2d, v22.2d, v23.2d}, [x1], #64
    rev64   v16.16b, v16.16b
    rev64   v17.16b, v17.16b
    rev64   v18.16b, v18.16b
    rev64   v19.16b, v19.16b
    rev64   v20.16b, v20.16b
    rev64   v21.16b, v21.16b
    rev64   v22.16b, v22.16b
    rev64   v23.16b, v23.16b
    mov     v28.16b, v0.16b
    mov     v29.16b, v1.16b
    mov     v30.16b, v2.16b
    mov     v31.16b, v3.16b

    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      0, 1, 2, 3, 4, 16, 17, 23, 20, 21, 24, 1
    DR      3, 0, 4, 2, 1, 17, 18, 16, 21, 22, 25, 1
    DR      2, 3, 1, 4, 0, 18, 19, 17, 22, 23, 26, 1
    DR      4, 2, 0, 1, 3, 19, 20, 18, 23, 16, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      1, 4, 3, 0, 2, 20, 21, 19, 16, 17, 24, 1
    DR      0, 1, 2, 3, 4, 21, 22, 20, 17, 18, 25, 1
    DR      3, 0, 4, 2, 1, 22, 23, 21, 18, 19, 26, 1
    DR      2, 3, 1, 4, 0, 23, 16, 22, 19, 20, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      4, 2, 0, 1, 3, 16, 17, 23, 20, 21, 24, 1
    DR      1, 4, 3, 0, 2, 17, 18, 16, 21, 22, 25, 1
    DR      0, 1, 2, 3, 4, 18, 19, 17, 22, 23, 26, 1
    DR      3, 0, 4, 2, 1, 19, 20, 18, 23, 16, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      2, 3, 1, 4, 0, 20, 21, 19, 16, 17, 24, 1
    DR      4, 2, 0, 1, 3, 21, 22, 20, 17, 18, 25, 1
    DR      1, 4, 3, 0, 2, 22, 23, 21, 18, 19, 26, 1
    DR      0, 1, 2, 3, 4, 23, 16, 22, 19, 20, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      3, 0, 4, 2, 1, 16, 17, 23, 20, 21, 24, 1
    DR      2, 3, 1, 4, 0, 17, 18, 16, 21, 22, 25, 1
    DR      4, 2, 0, 1, 3, 18, 19, 17, 22, 23, 26, 1
    DR      1, 4, 3, 0, 2, 19, 20, 18, 23, 16, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      0, 1, 2, 3, 4, 20, 21, 19, 16, 17, 24, 1
    DR      3, 0, 4, 2, 1, 21, 22, 20, 17, 18, 25, 1
    DR      2, 3, 1, 4, 0, 22, 23, 21, 18, 19, 26, 1
    DR      4, 2, 0, 1, 3, 23, 16, 22, 19, 20, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      1, 4, 3, 0, 2, 16, 17, 23, 20, 21, 24, 1
    DR      0, 1, 2, 3, 4, 17, 18, 16, 21, 22, 25, 1
    DR      3, 0, 4, 2, 1, 18, 19, 17, 22, 23, 26, 1
    DR      2, 3, 1, 4, 0, 19, 20, 18, 23, 16, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      4, 2, 0, 1, 3, 20, 21, 19, 16, 17, 24, 1
    DR      1, 4, 3, 0, 2, 21, 22, 20, 17, 18, 25, 1
    DR      0, 1, 2, 3, 4, 22, 23, 21, 18, 19, 26, 1
    DR      3, 0, 4, 2, 1, 23, 16, 22, 19, 20, 27, 1
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      2, 3, 1, 4, 0, 16, 17, 23, 20, 21, 24, 0
    DR      4, 2, 0, 1, 3, 17, 18, 16, 21, 22, 25, 0
    DR      1, 4, 3, 0, 2, 18, 19, 17, 22, 23, 26, 0
    DR      0, 1, 2, 3, 4, 19, 20, 18, 23, 16, 27, 0
    ld1     {v24.2d, v25.2d, v26.2d, v27.2d}, [x4], #64
    DR      3, 0, 4, 2, 1, 20, 21, 19, 16, 17, 24, 0
    DR      2, 3, 1, 4, 0, 21, 22, 20, 17, 18, 25, 0
    DR      4, 2, 0, 1, 3, 22, 23, 21, 18, 19, 26, 0
    DR      1, 4, 3, 0, 2, 23, 16, 22, 19, 20, 27, 0

    add     v0.2d, v0.2d, v28.2d
    add     v1.2d, v1.2d, v29.2d
    add     v2.2d, v2.2d, v30.2d
    add     v3.2d, v3.2d, v31.2d
    subs    x2, x2, #1
    b.ne    .Lsha512_block

    st1     {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]
.Lsha512_ret:
    ret
    .size   qn_sha512_blocks_ce, .-qn_sha512_blocks_ce

    .section .rodata
    .align  4
.LK512:
    .quad   0x428a2f98d728ae22, 0x7137449123ef65cd
    .quad   0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    .quad   0x3956c25bf348b538, 0x59f111f1b605d019
    .quad   0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    .quad   0xd807aa98a3030242, 0x12835b0145706fbe
    .quad   0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    .quad   0x72be5d74f27b896f, 0x80deb1fe3b1696b1
    .quad   0x9bdc06a725c71235, 0xc19bf174cf692694
    .quad   0xe49b69c19ef14ad2, 0xefbe4786384f25e3
    .quad   0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    .quad   0x2de92c6f592b0275, 0x4a7484aa6ea6e483
    .quad   0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    .quad   0x983e5152ee66dfab, 0xa831c66d2db43210
    .quad   0xb00327c898fb213f, 0xbf597fc7beef0ee4
    .quad   0xc6e00bf33da88fc2, 0xd5a79147930aa725
    .quad   0x06ca6351e003826f, 0x142929670a0e6e70
    .quad   0x27b70a8546d22ffc, 0x2e1b21385c26c926
    .quad   0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    .quad   0x650a73548baf63de, 0x766a0abb3c77b2a8
    .quad   0x81c2c92e47edaee6, 0x92722c851482353b
    .quad   0xa2bfe8a14cf10364, 0xa81a664bbc423001
    .quad   0xc24b8b70d0f89791, 0xc76c51a30654be30
    .quad   0xd192e819d6ef5218, 0xd69906245565a910
    .quad   0xf40e35855771202a, 0x106aa07032bbd1b8
    .quad   0x19a4c116b8d2d0c8, 0x1e376c085141ab53
    .quad   0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    .quad   0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
    .quad   0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    .quad   0x748f82ee5defb2fc, 0x78a5636f43172f60
    .quad   0x84c87814a1f0ab72, 0x8cc702081a6439ec
    .quad   0x90befffa23631e28, 0xa4506cebde82bde9
    .quad   0xbef9a3f7b2c67915, 0xc67178f2e372532b
    .quad   0xca273eceea26619c, 0xd186b8c721c0c207
    .quad   0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    .quad   0x06f067aa72176fba, 0x0a637dc5a2c898a6
    .quad   0x113f9804bef90dae, 0x1b710b35131c471b
    .quad   0x28db77f523047d84, 0x32caab7b40c72493
    .quad   0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    .quad   0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
    .quad   0x5fcb6fab3ad6faec, 0x6c44198c4a475817

    .section .note.GNU-stack,"",%progbits

#endif /* __aarch64__ */
