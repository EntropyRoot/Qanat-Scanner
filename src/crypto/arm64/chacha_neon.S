/* ChaCha20, four blocks at a time, state transposed across lanes. */

#if defined(__aarch64__)

#include "abi.h"

    .arch   armv8-a
    QN_GNU_PROPERTY

    .text

/* Quarter-round on four blocks at once; v24 is the only scratch. */
.macro  QR4 a, b, c, d
    add     \a\().4s, \a\().4s, \b\().4s
    eor     \d\().16b, \d\().16b, \a\().16b
    rev32   \d\().8h, \d\().8h

    add     \c\().4s, \c\().4s, \d\().4s
    eor     v24.16b, \b\().16b, \c\().16b
    shl     \b\().4s, v24.4s, #12
    sri     \b\().4s, v24.4s, #20

    add     \a\().4s, \a\().4s, \b\().4s
    eor     v24.16b, \d\().16b, \a\().16b
    shl     \d\().4s, v24.4s, #8
    sri     \d\().4s, v24.4s, #24

    add     \c\().4s, \c\().4s, \d\().4s
    eor     v24.16b, \b\().16b, \c\().16b
    shl     \b\().4s, v24.4s, #7
    sri     \b\().4s, v24.4s, #25
.endm

/* 4x4 lane transpose, turning word-major back into block-major. */
.macro  TR4 a, b, c, d
    trn1    v24.4s, \a\().4s, \b\().4s
    trn2    v25.4s, \a\().4s, \b\().4s
    trn1    v26.4s, \c\().4s, \d\().4s
    trn2    v27.4s, \c\().4s, \d\().4s
    trn1    \a\().2d, v24.2d, v26.2d
    trn1    \b\().2d, v25.2d, v27.2d
    trn2    \c\().2d, v24.2d, v26.2d
    trn2    \d\().2d, v25.2d, v27.2d
.endm

/* One-lane row-vectorized ChaCha20 handles short records and tails. */
    .global qn_chacha20_1x_neon
    .type   qn_chacha20_1x_neon, %function
    .align  4
qn_chacha20_1x_neon:
    QN_BTI_C
    cbz     x5, .Lc1_ret
    sub     sp, sp, #64

    adrp    x6, .Lc4_sigma
    add     x6, x6, :lo12:.Lc4_sigma
    ld1     {v28.4s}, [x6]
    ld1     {v29.4s, v30.4s}, [x0]

.Lc1_block:
    mov     v0.16b, v28.16b
    mov     v1.16b, v29.16b
    mov     v2.16b, v30.16b
    movi    v3.16b, #0
    ins     v3.s[0], w1
    ldr     w6, [x2, #0]
    ins     v3.s[1], w6
    ldr     w6, [x2, #4]
    ins     v3.s[2], w6
    ldr     w6, [x2, #8]
    ins     v3.s[3], w6
    mov     v16.16b, v0.16b
    mov     v17.16b, v1.16b
    mov     v18.16b, v2.16b
    mov     v19.16b, v3.16b

    mov     w7, #10
.Lc1_rounds:
    QR4     v0, v1, v2, v3
    ext     v1.16b, v1.16b, v1.16b, #4
    ext     v2.16b, v2.16b, v2.16b, #8
    ext     v3.16b, v3.16b, v3.16b, #12
    QR4     v0, v1, v2, v3
    ext     v1.16b, v1.16b, v1.16b, #12
    ext     v2.16b, v2.16b, v2.16b, #8
    ext     v3.16b, v3.16b, v3.16b, #4
    subs    w7, w7, #1
    b.ne    .Lc1_rounds

    add     v0.4s, v0.4s, v16.4s
    add     v1.4s, v1.4s, v17.4s
    add     v2.4s, v2.4s, v18.4s
    add     v3.4s, v3.4s, v19.4s
    mov     x6, sp
    st1     {v0.16b, v1.16b, v2.16b, v3.16b}, [x6]

    mov     x8, #64
    cmp     x5, x8
    csel    x8, x5, x8, lo          /* bytes consumed by this block */
    mov     x7, x8
    mov     x6, sp
.Lc1_xor_vectors:
    cmp     x7, #16
    b.lo    .Lc1_xor_partial
    ld1     {v4.16b}, [x3], #16
    ld1     {v5.16b}, [x6], #16
    eor     v4.16b, v4.16b, v5.16b
    st1     {v4.16b}, [x4], #16
    sub     x7, x7, #16
    b       .Lc1_xor_vectors

.Lc1_xor_partial:
    cbz     x7, .Lc1_next
    mov     x9, #0
.Lc1_xor_bytes:
    ldrb    w10, [x3, x9]
    ldrb    w11, [x6, x9]
    eor     w10, w10, w11
    strb    w10, [x4, x9]
    add     x9, x9, #1
    cmp     x9, x7
    b.lo    .Lc1_xor_bytes
    add     x3, x3, x7
    add     x4, x4, x7

.Lc1_next:
    sub     x5, x5, x8
    cbz     x5, .Lc1_done
    add     w1, w1, #1
    b       .Lc1_block

.Lc1_done:
    add     sp, sp, #64
.Lc1_ret:
    ret
    .size   qn_chacha20_1x_neon, .-qn_chacha20_1x_neon

/* Four-block entry: x5 counts 256-byte groups. */
    .global qn_chacha20_4x_neon
    .type   qn_chacha20_4x_neon, %function
    .align  4
qn_chacha20_4x_neon:
    QN_BTI_C
    cbz     x5, .Lc4_ret

    adrp    x6, .Lc4_sigma
    add     x6, x6, :lo12:.Lc4_sigma
    ld1     {v28.4s}, [x6], #16     /* sigma */
    ld1     {v29.4s}, [x6]          /* 0,1,2,3 */
    ld1     {v30.4s, v31.4s}, [x0]  /* key */

.Lc4_group:
    dup     v0.4s, v28.s[0]
    dup     v1.4s, v28.s[1]
    dup     v2.4s, v28.s[2]
    dup     v3.4s, v28.s[3]
    dup     v4.4s, v30.s[0]
    dup     v5.4s, v30.s[1]
    dup     v6.4s, v30.s[2]
    dup     v7.4s, v30.s[3]
    dup     v16.4s, v31.s[0]
    dup     v17.4s, v31.s[1]
    dup     v18.4s, v31.s[2]
    dup     v19.4s, v31.s[3]
    dup     v20.4s, w1
    add     v20.4s, v20.4s, v29.4s  /* four consecutive counters */
    ldr     w6, [x2, #0]
    dup     v21.4s, w6
    ldr     w6, [x2, #4]
    dup     v22.4s, w6
    ldr     w6, [x2, #8]
    dup     v23.4s, w6

    mov     w7, #10
.Lc4_rounds:
    QR4     v0, v4, v16, v20
    QR4     v1, v5, v17, v21
    QR4     v2, v6, v18, v22
    QR4     v3, v7, v19, v23
    QR4     v0, v5, v18, v23
    QR4     v1, v6, v19, v20
    QR4     v2, v7, v16, v21
    QR4     v3, v4, v17, v22
    subs    w7, w7, #1
    b.ne    .Lc4_rounds

    /* Reconstruct feed-forward state instead of spilling 256 bytes. */
    dup     v24.4s, v28.s[0]
    add     v0.4s, v0.4s, v24.4s
    dup     v24.4s, v28.s[1]
    add     v1.4s, v1.4s, v24.4s
    dup     v24.4s, v28.s[2]
    add     v2.4s, v2.4s, v24.4s
    dup     v24.4s, v28.s[3]
    add     v3.4s, v3.4s, v24.4s
    dup     v24.4s, v30.s[0]
    add     v4.4s, v4.4s, v24.4s
    dup     v24.4s, v30.s[1]
    add     v5.4s, v5.4s, v24.4s
    dup     v24.4s, v30.s[2]
    add     v6.4s, v6.4s, v24.4s
    dup     v24.4s, v30.s[3]
    add     v7.4s, v7.4s, v24.4s
    dup     v24.4s, v31.s[0]
    add     v16.4s, v16.4s, v24.4s
    dup     v24.4s, v31.s[1]
    add     v17.4s, v17.4s, v24.4s
    dup     v24.4s, v31.s[2]
    add     v18.4s, v18.4s, v24.4s
    dup     v24.4s, v31.s[3]
    add     v19.4s, v19.4s, v24.4s
    dup     v24.4s, w1
    add     v24.4s, v24.4s, v29.4s
    add     v20.4s, v20.4s, v24.4s
    ldr     w6, [x2, #0]
    dup     v24.4s, w6
    add     v21.4s, v21.4s, v24.4s
    ldr     w6, [x2, #4]
    dup     v24.4s, w6
    add     v22.4s, v22.4s, v24.4s
    ldr     w6, [x2, #8]
    dup     v24.4s, w6
    add     v23.4s, v23.4s, v24.4s

    TR4     v0, v1, v2, v3
    TR4     v4, v5, v6, v7
    TR4     v16, v17, v18, v19
    TR4     v20, v21, v22, v23

    /* block b is now (v0+b, v4+b, v16+b, v20+b). */
    ld1     {v24.16b, v25.16b, v26.16b, v27.16b}, [x3], #64
    eor     v0.16b, v0.16b, v24.16b
    eor     v4.16b, v4.16b, v25.16b
    eor     v16.16b, v16.16b, v26.16b
    eor     v20.16b, v20.16b, v27.16b
    st1     {v0.16b}, [x4], #16
    st1     {v4.16b}, [x4], #16
    st1     {v16.16b}, [x4], #16
    st1     {v20.16b}, [x4], #16

    ld1     {v24.16b, v25.16b, v26.16b, v27.16b}, [x3], #64
    eor     v1.16b, v1.16b, v24.16b
    eor     v5.16b, v5.16b, v25.16b
    eor     v17.16b, v17.16b, v26.16b
    eor     v21.16b, v21.16b, v27.16b
    st1     {v1.16b}, [x4], #16
    st1     {v5.16b}, [x4], #16
    st1     {v17.16b}, [x4], #16
    st1     {v21.16b}, [x4], #16

    ld1     {v24.16b, v25.16b, v26.16b, v27.16b}, [x3], #64
    eor     v2.16b, v2.16b, v24.16b
    eor     v6.16b, v6.16b, v25.16b
    eor     v18.16b, v18.16b, v26.16b
    eor     v22.16b, v22.16b, v27.16b
    st1     {v2.16b}, [x4], #16
    st1     {v6.16b}, [x4], #16
    st1     {v18.16b}, [x4], #16
    st1     {v22.16b}, [x4], #16

    ld1     {v24.16b, v25.16b, v26.16b, v27.16b}, [x3], #64
    eor     v3.16b, v3.16b, v24.16b
    eor     v7.16b, v7.16b, v25.16b
    eor     v19.16b, v19.16b, v26.16b
    eor     v23.16b, v23.16b, v27.16b
    st1     {v3.16b}, [x4], #16
    st1     {v7.16b}, [x4], #16
    st1     {v19.16b}, [x4], #16
    st1     {v23.16b}, [x4], #16

    add     w1, w1, #4
    subs    x5, x5, #1
    b.ne    .Lc4_group

.Lc4_ret:
    ret
    .size   qn_chacha20_4x_neon, .-qn_chacha20_4x_neon

    .section .rodata
    .align  4
.Lc4_sigma:
    .word   0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    .word   0, 1, 2, 3

    .section .note.GNU-stack,"",%progbits

#endif /* __aarch64__ */
