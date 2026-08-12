/* GHASH on PMULL. rbit alone puts GCM's bit order into polynomial order. */

#if defined(__aarch64__)

#include "abi.h"

    .arch   armv8-a+crypto
    QN_GNU_PROPERTY

    .text

.macro  BITREV  r
    rbit    \r\().16b, \r\().16b
.endm

/* v0 <- v0*v1 mod P. Karatsuba, then fold x^128 == 0x87 down twice. */
.macro  GMUL
    pmull   v3.1q, v0.1d, v1.1d
    pmull2  v4.1q, v0.2d, v1.2d
    ext     v5.16b, v0.16b, v0.16b, #8
    eor     v5.16b, v5.16b, v0.16b
    ext     v6.16b, v1.16b, v1.16b, #8
    eor     v6.16b, v6.16b, v1.16b
    pmull   v7.1q, v5.1d, v6.1d
    eor     v7.16b, v7.16b, v3.16b
    eor     v7.16b, v7.16b, v4.16b
    ext     v5.16b, v31.16b, v7.16b, #8
    ext     v6.16b, v7.16b, v31.16b, #8
    eor     v3.16b, v3.16b, v5.16b
    eor     v4.16b, v4.16b, v6.16b

    pmull   v5.1q, v4.1d, v30.1d
    pmull2  v6.1q, v4.2d, v30.2d
    ext     v7.16b, v31.16b, v6.16b, #8
    /* v8-v15 are AAPCS64 nonvolatile in their low 64 bits. */
    ext     v16.16b, v6.16b, v31.16b, #8
    pmull   v16.1q, v16.1d, v30.1d
    eor     v3.16b, v3.16b, v5.16b
    eor     v3.16b, v3.16b, v7.16b
    eor     v0.16b, v3.16b, v16.16b
.endm

.macro  GMUL_ACC a, h, lo, hi
    pmull   v3.1q, \a\().1d, \h\().1d
    pmull2  v4.1q, \a\().2d, \h\().2d
    ext     v5.16b, \a\().16b, \a\().16b, #8
    eor     v5.16b, v5.16b, \a\().16b
    ext     v6.16b, \h\().16b, \h\().16b, #8
    eor     v6.16b, v6.16b, \h\().16b
    pmull   v7.1q, v5.1d, v6.1d
    eor     v7.16b, v7.16b, v3.16b
    eor     v7.16b, v7.16b, v4.16b
    ext     v5.16b, v31.16b, v7.16b, #8
    ext     v6.16b, v7.16b, v31.16b, #8
    eor     v3.16b, v3.16b, v5.16b
    eor     v4.16b, v4.16b, v6.16b
    eor     \lo\().16b, \lo\().16b, v3.16b
    eor     \hi\().16b, \hi\().16b, v4.16b
.endm

.macro  REDUCE_ACC lo, hi
    pmull   v5.1q, \hi\().1d, v30.1d
    pmull2  v6.1q, \hi\().2d, v30.2d
    ext     v7.16b, v31.16b, v6.16b, #8
    ext     v16.16b, v6.16b, v31.16b, #8
    pmull   v16.1q, v16.1d, v30.1d
    eor     \lo\().16b, \lo\().16b, v5.16b
    eor     \lo\().16b, \lo\().16b, v7.16b
    eor     v0.16b, \lo\().16b, v16.16b
.endm

.macro  GHASH4 ptr
    movi    v25.16b, #0
    movi    v26.16b, #0
    ld1     {v2.16b}, [\ptr], #16
    BITREV  v2
    eor     v2.16b, v2.16b, v0.16b
    GMUL_ACC v2, v20, v25, v26
    ld1     {v2.16b}, [\ptr], #16
    BITREV  v2
    GMUL_ACC v2, v19, v25, v26
    ld1     {v2.16b}, [\ptr], #16
    BITREV  v2
    GMUL_ACC v2, v18, v25, v26
    ld1     {v2.16b}, [\ptr], #16
    BITREV  v2
    GMUL_ACC v2, v17, v25, v26
    REDUCE_ACC v25, v26
.endm

/* x1 holds H through H^4; x2 data; x3 block count. */
    .global qn_ghash_ce
    .type   qn_ghash_ce, %function
    .align  4
qn_ghash_ce:
    QN_BTI_C
    ld1     {v0.16b}, [x0]
    ld1     {v17.16b}, [x1], #16
    ld1     {v18.16b}, [x1], #16
    ld1     {v19.16b}, [x1], #16
    ld1     {v20.16b}, [x1]
    BITREV  v0
    BITREV  v17
    BITREV  v18
    BITREV  v19
    BITREV  v20
    mov     v1.16b, v17.16b
    movi    v31.16b, #0
    mov     x9, #0x87
    dup     v30.2d, x9

.Lgh_loop4:
    cmp     x3, #4
    b.lo    .Lgh_loop
    GHASH4  x2
    sub     x3, x3, #4
    b       .Lgh_loop4

.Lgh_loop:
    cbz     x3, .Lgh_done
    ld1     {v2.16b}, [x2], #16
    BITREV  v2
    eor     v0.16b, v0.16b, v2.16b
    GMUL
    sub     x3, x3, #1
    b       .Lgh_loop

.Lgh_done:
    BITREV  v0
    st1     {v0.16b}, [x0]
    ret
    .size   qn_ghash_ce, .-qn_ghash_ce

/* Coarse GHASH keeps H powers and the accumulator live across GCM segments. */
    .global qn_ghash_gcm_ce
    .type   qn_ghash_gcm_ce, %function
    .align  4
qn_ghash_gcm_ce:
    QN_BTI_C
    mov     x6, x3                  /* original AAD length */
    mov     x7, x5                  /* original ciphertext length */
    movi    v0.16b, #0
    ld1     {v17.16b}, [x1], #16
    ld1     {v18.16b}, [x1], #16
    ld1     {v19.16b}, [x1], #16
    ld1     {v20.16b}, [x1]
    BITREV  v17
    BITREV  v18
    BITREV  v19
    BITREV  v20
    mov     v1.16b, v17.16b
    movi    v31.16b, #0
    mov     x9, #0x87
    dup     v30.2d, x9

.Lgg_aad_groups:
    cmp     x3, #64
    b.lo    .Lgg_aad_blocks
    GHASH4  x2
    sub     x3, x3, #64
    b       .Lgg_aad_groups

.Lgg_aad_blocks:
    cmp     x3, #16
    b.lo    .Lgg_aad_partial
    ld1     {v2.16b}, [x2], #16
    BITREV  v2
    eor     v0.16b, v0.16b, v2.16b
    GMUL
    sub     x3, x3, #16
    b       .Lgg_aad_blocks

.Lgg_aad_partial:
    cbz     x3, .Lgg_ct_groups
    sub     sp, sp, #16
    stp     xzr, xzr, [sp]
    mov     x8, #0
.Lgg_aad_copy:
    ldrb    w9, [x2, x8]
    strb    w9, [sp, x8]
    add     x8, x8, #1
    cmp     x8, x3
    b.lo    .Lgg_aad_copy
    ld1     {v2.16b}, [sp]
    add     sp, sp, #16
    BITREV  v2
    eor     v0.16b, v0.16b, v2.16b
    GMUL

.Lgg_ct_groups:
    cmp     x5, #64
    b.lo    .Lgg_ct_blocks
    GHASH4  x4
    sub     x5, x5, #64
    b       .Lgg_ct_groups

.Lgg_ct_blocks:
    cmp     x5, #16
    b.lo    .Lgg_ct_partial
    ld1     {v2.16b}, [x4], #16
    BITREV  v2
    eor     v0.16b, v0.16b, v2.16b
    GMUL
    sub     x5, x5, #16
    b       .Lgg_ct_blocks

.Lgg_ct_partial:
    cbz     x5, .Lgg_lengths
    sub     sp, sp, #16
    stp     xzr, xzr, [sp]
    mov     x8, #0
.Lgg_ct_copy:
    ldrb    w9, [x4, x8]
    strb    w9, [sp, x8]
    add     x8, x8, #1
    cmp     x8, x5
    b.lo    .Lgg_ct_copy
    ld1     {v2.16b}, [sp]
    add     sp, sp, #16
    BITREV  v2
    eor     v0.16b, v0.16b, v2.16b
    GMUL

.Lgg_lengths:
    lsl     x8, x6, #3
    lsl     x9, x7, #3
    rev     x8, x8
    rev     x9, x9
    sub     sp, sp, #16
    stp     x8, x9, [sp]
    ld1     {v2.16b}, [sp]
    add     sp, sp, #16
    BITREV  v2
    eor     v0.16b, v0.16b, v2.16b
    GMUL

    BITREV  v0
    st1     {v0.16b}, [x0]
    ret
    .size   qn_ghash_gcm_ce, .-qn_ghash_gcm_ce

    .section .note.GNU-stack,"",%progbits

#endif /* __aarch64__ */
