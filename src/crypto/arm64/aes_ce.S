/* AES-CTR on the AArch64 crypto extensions, four blocks in flight. */

#if defined(__aarch64__)

#include "abi.h"

    .arch   armv8-a+crypto
    QN_GNU_PROPERTY

    .text

/* aese = AddRoundKey+SubBytes+ShiftRows, so a round is aese+aesmc. */
.macro  AESR4   k
    aese    v0.16b, \k\().16b
    aesmc   v0.16b, v0.16b
    aese    v1.16b, \k\().16b
    aesmc   v1.16b, v1.16b
    aese    v2.16b, \k\().16b
    aesmc   v2.16b, v2.16b
    aese    v3.16b, \k\().16b
    aesmc   v3.16b, v3.16b
.endm

.macro  AESLAST4  ksecond, klast
    aese    v0.16b, \ksecond\().16b
    aese    v1.16b, \ksecond\().16b
    aese    v2.16b, \ksecond\().16b
    aese    v3.16b, \ksecond\().16b
    eor     v0.16b, v0.16b, \klast\().16b
    eor     v1.16b, v1.16b, \klast\().16b
    eor     v2.16b, v2.16b, \klast\().16b
    eor     v3.16b, v3.16b, \klast\().16b
.endm

.macro  AESR1   k
    aese    v0.16b, \k\().16b
    aesmc   v0.16b, v0.16b
.endm

.macro  GCM_MUL_ACC a, h, lo, hi
    pmull   v4.1q, \a\().1d, \h\().1d
    pmull2  v5.1q, \a\().2d, \h\().2d
    ext     v6.16b, \a\().16b, \a\().16b, #8
    eor     v6.16b, v6.16b, \a\().16b
    ext     v7.16b, \h\().16b, \h\().16b, #8
    eor     v7.16b, v7.16b, \h\().16b
    pmull   v6.1q, v6.1d, v7.1d
    eor     v6.16b, v6.16b, v4.16b
    eor     v6.16b, v6.16b, v5.16b
    ext     v7.16b, v31.16b, v6.16b, #8
    eor     v4.16b, v4.16b, v7.16b
    ext     v7.16b, v6.16b, v31.16b, #8
    eor     v5.16b, v5.16b, v7.16b
    eor     \lo\().16b, \lo\().16b, v4.16b
    eor     \hi\().16b, \hi\().16b, v5.16b
.endm

.macro  GCM_REDUCE lo, hi
    pmull   v4.1q, \hi\().1d, v13.1d
    pmull2  v5.1q, \hi\().2d, v13.2d
    ext     v6.16b, v31.16b, v5.16b, #8
    ext     v7.16b, v5.16b, v31.16b, #8
    pmull   v7.1q, v7.1d, v13.1d
    eor     \lo\().16b, \lo\().16b, v4.16b
    eor     \lo\().16b, \lo\().16b, v6.16b
    eor     v12.16b, \lo\().16b, v7.16b
.endm

/* AES-CTR entry: x5 is the byte length. */
    .global qn_aes_ctr_ce
    .type   qn_aes_ctr_ce, %function
    .align  4
qn_aes_ctr_ce:
    QN_BTI_C
    cbz     x5, .Lctr_ret

    /* Round keys hold big-endian columns; rev32 lands them in AES order. */
    ld1     {v16.16b, v17.16b, v18.16b, v19.16b}, [x0], #64
    ld1     {v20.16b, v21.16b, v22.16b, v23.16b}, [x0], #64
    ld1     {v24.16b, v25.16b, v26.16b}, [x0], #48
    rev32   v16.16b, v16.16b
    rev32   v17.16b, v17.16b
    rev32   v18.16b, v18.16b
    rev32   v19.16b, v19.16b
    rev32   v20.16b, v20.16b
    rev32   v21.16b, v21.16b
    rev32   v22.16b, v22.16b
    rev32   v23.16b, v23.16b
    rev32   v24.16b, v24.16b
    rev32   v25.16b, v25.16b
    rev32   v26.16b, v26.16b

    cmp     w1, #10
    b.eq    .Lctr_keys_done
    ld1     {v27.16b, v28.16b, v29.16b, v30.16b}, [x0], #64
    rev32   v27.16b, v27.16b
    rev32   v28.16b, v28.16b
    rev32   v29.16b, v29.16b
    rev32   v30.16b, v30.16b
.Lctr_keys_done:

    ld1     {v4.16b}, [x2]
    umov    w6, v4.s[3]
    rev     w6, w6                  /* w6 = counter, host order */

.Lctr_loop4:
    cmp     x5, #64
    b.lo    .Lctr_tail

    rev     w7, w6
    mov     v0.16b, v4.16b
    ins     v0.s[3], w7
    add     w8, w6, #1
    rev     w9, w8
    mov     v1.16b, v4.16b
    ins     v1.s[3], w9
    add     w8, w6, #2
    rev     w9, w8
    mov     v2.16b, v4.16b
    ins     v2.s[3], w9
    add     w8, w6, #3
    rev     w9, w8
    mov     v3.16b, v4.16b
    ins     v3.s[3], w9
    add     w6, w6, #4

    AESR4   v16
    AESR4   v17
    AESR4   v18
    AESR4   v19
    AESR4   v20
    AESR4   v21
    AESR4   v22
    AESR4   v23
    AESR4   v24
    cmp     w1, #10
    b.ne    .Lctr_256_4
    AESLAST4 v25, v26
    b       .Lctr_xor4
.Lctr_256_4:
    AESR4   v25
    AESR4   v26
    AESR4   v27
    AESR4   v28
    AESLAST4 v29, v30
.Lctr_xor4:
    /* Keep block four in caller-saved v31; d8 is nonvolatile. */
    ld1     {v5.16b, v6.16b, v7.16b}, [x3], #48
    ld1     {v31.16b}, [x3], #16
    eor     v0.16b, v0.16b, v5.16b
    eor     v1.16b, v1.16b, v6.16b
    eor     v2.16b, v2.16b, v7.16b
    eor     v3.16b, v3.16b, v31.16b
    st1     {v0.16b, v1.16b, v2.16b, v3.16b}, [x4], #64
    sub     x5, x5, #64
    b       .Lctr_loop4

.Lctr_tail:
    cbz     x5, .Lctr_done
    rev     w7, w6
    mov     v0.16b, v4.16b
    ins     v0.s[3], w7
    add     w6, w6, #1

    AESR1   v16
    AESR1   v17
    AESR1   v18
    AESR1   v19
    AESR1   v20
    AESR1   v21
    AESR1   v22
    AESR1   v23
    AESR1   v24
    cmp     w1, #10
    b.ne    .Lctr_256_1
    aese    v0.16b, v25.16b
    eor     v0.16b, v0.16b, v26.16b
    b       .Lctr_xor1
.Lctr_256_1:
    AESR1   v25
    AESR1   v26
    AESR1   v27
    AESR1   v28
    aese    v0.16b, v29.16b
    eor     v0.16b, v0.16b, v30.16b
.Lctr_xor1:
    cmp     x5, #16
    b.lo    .Lctr_partial
    ld1     {v5.16b}, [x3], #16
    eor     v0.16b, v0.16b, v5.16b
    st1     {v0.16b}, [x4], #16
    sub     x5, x5, #16
    b       .Lctr_tail

.Lctr_partial:
    sub     sp, sp, #16
    mov     x10, sp
    st1     {v0.16b}, [x10]
    mov     x7, #0
.Lctr_pbyte:
    ldrb    w8, [x3, x7]
    ldrb    w9, [x10, x7]
    eor     w8, w8, w9
    strb    w8, [x4, x7]
    add     x7, x7, #1
    cmp     x7, x5
    b.lo    .Lctr_pbyte
    add     sp, sp, #16

.Lctr_done:
    rev     w7, w6
    ins     v4.s[3], w7
    st1     {v4.16b}, [x2]
.Lctr_ret:
    ret
    .size   qn_aes_ctr_ce, .-qn_aes_ctr_ce

/* Fused AES-CTR and four-way GHASH avoids rereading produced ciphertext. */
    .global qn_aes_gcm_encrypt_ghash_ce
    .type   qn_aes_gcm_encrypt_ghash_ce, %function
    .align  4
qn_aes_gcm_encrypt_ghash_ce:
    QN_BTI_C
    cbz     x6, .Lgcm_ret
    sub     sp, sp, #80
    stp     d8, d9, [sp, #0]
    stp     d10, d11, [sp, #16]
    stp     d12, d13, [sp, #32]
    stp     d14, d15, [sp, #48]

    ld1     {v8.16b}, [x2], #16
    ld1     {v9.16b}, [x2], #16
    ld1     {v10.16b}, [x2], #16
    ld1     {v11.16b}, [x2]
    rbit    v8.16b, v8.16b
    rbit    v9.16b, v9.16b
    rbit    v10.16b, v10.16b
    rbit    v11.16b, v11.16b
    ld1     {v12.16b}, [x7]
    rbit    v12.16b, v12.16b
    mov     x9, #0x87
    dup     v13.2d, x9
    movi    v31.16b, #0

    ld1     {v16.16b, v17.16b, v18.16b, v19.16b}, [x0], #64
    ld1     {v20.16b, v21.16b, v22.16b, v23.16b}, [x0], #64
    ld1     {v24.16b, v25.16b, v26.16b}, [x0], #48
    rev32   v16.16b, v16.16b
    rev32   v17.16b, v17.16b
    rev32   v18.16b, v18.16b
    rev32   v19.16b, v19.16b
    rev32   v20.16b, v20.16b
    rev32   v21.16b, v21.16b
    rev32   v22.16b, v22.16b
    rev32   v23.16b, v23.16b
    rev32   v24.16b, v24.16b
    rev32   v25.16b, v25.16b
    rev32   v26.16b, v26.16b
    cmp     w1, #10
    b.eq    .Lgcm_keys_done
    ld1     {v27.16b, v28.16b, v29.16b, v30.16b}, [x0]
    rev32   v27.16b, v27.16b
    rev32   v28.16b, v28.16b
    rev32   v29.16b, v29.16b
    rev32   v30.16b, v30.16b
.Lgcm_keys_done:

    ld1     {v4.16b}, [x3]
    umov    w8, v4.s[3]
    rev     w8, w8

.Lgcm_loop4:
    cmp     x6, #64
    b.lo    .Lgcm_tail
    ld1     {v4.16b}, [x3]
    rev     w9, w8
    mov     v0.16b, v4.16b
    ins     v0.s[3], w9
    add     w10, w8, #1
    rev     w9, w10
    mov     v1.16b, v4.16b
    ins     v1.s[3], w9
    add     w10, w8, #2
    rev     w9, w10
    mov     v2.16b, v4.16b
    ins     v2.s[3], w9
    add     w10, w8, #3
    rev     w9, w10
    mov     v3.16b, v4.16b
    ins     v3.s[3], w9
    add     w8, w8, #4

    AESR4   v16
    AESR4   v17
    AESR4   v18
    AESR4   v19
    AESR4   v20
    AESR4   v21
    AESR4   v22
    AESR4   v23
    AESR4   v24
    cmp     w1, #10
    b.ne    .Lgcm_256_4
    AESLAST4 v25, v26
    b       .Lgcm_xor4
.Lgcm_256_4:
    AESR4   v25
    AESR4   v26
    AESR4   v27
    AESR4   v28
    AESLAST4 v29, v30
.Lgcm_xor4:
    ld1     {v4.16b, v5.16b, v6.16b, v7.16b}, [x4], #64
    eor     v0.16b, v0.16b, v4.16b
    eor     v1.16b, v1.16b, v5.16b
    eor     v2.16b, v2.16b, v6.16b
    eor     v3.16b, v3.16b, v7.16b
    st1     {v0.16b, v1.16b, v2.16b, v3.16b}, [x5], #64

    rbit    v0.16b, v0.16b
    rbit    v1.16b, v1.16b
    rbit    v2.16b, v2.16b
    rbit    v3.16b, v3.16b
    eor     v0.16b, v0.16b, v12.16b
    movi    v14.16b, #0
    movi    v15.16b, #0
    GCM_MUL_ACC v0, v11, v14, v15
    GCM_MUL_ACC v1, v10, v14, v15
    GCM_MUL_ACC v2, v9, v14, v15
    GCM_MUL_ACC v3, v8, v14, v15
    GCM_REDUCE v14, v15
    sub     x6, x6, #64
    b       .Lgcm_loop4

.Lgcm_tail:
    cbz     x6, .Lgcm_done
    ld1     {v4.16b}, [x3]
    rev     w9, w8
    mov     v0.16b, v4.16b
    ins     v0.s[3], w9
    add     w8, w8, #1

    AESR1   v16
    AESR1   v17
    AESR1   v18
    AESR1   v19
    AESR1   v20
    AESR1   v21
    AESR1   v22
    AESR1   v23
    AESR1   v24
    cmp     w1, #10
    b.ne    .Lgcm_256_1
    aese    v0.16b, v25.16b
    eor     v0.16b, v0.16b, v26.16b
    b       .Lgcm_xor1
.Lgcm_256_1:
    AESR1   v25
    AESR1   v26
    AESR1   v27
    AESR1   v28
    aese    v0.16b, v29.16b
    eor     v0.16b, v0.16b, v30.16b
.Lgcm_xor1:
    cmp     x6, #16
    b.lo    .Lgcm_partial
    ld1     {v4.16b}, [x4], #16
    eor     v0.16b, v0.16b, v4.16b
    st1     {v0.16b}, [x5], #16
    rbit    v0.16b, v0.16b
    eor     v0.16b, v0.16b, v12.16b
    movi    v14.16b, #0
    movi    v15.16b, #0
    GCM_MUL_ACC v0, v8, v14, v15
    GCM_REDUCE v14, v15
    sub     x6, x6, #16
    b       .Lgcm_tail

.Lgcm_partial:
    add     x10, sp, #64
    st1     {v0.16b}, [x10]
    mov     x9, #0
.Lgcm_pbyte:
    ldrb    w11, [x4, x9]
    ldrb    w0, [x10, x9]
    eor     w11, w11, w0
    strb    w11, [x5, x9]
    strb    w11, [x10, x9]
    add     x9, x9, #1
    cmp     x9, x6
    b.lo    .Lgcm_pbyte
.Lgcm_pzero:
    cmp     x9, #16
    b.hs    .Lgcm_phash
    strb    wzr, [x10, x9]
    add     x9, x9, #1
    b       .Lgcm_pzero
.Lgcm_phash:
    ld1     {v0.16b}, [x10]
    rbit    v0.16b, v0.16b
    eor     v0.16b, v0.16b, v12.16b
    movi    v14.16b, #0
    movi    v15.16b, #0
    GCM_MUL_ACC v0, v8, v14, v15
    GCM_REDUCE v14, v15

.Lgcm_done:
    ld1     {v4.16b}, [x3]
    rev     w9, w8
    ins     v4.s[3], w9
    st1     {v4.16b}, [x3]
    rbit    v12.16b, v12.16b
    st1     {v12.16b}, [x7]
    ldp     d8, d9, [sp, #0]
    ldp     d10, d11, [sp, #16]
    ldp     d12, d13, [sp, #32]
    ldp     d14, d15, [sp, #48]
    add     sp, sp, #80
.Lgcm_ret:
    ret
    .size   qn_aes_gcm_encrypt_ghash_ce, .-qn_aes_gcm_encrypt_ghash_ce

/* Single block, for the GHASH key and the GCM tag mask. */
    .global qn_aes_encrypt_ce
    .type   qn_aes_encrypt_ce, %function
    .align  4
qn_aes_encrypt_ce:
    QN_BTI_C
    ld1     {v16.16b, v17.16b, v18.16b, v19.16b}, [x0], #64
    ld1     {v20.16b, v21.16b, v22.16b, v23.16b}, [x0], #64
    ld1     {v24.16b, v25.16b, v26.16b}, [x0], #48
    rev32   v16.16b, v16.16b
    rev32   v17.16b, v17.16b
    rev32   v18.16b, v18.16b
    rev32   v19.16b, v19.16b
    rev32   v20.16b, v20.16b
    rev32   v21.16b, v21.16b
    rev32   v22.16b, v22.16b
    rev32   v23.16b, v23.16b
    rev32   v24.16b, v24.16b
    rev32   v25.16b, v25.16b
    rev32   v26.16b, v26.16b
    cmp     w1, #10
    b.eq    1f
    ld1     {v27.16b, v28.16b, v29.16b, v30.16b}, [x0], #64
    rev32   v27.16b, v27.16b
    rev32   v28.16b, v28.16b
    rev32   v29.16b, v29.16b
    rev32   v30.16b, v30.16b
1:
    ld1     {v0.16b}, [x2]
    AESR1   v16
    AESR1   v17
    AESR1   v18
    AESR1   v19
    AESR1   v20
    AESR1   v21
    AESR1   v22
    AESR1   v23
    AESR1   v24
    cmp     w1, #10
    b.ne    2f
    aese    v0.16b, v25.16b
    eor     v0.16b, v0.16b, v26.16b
    b       3f
2:
    AESR1   v25
    AESR1   v26
    AESR1   v27
    AESR1   v28
    aese    v0.16b, v29.16b
    eor     v0.16b, v0.16b, v30.16b
3:
    st1     {v0.16b}, [x3]
    ret
    .size   qn_aes_encrypt_ce, .-qn_aes_encrypt_ce

    .section .note.GNU-stack,"",%progbits

#endif /* __aarch64__ */
