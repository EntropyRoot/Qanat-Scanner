/* Poly1305 3x44-bit block multiplication for baseline AArch64. */

#if defined(__aarch64__)

#include "abi.h"

    .arch   armv8-a
    QN_GNU_PROPERTY

    .text

    .global qn_poly1305_blocks_aarch64
    .type   qn_poly1305_blocks_aarch64, %function
    .align  4
qn_poly1305_blocks_aarch64:
    QN_BTI_C
    cbz     x2, .Lpoly_ret
    sub     sp, sp, #32
    stp     x19, x20, [sp]
    str     x0, [sp, #16]

    mov     x16, x1
    mov     x17, x2
    lsl     x3, x3, #40
    ldp     x4, x5, [x0]
    ldr     x6, [x0, #16]
    add     x7, x5, x5, lsl #2
    lsl     x7, x7, #2
    add     x8, x6, x6, lsl #2
    lsl     x8, x8, #2
    ldp     x0, x1, [x0, #24]
    ldr     x2, [sp, #16]
    ldr     x2, [x2, #40]

.Lpoly_loop:
    ldp     x15, x19, [x16], #16
    and     x20, x15, #0xfffffffffff
    add     x0, x0, x20
    extr    x20, x19, x15, #44
    and     x20, x20, #0xfffffffffff
    add     x1, x1, x20
    lsr     x20, x19, #24
    and     x20, x20, #0x3ffffffffff
    orr     x20, x20, x3
    add     x2, x2, x20

    mul     x9, x0, x4
    umulh   x10, x0, x4
    mul     x19, x1, x8
    umulh   x20, x1, x8
    adds    x9, x9, x19
    adc     x10, x10, x20
    mul     x19, x2, x7
    umulh   x20, x2, x7
    adds    x9, x9, x19
    adc     x10, x10, x20

    mul     x11, x0, x5
    umulh   x12, x0, x5
    mul     x19, x1, x4
    umulh   x20, x1, x4
    adds    x11, x11, x19
    adc     x12, x12, x20
    mul     x19, x2, x8
    umulh   x20, x2, x8
    adds    x11, x11, x19
    adc     x12, x12, x20

    mul     x13, x0, x6
    umulh   x14, x0, x6
    mul     x19, x1, x5
    umulh   x20, x1, x5
    adds    x13, x13, x19
    adc     x14, x14, x20
    mul     x19, x2, x4
    umulh   x20, x2, x4
    adds    x13, x13, x19
    adc     x14, x14, x20

    extr    x19, x10, x9, #44
    and     x0, x9, #0xfffffffffff
    adds    x11, x11, x19
    adc     x12, x12, xzr
    extr    x19, x12, x11, #44
    and     x1, x11, #0xfffffffffff
    adds    x13, x13, x19
    adc     x14, x14, xzr
    extr    x19, x14, x13, #42
    and     x2, x13, #0x3ffffffffff
    add     x0, x0, x19
    add     x0, x0, x19, lsl #2
    lsr     x19, x0, #44
    and     x0, x0, #0xfffffffffff
    add     x1, x1, x19

    subs    x17, x17, #1
    b.ne    .Lpoly_loop

    ldr     x15, [sp, #16]
    stp     x0, x1, [x15, #24]
    str     x2, [x15, #40]
    ldp     x19, x20, [sp]
    add     sp, sp, #32
.Lpoly_ret:
    ret
    .size   qn_poly1305_blocks_aarch64, .-qn_poly1305_blocks_aarch64

    .section .note.GNU-stack,"",%progbits

#endif /* __aarch64__ */
