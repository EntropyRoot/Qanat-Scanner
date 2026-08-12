/* Verifies AAPCS64 nonvolatile registers and SP around one indirect call. */

#if defined(__aarch64__)

#include "../../src/crypto/arm64/abi.h"

    .arch   armv8-a
    QN_GNU_PROPERTY
    .text

/* x0 is the target, x1 holds eight arguments, and x2 receives snapshots. */
    .global qn_test_abi_probe
    .type   qn_test_abi_probe, %function
    .align  4
qn_test_abi_probe:
    QN_BTI_C
    sub     sp, sp, #192
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    stp     d8, d9, [sp, #96]
    stp     d10, d11, [sp, #112]
    stp     d12, d13, [sp, #128]
    stp     d14, d15, [sp, #144]
    str     x0, [sp, #160]
    str     x1, [sp, #168]
    str     x2, [sp, #176]

    adrp    x9, .Labi_x_patterns
    add     x9, x9, :lo12:.Labi_x_patterns
    ldp     x19, x20, [x9, #0]
    ldp     x21, x22, [x9, #16]
    ldp     x23, x24, [x9, #32]
    ldp     x25, x26, [x9, #48]
    ldp     x27, x28, [x9, #64]

    adrp    x9, .Labi_d_patterns
    add     x9, x9, :lo12:.Labi_d_patterns
    ldp     d8, d9, [x9, #0]
    ldp     d10, d11, [x9, #16]
    ldp     d12, d13, [x9, #32]
    ldp     d14, d15, [x9, #48]

    mov     x29, sp
    ldr     x16, [x29, #160]
    ldr     x17, [x29, #168]
    ldp     x0, x1, [x17, #0]
    ldp     x2, x3, [x17, #16]
    ldp     x4, x5, [x17, #32]
    ldp     x6, x7, [x17, #48]
    blr     x16

    mov     x9, sp
    mov     x10, x29
    mov     sp, x29
    ldr     x11, [sp, #176]
    stp     x19, x20, [x11, #0]
    stp     x21, x22, [x11, #16]
    stp     x23, x24, [x11, #32]
    stp     x25, x26, [x11, #48]
    stp     x27, x28, [x11, #64]
    str     x10, [x11, #80]
    stp     d8, d9, [x11, #88]
    stp     d10, d11, [x11, #104]
    stp     d12, d13, [x11, #120]
    stp     d14, d15, [x11, #136]
    str     x10, [x11, #152]
    str     x9, [x11, #160]

    ldp     d8, d9, [sp, #96]
    ldp     d10, d11, [sp, #112]
    ldp     d12, d13, [sp, #128]
    ldp     d14, d15, [sp, #144]
    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    add     sp, sp, #192
    ret
    .size   qn_test_abi_probe, .-qn_test_abi_probe

    .section .rodata
    .align  3
.Labi_x_patterns:
    .quad   0x1919191919191919, 0x2020202020202020
    .quad   0x2121212121212121, 0x2222222222222222
    .quad   0x2323232323232323, 0x2424242424242424
    .quad   0x2525252525252525, 0x2626262626262626
    .quad   0x2727272727272727, 0x2828282828282828
.Labi_d_patterns:
    .quad   0xd8d8d8d8d8d8d8d8, 0xd9d9d9d9d9d9d9d9
    .quad   0xdadadadadadadada, 0xdbdbdbdbdbdbdbdb
    .quad   0xdcdcdcdcdcdcdcdc, 0xdddddddddddddddd
    .quad   0xdededededededede, 0xdfdfdfdfdfdfdfdf

    .section .note.GNU-stack,"",%progbits

#endif /* __aarch64__ */
