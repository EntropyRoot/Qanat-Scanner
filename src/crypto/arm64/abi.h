/* Branch-protection markers; see docs/CRYPTO-AARCH64-2026-08-11.md. */

#ifndef QANAT_CRYPTO_ARM64_ABI_H
#define QANAT_CRYPTO_ARM64_ABI_H

#if defined(__aarch64__)

/* `bti c`, which encodes as a NOP on cores without the extension. */
#define QN_BTI_C hint #34

/* The linker ANDs this across inputs, so every object must emit it. */
#define QN_GNU_PROPERTY                                                        \
    .pushsection .note.gnu.property, "a";                                      \
    .balign 8;                                                                 \
    .long 4;              /* namesz */                                         \
    .long 0x10;           /* descsz */                                         \
    .long 5;              /* NT_GNU_PROPERTY_TYPE_0 */                         \
    .asciz "GNU";                                                              \
    .long 0xc0000000;     /* GNU_PROPERTY_AARCH64_FEATURE_1_AND */             \
    .long 4;              /* datasz */                                         \
    .long 3;              /* BTI | PAC */                                      \
    .long 0;              /* pad to 8 */                                       \
    .popsection

#endif /* __aarch64__ */

#endif /* QANAT_CRYPTO_ARM64_ABI_H */
