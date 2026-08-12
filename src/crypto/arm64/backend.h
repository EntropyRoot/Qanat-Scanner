#ifndef QANAT_CRYPTO_ARM64_BACKEND_H
#define QANAT_CRYPTO_ARM64_BACKEND_H

#include <stdbool.h>

typedef enum {
    QN_BACKEND_AES_CE = 0,
    QN_BACKEND_GHASH_CE,
    QN_BACKEND_AES_GCM_FUSED,
    QN_BACKEND_SHA256_CE,
    QN_BACKEND_CHACHA_NEON,
    QN_BACKEND_POLY1305_ASM,
    QN_BACKEND_X25519_ASM,
    QN_BACKEND_SHA512_CE,
    QN_BACKEND_COUNT
} qn_crypto_backend;

/* Backend controls are cached once for tests and benchmarks. */
bool        qn_crypto_backend_available(qn_crypto_backend backend);
bool        qn_crypto_backend_enabled(qn_crypto_backend backend);
bool        qn_crypto_backend_forced(qn_crypto_backend backend);
const char *qn_crypto_backend_name(qn_crypto_backend backend);
const char *qn_crypto_backend_control_error(void);

#endif /* QANAT_CRYPTO_ARM64_BACKEND_H */
