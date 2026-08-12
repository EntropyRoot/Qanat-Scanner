#include "qanat/crypto.h"

#include <string.h>

#define uECC_WORD_SIZE 4
#define uECC_OPTIMIZATION_LEVEL 0
#define uECC_SUPPORTS_secp160r1 0
#define uECC_SUPPORTS_secp192r1 0
#define uECC_SUPPORTS_secp224r1 0
#define uECC_SUPPORTS_secp256r1 1
#define uECC_SUPPORTS_secp256k1 0
#define uECC_ENABLE_VLI_API 0

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#endif
#include "../../third_party/micro-ecc/uECC.c"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

static bool p256_private(uint8_t sk[QN_P256_SECRET_LEN], qn_rng *rng)
{
    if (rng) {
        qn_rng_bytes(rng, sk, QN_P256_SECRET_LEN);
        return true;
    }
    return qn_random_secure(sk, QN_P256_SECRET_LEN);
}

bool qn_p256_keypair(uint8_t sk[QN_P256_SECRET_LEN], uint8_t pk[QN_P256_PUBLIC_LEN],
                     qn_rng *rng)
{
    uint8_t raw[QN_P256_PUBLIC_LEN - 1u];
    unsigned attempt;

    for (attempt = 0u; attempt < 128u; attempt++) {
        if (!p256_private(sk, rng))
            break;
        if (uECC_compute_public_key(sk, raw, uECC_secp256r1())) {
            pk[0] = 0x04u;
            memcpy(pk + 1u, raw, sizeof raw);
            qn_wipe(raw, sizeof raw);
            return true;
        }
    }
    qn_wipe(raw, sizeof raw);
    qn_wipe(sk, QN_P256_SECRET_LEN);
    qn_wipe(pk, QN_P256_PUBLIC_LEN);
    return false;
}

bool qn_p256(uint8_t out[QN_P256_SECRET_LEN], const uint8_t sk[QN_P256_SECRET_LEN],
             const uint8_t peer[QN_P256_PUBLIC_LEN])
{
    uint8_t zero[QN_P256_SECRET_LEN] = { 0 };

    if (peer[0] != 0x04u ||
        !uECC_valid_public_key(peer + 1u, uECC_secp256r1()) ||
        !uECC_shared_secret(peer + 1u, sk, out, uECC_secp256r1()) ||
        qn_ct_eq(out, zero, sizeof zero)) {
        qn_wipe(out, QN_P256_SECRET_LEN);
        return false;
    }
    return true;
}
