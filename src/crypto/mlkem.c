#include "qanat/mlkem.h"

#define MLK_CONFIG_FILE "qanat/mlkem_vendor_config.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wredundant-decls"
#endif
#include "../../third_party/mlkem-native/mlkem/mlkem_native.h"
#include "../../third_party/mlkem-native/mlkem/mlkem_native.c"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

bool qn_mlkem768_keypair(
    uint8_t public_key[QN_MLKEM768_PUBLIC_LEN],
    uint8_t secret_key[QN_MLKEM768_SECRET_LEN],
    const uint8_t seed[QN_MLKEM_KEYGEN_SEED_LEN])
{
    return qn_vendor_mlkem768_keypair_derand(public_key, secret_key, seed) == 0;
}

bool qn_mlkem768_encap(
    uint8_t ciphertext[QN_MLKEM768_CIPHERTEXT_LEN],
    uint8_t shared[QN_MLKEM_SHARED_LEN],
    const uint8_t public_key[QN_MLKEM768_PUBLIC_LEN],
    const uint8_t seed[QN_MLKEM_ENCAP_SEED_LEN])
{
    return qn_vendor_mlkem768_enc_derand(ciphertext, shared, public_key, seed) == 0;
}

bool qn_mlkem768_decap(
    uint8_t shared[QN_MLKEM_SHARED_LEN],
    const uint8_t ciphertext[QN_MLKEM768_CIPHERTEXT_LEN],
    const uint8_t secret_key[QN_MLKEM768_SECRET_LEN])
{
    return qn_vendor_mlkem768_dec(shared, ciphertext, secret_key) == 0;
}

bool qn_mlkem768_public_valid(
    const uint8_t public_key[QN_MLKEM768_PUBLIC_LEN])
{
    return qn_vendor_mlkem768_check_pk(public_key) == 0;
}

bool qn_mlkem768_secret_valid(
    const uint8_t secret_key[QN_MLKEM768_SECRET_LEN])
{
    return qn_vendor_mlkem768_check_sk(secret_key) == 0;
}
