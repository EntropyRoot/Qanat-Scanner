#ifndef QANAT_MLKEM_H
#define QANAT_MLKEM_H

#include <stdbool.h>
#include <stdint.h>

#define QN_MLKEM768_PUBLIC_LEN     1184u
#define QN_MLKEM768_SECRET_LEN     2400u
#define QN_MLKEM768_CIPHERTEXT_LEN 1088u
#define QN_MLKEM_SHARED_LEN        32u
#define QN_MLKEM_KEYGEN_SEED_LEN   64u
#define QN_MLKEM_ENCAP_SEED_LEN    32u

bool qn_mlkem768_keypair(
    uint8_t public_key[QN_MLKEM768_PUBLIC_LEN],
    uint8_t secret_key[QN_MLKEM768_SECRET_LEN],
    const uint8_t seed[QN_MLKEM_KEYGEN_SEED_LEN]);
bool qn_mlkem768_encap(
    uint8_t ciphertext[QN_MLKEM768_CIPHERTEXT_LEN],
    uint8_t shared[QN_MLKEM_SHARED_LEN],
    const uint8_t public_key[QN_MLKEM768_PUBLIC_LEN],
    const uint8_t seed[QN_MLKEM_ENCAP_SEED_LEN]);
bool qn_mlkem768_decap(
    uint8_t shared[QN_MLKEM_SHARED_LEN],
    const uint8_t ciphertext[QN_MLKEM768_CIPHERTEXT_LEN],
    const uint8_t secret_key[QN_MLKEM768_SECRET_LEN]);
bool qn_mlkem768_public_valid(
    const uint8_t public_key[QN_MLKEM768_PUBLIC_LEN]);
bool qn_mlkem768_secret_valid(
    const uint8_t secret_key[QN_MLKEM768_SECRET_LEN]);

#endif /* QANAT_MLKEM_H */
