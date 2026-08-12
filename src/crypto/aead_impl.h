#ifndef QANAT_AEAD_IMPL_H
#define QANAT_AEAD_IMPL_H

#include "qanat/crypto.h"

/* Opaque so the 44-bit and 26-bit limb layouts stay private. */
typedef struct {
    uint64_t opaque[16];
} qn_poly1305;

void qn_poly1305_init(qn_poly1305 *st, const uint8_t key[32]);
void qn_poly1305_update(qn_poly1305 *st, const uint8_t *m, size_t n);
void qn_poly1305_final(qn_poly1305 *st, uint8_t tag[16]);

bool qn_chacha20poly1305_seal(const uint8_t key[32], const uint8_t nonce[QN_AEAD_IV_LEN],
                              const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t ptlen,
                              uint8_t *out);
bool qn_chacha20poly1305_open(const uint8_t key[32], const uint8_t nonce[QN_AEAD_IV_LEN],
                              const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t ctlen,
                              uint8_t *out);

bool qn_aes_gcm_setkey(qn_aes_gcm *g, const uint8_t *key, size_t klen);
bool qn_aes_gcm_seal(const qn_aes_gcm *g, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                     size_t aadlen, const uint8_t *pt, size_t ptlen, uint8_t *out);
bool qn_aes_gcm_open(const qn_aes_gcm *g, const uint8_t iv[QN_AEAD_IV_LEN], const uint8_t *aad,
                     size_t aadlen, const uint8_t *ct, size_t ctlen, uint8_t *out);

#if defined(QN_CRYPTO_TESTING)
void qn_aes_encrypt_block_c(const qn_aes_gcm *g, const uint8_t in[16], uint8_t out[16]);
void qn_aes_ctr_c(const qn_aes_gcm *g, uint8_t ctr[16], const uint8_t *in, uint8_t *out,
                  size_t len);
void qn_ghash_blocks_c(const qn_aes_gcm *g, uint8_t acc[16], const uint8_t *data,
                       size_t blocks);
void qn_ghash_gcm_c(const qn_aes_gcm *g, uint8_t out[16], const uint8_t *aad, size_t aadlen,
                    const uint8_t *ct, size_t ctlen);
void qn_chacha20_xor_c(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                       const uint8_t *in, uint8_t *out, size_t len);
void qn_poly1305_blocks_c(qn_poly1305 *st, const uint8_t *m, size_t blocks, uint64_t full);
#endif

#endif /* QANAT_AEAD_IMPL_H */
